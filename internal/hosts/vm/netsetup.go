package vm

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	vnetns "github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// setupNetDirect replaces the ptp + tc-redirect-tap CNI plugins with direct
// netlink calls. Given an already-created netns at nsPath, an allocated
// ipCIDR and its gateway, it:
//
//  1. creates a veth pair in the root ns
//  2. moves one end into the netns, renames it "veth0", assigns ipCIDR,
//     brings it up, sets default route via gateway
//  3. creates a tap device "tap0" in the netns
//  4. wires veth0 ⇄ tap0 via ingress qdisc + u32 mirred filters (same
//     topology that tc-redirect-tap installs)
//  5. brings up the host-side veth and assigns the gateway as /32 so host
//     responds to ARP for it
//
// Returns the host veth name, MAC addresses, and other facts the caller
// needs to boot Firecracker.
type directNetResult struct {
	HostVeth string
	TapName  string
	MAC      string // guest-facing MAC (of veth inside netns, also cloned onto tap for virtio)
	Gateway  string
}

// setupNetDirect builds the per-slot veth pair, netns, and tap. When
// slotUID > 0 the tap is created with TUNSETOWNER + TUNSETGROUP so the
// post-uid-drop firecracker (uid=slotUID, kvm supplementary group) can
// TUNSETIFF on it. 0 keeps today's behaviour (root-owned tap, root
// firecracker).
func setupNetDirect(nsPath, id, ipCIDR, gateway string, slotUID, slotGID uint32) (*directNetResult, error) {
	ip, ipNet, err := net.ParseCIDR(ipCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse cidr %q: %w", ipCIDR, err)
	}
	gwIP := net.ParseIP(gateway).To4()
	if gwIP == nil {
		return nil, fmt.Errorf("bad gateway %q", gateway)
	}

	// Names: both must fit in IFNAMSIZ (15 bytes).
	//  - host side: "fcp" + N (counter from "fcpN") — direct encoding,
	//    no hash, no collision risk. See vethNameFor() in network.go.
	//  - peer transient: "fcq" + shortHash(id) — moved into the slot's
	//    netns and renamed to "veth0" before any user code sees it; hash
	//    is fine because it's never accessed by name post-rename.
	hostVeth := vethNameFor(id)
	peerName := "fcq" + shortHash(id)
	// Generate random MACs — one per end. tap0 reuses the veth's MAC so the
	// virtio-net in the guest sees frames addressed to the same L2.
	hostMAC := randMAC()
	guestMAC := randMAC()

	// 1. veth pair in root ns.
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:         hostVeth,
			HardwareAddr: hostMAC,
			MTU:          1500,
		},
		PeerName:         peerName,
		PeerHardwareAddr: guestMAC,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("veth add: %w", err)
	}
	// From here on, on error, best-effort delete the veth to free resources.
	cleanupOnErr := func(err error) error {
		_ = netlink.LinkDel(veth)
		return err
	}

	hostLink, err := netlink.LinkByName(hostVeth)
	if err != nil {
		return nil, cleanupOnErr(fmt.Errorf("lookup host veth: %w", err))
	}
	peerLink, err := netlink.LinkByName(peerName)
	if err != nil {
		return nil, cleanupOnErr(fmt.Errorf("lookup peer veth: %w", err))
	}

	// 2. Move peer into netns, then configure everything inside.
	nsH, err := vnetns.GetFromPath(nsPath)
	if err != nil {
		return nil, cleanupOnErr(fmt.Errorf("open netns: %w", err))
	}
	defer nsH.Close()
	if err := netlink.LinkSetNsFd(peerLink, int(nsH)); err != nil {
		return nil, cleanupOnErr(fmt.Errorf("veth to netns: %w", err))
	}

	// Configure inside the target netns. This section runs with the goroutine
	// pinned to a thread that's switched into nsH; we always restore before
	// returning.
	tapName, err := configureGuestNS(nsH, peerName, guestMAC, hostMAC, ip, ipNet, gwIP, slotUID, slotGID)
	if err != nil {
		return nil, cleanupOnErr(fmt.Errorf("configure guest netns: %w", err))
	}

	// 3. Bring up the host side and route the VM IP through it.
	if err := netlink.LinkSetUp(hostLink); err != nil {
		return nil, cleanupOnErr(fmt.Errorf("host veth up: %w", err))
	}
	// Disable IPv6 on the host-side veth. createos's overlay, BPF gates,
	// MASQUERADE rules, and the transparent egress proxy are all IPv4-only.
	// Without this, a guest that auto-configured an IPv6 link-local could
	// in principle emit packets that the IPv4 iptables REDIRECT chains
	// never see — bypassing the per-VM egress allowlist. Defense in depth:
	// the guest doesn't have IPv6 connectivity beyond link-local anyway,
	// but we kill the interface address entirely so there's no surface.
	disableV6Path := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", hostVeth)
	if err := os.WriteFile(disableV6Path, []byte("1"), 0); err != nil {
		// Non-fatal: hosts compiled without CONFIG_IPV6 won't have the
		// sysctl, and that's fine — there's no IPv6 to leak there.
		log.Debugf("[net-direct] disable ipv6 on %s: %v (continuing)", hostVeth, err)
	}
	// Strict reverse-path filter on the per-VM host veth. The kernel's
	// rp_filter (=1) rejects any incoming packet whose source IP isn't
	// reachable back out the same interface. For us: a VM at 10.0.0.5
	// trying to spoof src=10.0.0.99 gets dropped at receive — the route
	// to 10.0.0.99 goes out a different veth. The BPF VNI gate already
	// blocks cross-tenant, but rp_filter closes the intra-subnet spoof
	// (conntrack pollution, byte-meter framing, anything else that
	// trusts src_ip). Effective value is max(conf.all, conf.<iface>),
	// so we set the per-iface value rather than depending on the host
	// default. Best-effort.
	rpFilterPath := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", hostVeth)
	if err := os.WriteFile(rpFilterPath, []byte("1"), 0); err != nil {
		log.Debugf("[net-direct] rp_filter on %s: %v (continuing)", hostVeth, err)
	}
	// Put the per-VM gateway IP /31 on the host veth. Each VM has a unique
	// gateway, so multiple fcv interfaces never share an address — strict
	// reverse-path filter passes because every IP is reachable through
	// exactly one interface.
	prefixBits, _ := ipNet.Mask.Size()
	gwAddr := &netlink.Addr{IPNet: &net.IPNet{IP: gwIP, Mask: net.CIDRMask(prefixBits, 32)}}
	if err := netlink.AddrAdd(hostLink, gwAddr); err != nil && !isExists(err) {
		return nil, cleanupOnErr(fmt.Errorf("host gw addr: %w", err))
	}
	// No explicit host route: the /31 onlink route the kernel installs from
	// the AddrAdd above is sufficient. An explicit `scope host` route would
	// mark the VM IP as local-to-the-host and prevent forwarding across
	// the veth — that was a bug carried over from the shared-gateway era.

	return &directNetResult{
		HostVeth: hostVeth,
		TapName:  tapName,
		MAC:      guestMAC.String(),
		Gateway:  gwIP.String(),
	}, nil
}

// configureGuestNS runs with the calling goroutine pinned to a thread
// temporarily switched into nsH. Creates tap0, renames the peer veth to
// "veth0", configures IP + route, and wires the tc mirred redirect between
// veth0 and tap0. Always restores the original netns before returning.
func configureGuestNS(nsH vnetns.NsHandle, peerName string, guestMAC, hostMAC net.HardwareAddr, ip net.IP, ipNet *net.IPNet, gw net.IP, slotUID, slotGID uint32) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origNS, err := vnetns.Get()
	if err != nil {
		return "", fmt.Errorf("get current netns: %w", err)
	}
	defer origNS.Close()
	if err := vnetns.Set(nsH); err != nil {
		return "", fmt.Errorf("enter netns: %w", err)
	}
	defer func() { _ = vnetns.Set(origNS) }() // best-effort restore; nothing useful to do if it fails

	// Rename the moved veth to "veth0" so Firecracker's static-network-config
	// (and any existing agent code) finds the expected device name.
	peer, err := netlink.LinkByName(peerName)
	if err != nil {
		return "", fmt.Errorf("peer lookup in ns: %w", err)
	}
	if err := netlink.LinkSetName(peer, "veth0"); err != nil {
		return "", fmt.Errorf("rename peer: %w", err)
	}
	veth0, err := netlink.LinkByName("veth0")
	if err != nil {
		return "", fmt.Errorf("lookup veth0: %w", err)
	}
	if err := netlink.LinkSetUp(veth0); err != nil {
		return "", fmt.Errorf("veth0 up: %w", err)
	}
	// Disable IPv6 on veth0 inside the guest netns. We're IPv4-only on the
	// overlay; without this, the guest auto-assigns an IPv6 link-local and
	// could (in principle) emit packets the host's IPv4 iptables proxy
	// REDIRECT never sees. Best-effort: kernels without CONFIG_IPV6 just
	// don't have the file.
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/veth0/disable_ipv6", []byte("1"), 0)
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/all/disable_ipv6", []byte("1"), 0)
	// Assign the VM IP on veth0 with the /24 mask so the agent's IP config
	// reads it back correctly post-boot.
	ones, _ := ipNet.Mask.Size()
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: net.CIDRMask(ones, 32)}}
	if err := netlink.AddrAdd(veth0, addr); err != nil {
		return "", fmt.Errorf("veth0 addr: %w", err)
	}
	// Default route via gateway.
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: veth0.Attrs().Index,
		Gw:        gw,
	}); err != nil {
		return "", fmt.Errorf("default route: %w", err)
	}

	// Create tap0 with the SAME MAC as veth0 so the virtio-net sees matching L2.
	// NOTE: tc-redirect-tap uses different MACs too; matching isn't required
	// for mirred redirection to work, but we mirror its behaviour by keeping
	// tap0 with its own auto-assigned MAC.
	tap := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: "tap0", MTU: 1500},
		Mode:      netlink.TUNTAP_MODE_TAP,
		Flags:     netlink.TUNTAP_DEFAULTS | netlink.TUNTAP_NO_PI,
	}
	// When per-slot UIDs are enabled, stamp the tap with TUNSETOWNER
	// AND TUNSETGROUP. Both are required: the kernel's tun_not_capable
	// check fails EPERM unless caller's euid matches Owner AND caller
	// is in the tap's Group (or has CAP_NET_ADMIN). Group=kvm matches
	// the supplementary group we pass in firecracker's Credential.
	if slotUID > 0 {
		tap.Owner = slotUID
		tap.Group = slotGID
	}
	if err := netlink.LinkAdd(tap); err != nil {
		return "", fmt.Errorf("tap add: %w", err)
	}
	tapLink, err := netlink.LinkByName("tap0")
	if err != nil {
		return "", fmt.Errorf("tap lookup: %w", err)
	}
	if err := netlink.LinkSetUp(tapLink); err != nil {
		return "", fmt.Errorf("tap up: %w", err)
	}

	// 4. tc-redirect-tap equivalent: ingress qdisc on each, u32 matching all
	// packets, action mirred egress redir to the other device.
	if err := netlink.QdiscAdd(&netlink.Ingress{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: veth0.Attrs().Index,
			Parent:    netlink.HANDLE_INGRESS,
		},
	}); err != nil {
		return "", fmt.Errorf("veth0 ingress qdisc: %w", err)
	}
	if err := netlink.QdiscAdd(&netlink.Ingress{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: tapLink.Attrs().Index,
			Parent:    netlink.HANDLE_INGRESS,
		},
	}); err != nil {
		return "", fmt.Errorf("tap ingress qdisc: %w", err)
	}

	// Match-all u32 filter on each, with mirred redirect to the counterpart.
	// Priority 49152 matches what tc-redirect-tap uses.
	addMirred := func(from, to netlink.Link) error {
		mirred := netlink.NewMirredAction(to.Attrs().Index)
		f := &netlink.U32{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: from.Attrs().Index,
				Parent:    netlink.MakeHandle(0xffff, 0),
				Priority:  49152,
				Protocol:  unix.ETH_P_ALL,
			},
			Actions: []netlink.Action{mirred},
		}
		return netlink.FilterAdd(f)
	}
	if err := addMirred(veth0, tapLink); err != nil {
		return "", fmt.Errorf("veth→tap filter: %w", err)
	}
	if err := addMirred(tapLink, veth0); err != nil {
		return "", fmt.Errorf("tap→veth filter: %w", err)
	}

	return "tap0", nil
}

// teardownNetDirect removes the host-side veth (which implicitly removes its
// peer, the tap, all the tc state, and the host route). Release of the IP
// back to StaticIPAM is the caller's job.
func teardownNetDirect(hostVeth string) error {
	for attempt := 1; attempt <= 3; attempt++ {
		link, err := netlink.LinkByName(hostVeth)
		if err != nil {
			var notFound netlink.LinkNotFoundError
			if errors.As(err, &notFound) {
				return nil // already gone
			}
			return fmt.Errorf("lookup %s: %w", hostVeth, err)
		}
		if err := netlink.LinkDel(link); err == nil {
			return nil
		} else if attempt == 3 {
			return fmt.Errorf("delete %s after %d attempts: %w", hostVeth, attempt, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

// EnsureDirectNetMasquerade installs a single MASQUERADE rule covering the
// whole VM subnet, so we don't need per-VM NAT. Call once at startup.
//
// Two exclusions stay UN-MASQUERADED:
//   - `! -o wg-hosts`: cross-host VM traffic flows raw inside the WG mesh.
//     SNAT'ing the source to the host's WG IP would break the peer-side
//     BPF gate (source/destination allow-pair lookup) and the destination's ability to
//     reply to the real VM IP.
//   - `! -d <subnet>`: same-host VM-to-VM traffic exits one veth and enters
//     another in the same /22 — SNAT here would rewrite src=VM-A to
//     src=host-gateway and the destination's BPF gate would see "src
//     is not a VM", bypassing the agent-port protection.
//
// Internet egress (out eth0 / underlay, to non-VM destinations) still
// gets MASQUERADE'd as before.
func EnsureDirectNetMasquerade(subnet string) error {
	if subnet == "" {
		return nil
	}
	// Idempotent: `-C` first, `-I` if missing.
	args := []string{
		"-t", "nat", "-C", "POSTROUTING",
		"-s", subnet,
		"!", "-d", subnet,
		"!", "-o", WGHostsDevName,
		"-j", "MASQUERADE",
	}
	if err := runIPT(args...); err == nil {
		// Already present in the desired shape.
		return nil
	}
	// Best-effort cleanup of any stale rule without one or both exclusions.
	_ = runIPT("-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE")
	_ = runIPT("-t", "nat", "-D", "POSTROUTING", "-s", subnet, "!", "-o", WGHostsDevName, "-j", "MASQUERADE")
	return runIPT(
		"-t", "nat", "-I", "POSTROUTING",
		"-s", subnet,
		"!", "-d", subnet,
		"!", "-o", WGHostsDevName,
		"-j", "MASQUERADE",
	)
}

// vmSubnet is the CIDR covering every VM's IP on this host. Captured by
// EnsureInterVMIsolation at startup so per-VM egress chains built later
// can install a pre-emptive DROP for peer-VM destinations.
var vmSubnet string

// EnsureInterVMIsolation installs the FORWARD rules that make the VM
// subnet routable. Tenant isolation between VMs is enforced by the BPF
// `fc_veth_policy` gate (VNI intersection), not by iptables — Path B
// uses kernel routing for same-host VM-to-VM, so an iptables intra-subnet
// DROP would also block legitimate same-host same-tenant traffic.
//
//  1. -s subnet -j ACCEPT                  ← VM → internet/peer allowed
//  2. -d subnet -m ctstate …,EST -j ACCEPT ← return traffic allowed
//  3. -i wg-hosts -j ACCEPT                ← cross-host overlay arriving via WG
//
// Without rules 1 and 2, a host with `-P FORWARD DROP` (UFW default on
// many distros, also k3s/k8s nodes after Calico / kube-proxy install
// their own chains) silently blocks VM outbound.
//
// Idempotent: -C before every -I so re-running on startup is cheap.
func EnsureInterVMIsolation(subnet string) error {
	if subnet == "" {
		return nil
	}
	vmSubnet = subnet

	// Clean up the legacy intra-subnet DROP rule from the pre-Path-B era
	// (it would now block same-host same-tenant traffic that the BPF gate
	// already allowed). Best-effort: nothing depends on this succeeding.
	_ = runIPT("-D", "FORWARD", "-s", subnet, "-d", subnet, "-j", "DROP")

	// Rule 1: ACCEPT outbound from VMs.
	if err := ensureForwardRule(
		[]string{"-s", subnet, "-j", "ACCEPT"},
		false,
	); err != nil {
		return fmt.Errorf("install subnet outbound ACCEPT: %w", err)
	}
	// Rule 3: ACCEPT return traffic (replies to VM-initiated conns).
	// The -s rule alone isn't enough because reply packets have dst in
	// the subnet, not src; the RELATED,ESTABLISHED match keeps this
	// scoped to conntrack-approved flows so it's not a blanket hole.
	if err := ensureForwardRule(
		[]string{"-d", subnet, "-m", "conntrack",
			"--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		false,
	); err != nil {
		return fmt.Errorf("install subnet return ACCEPT: %w", err)
	}

	// Rule 4: ACCEPT cross-host overlay packets arriving via the WG mesh.
	// fc_wg_ingress BPF has already enforced tenant (VNI) isolation, so
	// anything that reaches FORWARD on `-i wg-hosts` is an authorized
	// overlay packet headed for one of our local VMs. Without this rule
	// the default-DROP policy kills NEW-state SYN packets from peer VMs
	// (the RELATED,ESTABLISHED rule above only covers replies).
	if err := ensureForwardRule(
		[]string{"-i", WGHostsDevName, "-j", "ACCEPT"},
		false,
	); err != nil {
		return fmt.Errorf("install wg-hosts forward ACCEPT: %w", err)
	}

	// Rule 5 (INPUT): DROP VM-originated attempts to reach host services
	// that aren't part of the VM data plane. Defense-in-depth against a
	// future pre-auth CVE in sshd / Go net-http / mTLS parser reachable
	// on those ports. App-level auth (SSH pubkey, mTLS, bearer token)
	// remains the primary gate; this closes the wire-level probe surface.
	//
	// Ports blocked (all TCP, from VM subnet only):
	//   22   sshd
	//   111  rpcbind (unused, but bound by baseline distro packages)
	//   9090 machine host mTLS listener
	//   9091 createos metrics + pprof
	//
	// NOT blocked:
	//   - 8081/8443 (proxy, restricted to sandbox interfaces below)
	//   - 169.254.20.10:53 (DNS stub, dst-based accept elsewhere)
	//   - Host-initiated → VM:1024/1025 (agent RPC): the SYN-ACK reply
	//     has DST PORT = host's ephemeral (32768+), never matches this
	//     dports list. Verified with tcpdump + e2e_crucial (10/10 pass).
	if err := ensureInputRule(
		[]string{"-s", subnet, "-p", "tcp", "-m", "multiport",
			"--dports", "22,111,9090,9091", "-j", "DROP",
			"-m", "comment", "--comment", "createos-vm-host-ports-block"},
	); err != nil {
		return fmt.Errorf("install INPUT drop for VM-side host probes: %w", err)
	}
	return ensureProxyInput(subnet)
}

// ensureProxyInput protects the shared transparent-proxy listeners. REDIRECT
// changes the destination, but retains the incoming fcpN interface. A public
// connection must never reach the proxy's source-IP lookup, even on hosts whose
// INPUT policy is ACCEPT. IPv6 is not part of the sandbox data plane.
func ensureProxyInput(subnet string) error {
	if ip, _, err := net.ParseCIDR(subnet); err != nil || ip.To4() == nil {
		return fmt.Errorf("invalid IPv4 proxy subnet %q", subnet)
	}
	const chain = "CREATEOS_PROXY_INPUT"
	ports := fmt.Sprintf("%d,%d", ProxyHTTPPort, ProxyHTTPSPort)
	jump := "-p tcp -m multiport --dports " + ports + " -j " + chain
	for _, binary := range []string{"iptables", "ip6tables"} {
		if binary == "ip6tables" {
			if _, err := os.Stat("/proc/net/if_inet6"); os.IsNotExist(err) {
				continue // Kernel has no IPv6 stack/listener to protect.
			}
		}
		var rules strings.Builder
		fmt.Fprintf(&rules, "*filter\n:%s - [0:0]\n-F %s\n", chain, chain)
		if binary == "iptables" {
			fmt.Fprintf(&rules, "-A %s -i %s+ -s %s -j ACCEPT\n", chain, VethHostPrefix, subnet)
			// Remove the old subnet-only permission as part of the same commit.
			legacy := "-s " + subnet + " -p tcp -m multiport --dports " + ports + " -j ACCEPT"
			if runIPT(append([]string{"-C", "INPUT"}, strings.Fields(legacy)...)...) == nil {
				fmt.Fprintf(&rules, "-D INPUT %s\n", legacy)
			}
		}
		fmt.Fprintf(&rules, "-A %s -j DROP\n", chain)
		args := append([]string{"-w", "2", "-C", "INPUT"}, strings.Fields(jump)...)
		if exec.Command(binary, args...).Run() == nil {
			fmt.Fprintf(&rules, "-D INPUT %s\n", jump)
		}
		// Move the gate ahead of existing broad ACCEPT/ESTABLISHED rules.
		// Replacing the chain and jump atomically avoids an open restart window.
		fmt.Fprintf(&rules, "-I INPUT 1 %s\nCOMMIT\n", jump)
		cmd := exec.Command(binary+"-restore", "--noflush", "-w", "2")
		cmd.Stdin = strings.NewReader(rules.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("install proxy INPUT protection (%s): %w (%s)", binary, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// ensureInputRule installs an INPUT rule idempotently at position 1.
func ensureInputRule(spec []string) error {
	check := append([]string{"-C", "INPUT"}, spec...)
	if err := runIPT(check...); err == nil {
		return nil // already present
	}
	insert := append([]string{"-I", "INPUT", "1"}, spec...)
	return runIPT(insert...)
}

// ensureForwardRule installs a FORWARD rule idempotently. Runs -C first
// to detect an existing match; if absent, uses -I 1 (when atTop is set)
// or -A to append.
func ensureForwardRule(spec []string, atTop bool) error {
	check := append([]string{"-C", "FORWARD"}, spec...)
	if err := runIPT(check...); err == nil {
		return nil // already present
	}
	insert := []string{"-A", "FORWARD"}
	if atTop {
		insert = []string{"-I", "FORWARD", "1"}
	}
	return runIPT(append(insert, spec...)...)
}

// --- helpers ---

// randMAC returns a random locally-administered unicast MAC (02:xx:...).
func randMAC() net.HardwareAddr {
	buf := make([]byte, 6)
	_, _ = rand.Read(buf)
	buf[0] = (buf[0] | 0x02) & 0xfe // set local bit, clear multicast bit
	return net.HardwareAddr(buf)
}

func shortHash(id string) string {
	// 10 hex-ish chars derived from id — stable, fits in IFNAMSIZ together
	// with the 3-char prefix. Simple FNV-ish since collisions are tolerable
	// (we just need uniqueness among concurrently-live VMs).
	var h uint64 = 14695981039346656037
	for i := 0; i < len(id); i++ {
		h ^= uint64(id[i])
		h *= 1099511628211
	}
	s := fmt.Sprintf("%x", h)
	if len(s) > 12 {
		s = s[:12]
	}
	return s
}

func isExists(err error) bool {
	return err != nil && strings.Contains(err.Error(), "file exists")
}
