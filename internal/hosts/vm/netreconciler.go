package vm

// netreconciler.go runs a 5-second loop that fetches the desired overlay
// network state from the control plane and syncs the four pinned eBPF maps
// used by the policy programs. It is the sole writer to those maps for
// cross-host policy; the fast path (create/destroy) writes local entries
// directly.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/NodeOps-app/createos-sandbox/internal/hosts/vm/dns"
)

// NetReconcilerConfig configures the network reconciler loop.
type NetReconcilerConfig struct {
	// ControlURL is the base URL of control's internal mTLS endpoint.
	ControlURL string
	// HostID is this host's registered identifier.
	HostID string
	// Interval between reconcile ticks. Default 5s.
	Interval time.Duration
	// Client carries the host's mTLS credentials for control-plane calls.
	// If nil, the loop uses a plain client with a 5s timeout.
	Client *http.Client
	// IFIndexForIP returns the host-side veth ifindex for a VM IP that lives
	// on this host. Returns 0 if the IP is unknown (reconciler skips the
	// ifindex map entry for that VM).
	IFIndexForIP func(ip string) uint32
	// LocalSandboxIDForIP returns the ID of the live local sandbox currently
	// holding an IP. Control state may be briefly stale while a permanent
	// network slot is recycled; matching both ID and IP prevents an old
	// sandbox's memberships from being assigned to the new occupant's veth.
	LocalSandboxIDForIP func(ip string) string

	// LocalSandboxIPs returns the IPv4 addresses of every live sandbox on
	// this host — including ones that are NOT a member of any overlay.
	// The reconciler includes these IPs in fc_known_vmips without granting
	// any network-derived allow pairs. BPF can then distinguish them from
	// external destinations and reject traffic without an allowed pair.
	// Nil disables this enumeration of unnetworked local sandboxes.
	LocalSandboxIPs func() []string
	// DNSTable is updated on every tick with the current sandbox-name → IP
	// and alias → IP mappings for all VMs visible to this host's networks.
	// Nil disables DNS table updates (DNS stub won't resolve anything).
	DNSTable *dns.Table

	// Trigger is an optional non-blocking wake channel. The loop selects
	// on both ticker.C and Trigger; either fires reconcileOnce. Used by
	// the Create path to publish a new sandbox's overlay membership
	// instantly instead of waiting up to one full interval.
	Trigger <-chan struct{}
}

// hostStateResp mirrors the JSON from GET /v1/internal/networks/host-state.
type hostStateResp struct {
	Status string        `json:"status"`
	Data   hostStateData `json:"data"`
}

type hostStateData struct {
	Members []hostStateMember `json:"members"`
	Epoch   int64             `json:"epoch"`
}

type hostStateMember struct {
	SandboxID   string `json:"sandbox_id"`
	IP          string `json:"ip"`
	MAC         string `json:"mac,omitempty"`
	HostID      string `json:"host_id"`
	UnderlayIP  string `json:"underlay_ip,omitempty"`
	WGIP        string `json:"wg_ip,omitempty"` // peer's WG mesh IP (172.30.0.X)
	NetworkID   string `json:"network_id"`
	NetworkName string `json:"network_name,omitempty"`
	Name        string `json:"name,omitempty"`
	VNI         int    `json:"vni"`
	IsLocal     bool   `json:"is_local"`
	Kind        string `json:"kind,omitempty"` // "vm" | "device"
}

// RunNetReconciler starts the reconcile loop and blocks until ctx is done.
func RunNetReconciler(ctx context.Context, cfg NetReconcilerConfig) {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	if cfg.Client == nil {
		// HTTP/1.1 explicitly. Go's default Transport auto-upgrades to
		// HTTP/2 on TLS, which panics under burst:
		//   panic: id (N) <= evictCount (M)
		//   x/net/http2/hpack.(*headerFieldTable).idToIndex
		// See internal/hosts/controlclient/main.go for the longer note.
		cfg.Client = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				Proxy:               http.ProxyFromEnvironment,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
				ForceAttemptHTTP2:   false,
			},
		}
	}

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := reconcileOnce(ctx, cfg); err != nil {
				log.WithContext(ctx).Warnf("[net-reconciler] tick error: %v", err)
			}
		case <-cfg.Trigger:
			if err := reconcileOnce(ctx, cfg); err != nil {
				log.WithContext(ctx).Warnf("[net-reconciler] trigger error: %v", err)
			}
		}
	}
}

func reconcileOnce(ctx context.Context, cfg NetReconcilerConfig) error {
	o := globalOverlayMaps
	if o.ifacePair == nil {
		log.WithContext(ctx).Infof("[net-reconciler] maps not initialized, skipping")
		return nil // overlay maps not enabled
	}
	// Serialize the state read and its map application with synchronous slot
	// cleanup. Taking only the low-level map lock around writes would allow a
	// reconcile that fetched pre-destroy state to reinsert stale pairs after
	// destroy removed them and returned the slot to another tenant.
	o.reconcileMu.Lock()
	defer o.reconcileMu.Unlock()

	members, err := fetchHostState(ctx, cfg)
	if err != nil {
		return fmt.Errorf("fetch host-state: %w", err)
	}
	log.WithContext(ctx).Infof("[net-reconciler] got %d members from host-state", len(members))

	// Group members into per-VM state keyed by IP.
	type vmInfo struct {
		ip      string
		ipNet   uint32 // big-endian (matches packet view)
		isLocal bool
		vnis    map[int]struct{}
		ifindex uint32 // 0 if unknown / not local
	}
	vms := make(map[string]*vmInfo, len(members))
	for _, m := range members {
		if m.IP == "" {
			continue
		}
		if m.IsLocal && cfg.LocalSandboxIDForIP != nil {
			currentID := cfg.LocalSandboxIDForIP(m.IP)
			if currentID == "" || currentID != m.SandboxID {
				log.WithContext(ctx).Warnf("[net-reconciler] ignoring stale local member id=%s ip=%s current_id=%s",
					m.SandboxID, m.IP, currentID)
				continue
			}
		}
		v, ok := vms[m.IP]
		if !ok {
			ipN, err := ipKey(m.IP)
			if err != nil {
				continue
			}
			v = &vmInfo{
				ip:      m.IP,
				ipNet:   ipN,
				isLocal: m.IsLocal,
				vnis:    make(map[int]struct{}, 4),
			}
			if m.IsLocal && cfg.IFIndexForIP != nil {
				v.ifindex = cfg.IFIndexForIP(m.IP)
			}
			vms[m.IP] = v
		}
		if m.VNI > 0 {
			v.vnis[m.VNI] = struct{}{}
		}
	}

	// Add LOCAL unnetworked sandboxes so they appear in fc_known_vmips.
	// Without this entry, the BPF programs treat an unnetworked VM as
	// "external" → two unnetworked sandboxes could route to each other
	// through the kernel fabric and bypass tenant isolation.
	if cfg.LocalSandboxIPs != nil {
		for _, ipStr := range cfg.LocalSandboxIPs() {
			if _, ok := vms[ipStr]; ok {
				continue
			}
			ipN, err := ipKey(ipStr)
			if err != nil {
				continue
			}
			v := &vmInfo{
				ip:      ipStr,
				ipNet:   ipN,
				isLocal: true,
				vnis:    map[int]struct{}{},
			}
			if cfg.IFIndexForIP != nil {
				v.ifindex = cfg.IFIndexForIP(ipStr)
			}
			vms[ipStr] = v
		}
	}

	// Enumerate desired state for the four maps.
	desiredKnownVMIPs := make(map[uint32]struct{}, len(vms))
	desiredIfaceToIP := make(map[uint32]uint32, len(vms))      // ifindex → ip
	desiredIfacePair := make(map[pairKey]struct{}, 4*len(vms)) // (ifindex, dst_ip)
	desiredVMIPPair := make(map[pairKey]struct{}, 4*len(vms))  // (src_ip, dst_ip)

	vmList := make([]*vmInfo, 0, len(vms))
	for _, v := range vms {
		vmList = append(vmList, v)
		desiredKnownVMIPs[v.ipNet] = struct{}{}
		if v.isLocal && v.ifindex != 0 {
			desiredIfaceToIP[v.ifindex] = v.ipNet
		}
	}

	// Borrowed slots can carry traffic before Manager registers the sandbox.
	// Preserve their identities, but never infer network membership from them.
	// Slot cleanup removes these entries under the same reconcile lock.
	for ifindex, ip := range o.boundIfaces {
		desiredKnownVMIPs[ip] = struct{}{}
		desiredIfaceToIP[ifindex] = ip
	}

	// For every ordered pair (a, b) of VMs visible to this host:
	//   if a and b share at least one VNI, allow a → b.
	// Skip pairs where neither side is local — the host has no work to
	// enforce on traffic that never touches a local veth or wg-hosts.
	for i := range vmList {
		a := vmList[i]
		for j := range vmList {
			if i == j {
				continue
			}
			b := vmList[j]
			if !a.isLocal && !b.isLocal {
				continue
			}
			if !shareVNI(a.vnis, b.vnis) {
				continue
			}
			// a sends to b — local-source side uses ifindex (unspoofable).
			if a.isLocal && a.ifindex != 0 {
				desiredIfacePair[pairKey{A: a.ifindex, B: b.ipNet}] = struct{}{}
			}
			// vmip_pair carries the direction for delivery (fc_veth_deliver)
			// and cross-host receiver (fc_wg_ingress).
			desiredVMIPPair[pairKey{A: a.ipNet, B: b.ipNet}] = struct{}{}
		}
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	// Diff + apply fc_known_vmips.
	currentKnown := iterU32Set(o.knownVMIPs)
	for ip := range desiredKnownVMIPs {
		if _, ok := currentKnown[ip]; ok {
			delete(currentKnown, ip)
			continue
		}
		if err := SetKnownVMIP(ip); err != nil {
			log.WithContext(ctx).Warnf("[net-reconciler] put known_vmips %s: %v", ipString(ip), err)
		}
	}
	for ip := range currentKnown {
		if err := DeleteKnownVMIP(ip); err != nil {
			log.WithContext(ctx).Warnf("[net-reconciler] delete known_vmips %s: %v", ipString(ip), err)
		}
	}

	// Diff + apply fc_iface_to_ip.
	currentIfaceToIP := iterU32U32(o.ifaceToIP)
	for ifindex, ip := range desiredIfaceToIP {
		if cur, ok := currentIfaceToIP[ifindex]; ok && cur == ip {
			delete(currentIfaceToIP, ifindex)
			continue
		}
		if err := SetIfaceToIP(ifindex, ip); err != nil {
			log.WithContext(ctx).Warnf("[net-reconciler] put iface_to_ip ifindex=%d ip=%s: %v",
				ifindex, ipString(ip), err)
		}
		delete(currentIfaceToIP, ifindex)
	}
	for ifindex := range currentIfaceToIP {
		if err := DeleteIfaceToIP(ifindex); err != nil {
			log.WithContext(ctx).Warnf("[net-reconciler] delete iface_to_ip ifindex=%d: %v", ifindex, err)
		}
	}

	// Diff + apply fc_iface_pair.
	currentIfacePair := iterIfacePairSet(o.ifacePair)
	for k := range desiredIfacePair {
		if _, ok := currentIfacePair[k]; ok {
			delete(currentIfacePair, k)
			continue
		}
		if err := SetIfacePair(k.A, k.B); err != nil {
			log.WithContext(ctx).Warnf("[net-reconciler] put iface_pair ifindex=%d dst=%s: %v",
				k.A, ipString(k.B), err)
		}
	}
	for k := range currentIfacePair {
		if err := DeleteIfacePair(k.A, k.B); err != nil {
			log.WithContext(ctx).Warnf("[net-reconciler] delete iface_pair ifindex=%d dst=%s: %v",
				k.A, ipString(k.B), err)
		}
	}

	// Diff + apply fc_vmip_pair.
	currentVMIPPair := iterVMIPPairSet(o.vmipPair)
	for k := range desiredVMIPPair {
		if _, ok := currentVMIPPair[k]; ok {
			delete(currentVMIPPair, k)
			continue
		}
		if err := SetVMIPPair(k.A, k.B); err != nil {
			log.WithContext(ctx).Warnf("[net-reconciler] put vmip_pair src=%s dst=%s: %v",
				ipString(k.A), ipString(k.B), err)
		}
	}
	for k := range currentVMIPPair {
		if err := DeleteVMIPPair(k.A, k.B); err != nil {
			log.WithContext(ctx).Warnf("[net-reconciler] delete vmip_pair src=%s dst=%s: %v",
				ipString(k.A), ipString(k.B), err)
		}
	}

	log.WithContext(ctx).Infof("[net-reconciler] applied: known=%d iface_to_ip=%d iface_pair=%d vmip_pair=%d",
		len(desiredKnownVMIPs), len(desiredIfaceToIP), len(desiredIfacePair), len(desiredVMIPPair))

	// Update DNS table from member list.
	if cfg.DNSTable != nil {
		updateDNSTable(cfg, members)
	}

	// Install /32 routes for remote DEVICE endpoints so this host's
	// kernel knows to send reply traffic via the relay holding each
	// device's WG session. VMs' /22 routes are handled by the wg-hosts
	// peer reconciler (via host.subnet_cidr); devices don't fit in a
	// subnet allocator because they're CGNAT-pool-allocated globally,
	// so we install per-device /32s here.
	reconcileDeviceRoutes(members)

	return nil
}

// reconcileDeviceRoutes installs /32 routes on wg-hosts for every
// device endpoint in `members` (kind="device", non-local). Cleans up
// stale routes the same loop that owned. Idempotent.
func reconcileDeviceRoutes(members []hostStateMember) {
	link, err := netlink.LinkByName("wg-hosts")
	if err != nil {
		log.Debugf("[net-reconciler] device routes: no wg-hosts iface: %v", err)
		return
	}

	desired := make(map[string]net.IP) // dst-cidr → next-hop
	for _, m := range members {
		if m.Kind != "device" || m.IP == "" || m.WGIP == "" {
			continue
		}
		ip := net.ParseIP(m.IP)
		gw := net.ParseIP(m.WGIP)
		if ip == nil || gw == nil {
			continue
		}
		cidr := ip.String() + "/32"
		desired[cidr] = gw
	}

	// Apply desired.
	for cidr, gw := range desired {
		_, dst, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dst,
			Gw:        gw,
			Protocol:  unix.RTPROT_BOOT,
		}
		if err := netlink.RouteReplace(route); err != nil {
			log.Warnf("[net-reconciler] device route %s via %s: %v", cidr, gw, err)
		}
	}

	// Cleanup: drop our previously-installed device routes that aren't
	// in desired anymore (session expired, device disconnected). We
	// identify "our" routes by Protocol=BOOT + a destination in
	// 100.64.0.0/10 (the CGNAT device pool). The protocol tag is the
	// load-bearing guard — without it, a stray operator-installed route
	// in that CIDR (unusual but possible) would get clobbered every tick.
	existing, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return
	}
	_, devicePool, _ := net.ParseCIDR("100.64.0.0/10")
	for _, r := range existing {
		if r.Protocol != unix.RTPROT_BOOT {
			continue // not ours
		}
		if r.Dst == nil || !devicePool.Contains(r.Dst.IP) {
			continue
		}
		if _, keep := desired[r.Dst.String()]; keep {
			continue
		}
		_ = netlink.RouteDel(&r)
	}
}

// shareVNI returns true iff a and b have at least one VNI in common.
// Iterates the smaller set so worst-case is O(min(|a|, |b|)).
func shareVNI(a, b map[int]struct{}) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	for v := range a {
		if _, ok := b[v]; ok {
			return true
		}
	}
	return false
}

// ipString formats a u32 (network byte order) as dotted-quad.
func ipString(ipNet uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ipNet>>24)&0xff, (ipNet>>16)&0xff, (ipNet>>8)&0xff, ipNet&0xff)
}

// updateDNSTable rebuilds the name→IP mappings from the current member list.
// All keys are lowercased so they match DNS queries (the wire format is
// case-insensitive and the stub server lowercases QNAME on parse).
func updateDNSTable(cfg NetReconcilerConfig, members []hostStateMember) {
	bySandboxID := make(map[string]string)
	byName := make(map[string]string)
	// VM IP → (lowercased network name → VNI) for that VM's memberships.
	// Keyed by VNI, not name: network names are unique only per-user, so
	// two tenants can each have a network "net" — resolving by name alone
	// would let one tenant's DNS query hit the other's VM.
	srcNets := make(map[string]map[string]int)

	for _, m := range members {
		if m.SandboxID == "" || m.IP == "" {
			continue
		}
		// One entry per sandbox_id (first seen wins when multi-network).
		// Sandbox IDs contain uppercase Crockford base32; DNS QNAME is
		// lowercased by parseQuestion, so the key must be lowercase too.
		// Strip the `sb-` prefix: glibc rejects underscores in hostnames
		// before sending, so users query `<ulid>.fc.local`.
		k := strings.ToLower(strings.TrimPrefix(m.SandboxID, "sb-"))
		if _, ok := bySandboxID[k]; !ok {
			bySandboxID[k] = m.IP
		}
		// Name form keyed by VNI (globally unique) + VM name. The DNS
		// stub resolves the query's network-name component to a VNI
		// within the requester's own membership before looking here.
		if m.Name != "" && m.VNI > 0 {
			byName[dns.NameKey(m.VNI, strings.ToLower(m.Name))] = m.IP
		}
		// Track requester membership: network name → VNI, per VM IP.
		if m.NetworkName != "" && m.VNI > 0 {
			set, ok := srcNets[m.IP]
			if !ok {
				set = make(map[string]int)
				srcNets[m.IP] = set
			}
			set[strings.ToLower(m.NetworkName)] = m.VNI
		}
	}
	cfg.DNSTable.Update(bySandboxID, byName, srcNets)
}

func fetchHostState(ctx context.Context, cfg NetReconcilerConfig) ([]hostStateMember, error) {
	url := cfg.ControlURL + "/v1/internal/networks/host-state?host_id=" + cfg.HostID

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	// Authentication rides on the mTLS handshake the controlclient's
	// transport performs — no Authorization header needed.

	resp, err := cfg.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control returned %d", resp.StatusCode)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, err
	}

	var hs hostStateResp
	if err := json.Unmarshal(buf.Bytes(), &hs); err != nil {
		return nil, fmt.Errorf("decode host-state: %w", err)
	}
	if hs.Status != "success" {
		return nil, fmt.Errorf("host-state status=%q", hs.Status)
	}
	return hs.Data.Members, nil
}
