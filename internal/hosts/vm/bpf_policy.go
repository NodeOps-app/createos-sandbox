package vm

// bpf_policy.go — userspace loader and veth/WireGuard attacher for the
// overlay policy BPF programs (policy.bpf.c).
//
// Compute hosts share one process-wide collection of three TC programs:
//   fc_veth_policy   — INGRESS on each VM host-veth (VM→host direction)
//   fc_veth_deliver  — EGRESS on each VM host-veth (host→VM direction)
//   fc_wg_ingress    — INGRESS on wg-hosts (decrypted cross-host packets)
//
// The four shared policy maps (fc_iface_pair, fc_vmip_pair, fc_known_vmips,
// fc_iface_to_ip) are pinned by EnsureOverlayMaps. The compute-host loader
// reopens them so its programs and the reconciler use the same kernel state.
// RelayPolicy separately loads fc_wg_ingress for wg-devices with its own
// pinned pair map, isolated from the compute-host maps.
//
// One config map is owned by this file:
//   fc_vm_subnet — {network, mask} populated once at startup, used by the
//                  policy program's is_vm_ip() helper to short-circuit
//                  non-overlay destinations.

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

//go:embed bpf/policy.bpf.o
var policyBPFBytes []byte

// RelayPolicy owns the wg-devices allow-pair map. Its separate pin directory
// prevents relay reconciliation from deleting compute-host permissions.
type RelayPolicy struct {
	collection *ebpf.Collection
	pairs      *ebpf.Map
}

// AttachRelayPolicy installs the existing WG ingress filter with a dedicated
// relay map. The caller must remove old device peers before attaching it.
func AttachRelayPolicy(ifaceName string) (*RelayPolicy, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(policyBPFBytes))
	if err != nil {
		return nil, fmt.Errorf("load relay BPF: %w", err)
	}
	// This ingress program uses only the pair map; it needs neither the
	// compute-host known-IP map nor the veth policy programs.
	pairSpec := spec.Maps[BPFMapVMIPPair]
	programSpec := spec.Programs[BPFProgWGIngress]
	if pairSpec == nil || programSpec == nil {
		return nil, errors.New("relay BPF program or pair map missing")
	}
	pairSpec.Pinning = ebpf.PinByName
	spec.Maps = map[string]*ebpf.MapSpec{BPFMapVMIPPair: pairSpec}
	spec.Programs = map[string]*ebpf.ProgramSpec{BPFProgWGIngress: programSpec}
	pinDir := bpfPinDir + "/relay"
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir relay bpffs: %w", err)
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinDir},
	})
	if err != nil {
		return nil, fmt.Errorf("load relay policy: %w", err)
	}
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		coll.Close()
		return nil, err
	}
	// A clsact filter survives process exit. Unlike an unpinned TCX link,
	// it will not silently disappear while the WireGuard interface remains.
	if _, err := attachViaClsact(iface, coll.Programs[BPFProgWGIngress], "ingress"); err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach relay policy: %w", err)
	}
	return &RelayPolicy{collection: coll, pairs: coll.Maps[BPFMapVMIPPair]}, nil
}

// Close releases process handles. The filter remains until its interface is
// removed, and the pinned map is reconciled again by the next relay process.
func (p *RelayPolicy) Close() { p.collection.Close() }

// Reconcile reads actual kernel entries instead of process-local history.
// A failed deletion remains visible on the next attempt, including after a
// restart. Iteration/deletion failures are returned before granting new access.
func (p *RelayPolicy) Reconcile(desired map[[2]uint32]struct{}) error {
	actual := make(map[[2]uint32]struct{})
	iter := p.pairs.Iterate()
	var key [8]byte
	var value uint8
	for iter.Next(&key, &value) {
		actual[[2]uint32{
			binary.BigEndian.Uint32(key[:4]),
			binary.BigEndian.Uint32(key[4:]),
		}] = struct{}{}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("read relay pairs: %w", err)
	}
	for pair := range actual {
		if _, keep := desired[pair]; keep {
			continue
		}
		key := vmipPairBytes(pair[0], pair[1])
		if err := p.pairs.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete relay pair: %w", err)
		}
	}
	for pair := range desired {
		if _, exists := actual[pair]; exists {
			continue
		}
		key := vmipPairBytes(pair[0], pair[1])
		if err := p.pairs.Put(key, uint8(1)); err != nil {
			return fmt.Errorf("set relay pair: %w", err)
		}
	}
	return nil
}

// vmSubnetValue mirrors the struct vm_subnet in policy.bpf.c.
type vmSubnetValue struct {
	Network uint32 // network order
	Mask    uint32 // network order
}

// policyAttach holds the TC attach handles for one interface.
type policyAttach struct {
	// TCX path (kernel >= 6.6)
	ingressLink link.Link
	egressLink  link.Link
	// Legacy clsact fallback
	ingressFilter *netlink.BpfFilter
	egressFilter  *netlink.BpfFilter
}

func (a *policyAttach) detach() {
	if a == nil {
		return
	}
	if a.ingressLink != nil {
		_ = a.ingressLink.Unpin()
		_ = a.ingressLink.Close()
	}
	if a.egressLink != nil {
		_ = a.egressLink.Unpin()
		_ = a.egressLink.Close()
	}
	if a.ingressFilter != nil {
		_ = netlink.FilterDel(a.ingressFilter)
	}
	if a.egressFilter != nil {
		_ = netlink.FilterDel(a.egressFilter)
	}
}

// bpfPolicy is the process-wide singleton for the overlay policy programs.
type bpfPolicy struct {
	loaded atomic.Bool
	mu     sync.Mutex

	collection *ebpf.Collection

	// Shared maps opened from pinned path (written by reconciler /
	// fast-path). Pair-allow-list model — see bpf_policy_maps.go.
	ifacePair  *ebpf.Map
	vmipPair   *ebpf.Map
	knownVMIPs *ebpf.Map
	ifaceToIP  *ebpf.Map

	// Config map owned by this loader.
	vmSubnet *ebpf.Map // fc_vm_subnet — {network, mask}

	// Programs.
	progVethPolicy  *ebpf.Program // fc_veth_policy
	progVethDeliver *ebpf.Program // fc_veth_deliver
	progWGIngress   *ebpf.Program // fc_wg_ingress

	// Per-veth + per-WG-iface attachments.
	attachMu        sync.Mutex
	vethAttach      map[string]*policyAttach // veth name → attach
	wgIfaceAttaches map[string]*policyAttach // WG iface name → attach (wg-hosts, wg-devices)
}

var globalBPFPolicy = &bpfPolicy{
	vethAttach: make(map[string]*policyAttach),
}

// load lazily loads the policy BPF collection.
// Idempotent — safe to call concurrently; only the first call does work.
func (p *bpfPolicy) load() error {
	if p.loaded.Load() {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.loaded.Load() {
		return nil
	}

	if err := os.MkdirAll(bpfPinDir, 0o755); err != nil {
		return fmt.Errorf("mkdir bpffs pin dir: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(policyBPFBytes))
	if err != nil {
		return fmt.Errorf("load policy BPF collection spec: %w", err)
	}

	// The shared policy maps are already pinned by EnsureOverlayMaps().
	// Tell the loader to reuse them instead of creating new ones.
	for _, name := range []string{
		BPFMapIfacePair,
		BPFMapVMIPPair,
		BPFMapKnownVMIPs,
		BPFMapIfaceToIP,
		BPFMapVMSubnet,
	} {
		if ms, ok := spec.Maps[name]; ok {
			ms.Pinning = ebpf.PinByName
		}
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: bpfPinDir},
	})
	if err != nil {
		return fmt.Errorf("instantiate policy BPF collection: %w", err)
	}

	p.collection = coll
	p.ifacePair = coll.Maps[BPFMapIfacePair]
	p.vmipPair = coll.Maps[BPFMapVMIPPair]
	p.knownVMIPs = coll.Maps[BPFMapKnownVMIPs]
	p.ifaceToIP = coll.Maps[BPFMapIfaceToIP]
	p.vmSubnet = coll.Maps[BPFMapVMSubnet]
	p.progVethPolicy = coll.Programs[BPFProgVethPolicy]
	p.progVethDeliver = coll.Programs[BPFProgVethDeliver]
	p.progWGIngress = coll.Programs[BPFProgWGIngress]

	missing := []string{}
	if p.ifacePair == nil {
		missing = append(missing, BPFMapIfacePair)
	}
	if p.vmipPair == nil {
		missing = append(missing, BPFMapVMIPPair)
	}
	if p.knownVMIPs == nil {
		missing = append(missing, BPFMapKnownVMIPs)
	}
	if p.ifaceToIP == nil {
		missing = append(missing, BPFMapIfaceToIP)
	}
	if p.vmSubnet == nil {
		missing = append(missing, BPFMapVMSubnet)
	}
	if p.progVethPolicy == nil {
		missing = append(missing, BPFProgVethPolicy)
	}
	if p.progVethDeliver == nil {
		missing = append(missing, BPFProgVethDeliver)
	}
	if p.progWGIngress == nil {
		missing = append(missing, BPFProgWGIngress)
	}
	if len(missing) > 0 {
		return fmt.Errorf("policy BPF collection missing: %v", missing)
	}

	if err := pruneDetachedPolicyLinks(); err != nil {
		coll.Close()
		return err
	}
	p.loaded.Store(true)
	log.Infof("[bpf-policy] programs loaded; pin dir=%s", bpfPinDir)
	return nil
}

// LoadBPFPolicy loads the overlay policy BPF programs. Must be called after
// EnsureOverlayMaps() so the shared maps are already pinned.
func LoadBPFPolicy() error {
	return globalBPFPolicy.load()
}

// SetVMSubnet writes the host's VM subnet into fc_vm_subnet[0] so the policy
// program can distinguish overlay-destined from internet-destined traffic.
// subnetCIDR is e.g. "10.0.0.0/22".
func SetVMSubnet(subnetCIDR string) error {
	p := globalBPFPolicy
	if !p.loaded.Load() {
		return errors.New("bpf policy not loaded")
	}
	_, ipNet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return fmt.Errorf("parse subnet %q: %w", subnetCIDR, err)
	}
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("overlay subnet must be IPv4: %s", subnetCIDR)
	}
	rawMask := ipNet.Mask

	// Native-endian: stored bytes match on-wire (network) byte order so the
	// BPF bitwise AND against ip->saddr works without further swapping.
	network := binary.NativeEndian.Uint32(ip4)
	mask := binary.NativeEndian.Uint32(rawMask)

	idx := uint32(0)
	val := vmSubnetValue{Network: network, Mask: mask}
	return p.vmSubnet.Update(&idx, &val, ebpf.UpdateAny)
}

// Pinned links keep isolation attached while the host daemon is stopped.
const policyLinkDir = bpfPinDir + "/policy_links"

// Interface deletion detaches TCX links in the kernel, but leaves their pins.
// Reap only detached links; live links must keep enforcing during startup.
func pruneDetachedPolicyLinks() error {
	entries, err := os.ReadDir(policyLinkDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("list policy links: %w", err)
	}
	for _, entry := range entries {
		l, err := link.LoadPinnedLink(filepath.Join(policyLinkDir, entry.Name()), nil)
		if err != nil {
			return fmt.Errorf("open policy link: %w", err)
		}
		info, err := l.Info()
		if err == nil && info.TCX() != nil && info.TCX().Ifindex == 0 {
			err = l.Unpin()
		}
		l.Close()
		if err != nil {
			return fmt.Errorf("prune policy link: %w", err)
		}
	}
	return nil
}

// attachTCPolicy attaches prog to iface on the given TC direction (ingress/egress).
// Tries TCX first, falls back to clsact. Returns a *policyAttach with the
// appropriate field populated.
func attachTCPolicy(iface netlink.Link, prog *ebpf.Program, direction string) (*policyAttach, error) {
	att := &policyAttach{}
	var attachType ebpf.AttachType
	switch direction {
	case "ingress":
		attachType = ebpf.AttachTCXIngress
	case "egress":
		attachType = ebpf.AttachTCXEgress
	default:
		return nil, fmt.Errorf("invalid direction %q", direction)
	}

	pinPath := filepath.Join(policyLinkDir, iface.Attrs().Name+"_"+direction)
	l, err := link.LoadPinnedLink(pinPath, nil)
	if err == nil {
		info, infoErr := l.Info()
		if infoErr != nil {
			l.Close()
			return nil, infoErr
		}
		tcx := info.TCX()
		if tcx == nil || ebpf.AttachType(tcx.AttachType) != attachType {
			l.Close()
			return nil, fmt.Errorf("unexpected policy link at %s", pinPath)
		}
		if tcx.Ifindex == 0 {
			// The old interface was deleted and its name has been reused.
			err = l.Unpin()
			l.Close()
			if err != nil {
				return nil, err
			}
		} else {
			if tcx.Ifindex != uint32(iface.Attrs().Index) {
				l.Close()
				return nil, fmt.Errorf("policy link interface mismatch at %s", pinPath)
			}
			// BPF_LINK_UPDATE swaps the program without detaching the filter.
			if err := l.Update(prog); err != nil {
				l.Close()
				return nil, fmt.Errorf("update pinned policy: %w", err)
			}
			if direction == "ingress" {
				att.ingressLink = l
			} else {
				att.egressLink = l
			}
			return att, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("open pinned policy: %w", err)
	}

	l, err = link.AttachTCX(link.TCXOptions{
		Interface: iface.Attrs().Index,
		Program:   prog,
		Attach:    attachType,
	})
	if err == nil {
		if err := os.MkdirAll(policyLinkDir, 0o755); err != nil {
			l.Close()
			return nil, err
		}
		if err := l.Pin(pinPath); err != nil {
			l.Close()
			return nil, fmt.Errorf("pin policy link: %w", err)
		}
		log.Infof("[bpf-policy] TCX %s attach ok on ifindex=%d", direction, iface.Attrs().Index)
		if direction == "ingress" {
			att.ingressLink = l
		} else {
			att.egressLink = l
		}
		return att, nil
	}
	log.Warnf("[bpf-policy] TCX %s attach failed on ifindex=%d, falling back to clsact: %v", direction, iface.Attrs().Index, err)

	// Fallback: legacy clsact.
	f, ferr := attachViaClsact(iface, prog, direction)
	if ferr != nil {
		return nil, fmt.Errorf("attach %s (TCX: %v / clsact: %w)", direction, err, ferr)
	}
	if direction == "ingress" {
		att.ingressFilter = f
	} else {
		att.egressFilter = f
	}
	return att, nil
}

// AttachBPFPolicyToVeth attaches fc_veth_policy (INGRESS) and fc_veth_deliver
// (EGRESS) to the given host-veth. Called once per NetPool slot at creation.
// Idempotent: skips work if already attached.
func AttachBPFPolicyToVeth(hostVeth string) error {
	if err := globalBPFPolicy.load(); err != nil {
		return err
	}
	p := globalBPFPolicy

	p.attachMu.Lock()
	if _, exists := p.vethAttach[hostVeth]; exists {
		p.attachMu.Unlock()
		return nil
	}
	p.attachMu.Unlock()

	iface, err := netlink.LinkByName(hostVeth)
	if err != nil {
		return fmt.Errorf("lookup veth %s: %w", hostVeth, err)
	}

	// INGRESS: VM→host — policy check + redirect.
	ingressAtt, err := attachTCPolicy(iface, p.progVethPolicy, "ingress")
	if err != nil {
		return fmt.Errorf("veth policy ingress attach %s: %w", hostVeth, err)
	}

	// EGRESS: host→VM — delivery re-verify.
	egressAtt, err := attachTCPolicy(iface, p.progVethDeliver, "egress")
	if err != nil {
		// Preserve ingress protection if updating egress fails during restart.
		if ingressAtt.ingressLink != nil {
			ingressAtt.ingressLink.Close()
		}
		return fmt.Errorf("veth deliver egress attach %s: %w", hostVeth, err)
	}

	// Merge into one record.
	combined := &policyAttach{
		ingressLink:   ingressAtt.ingressLink,
		ingressFilter: ingressAtt.ingressFilter,
		egressLink:    egressAtt.egressLink,
		egressFilter:  egressAtt.egressFilter,
	}

	p.attachMu.Lock()
	p.vethAttach[hostVeth] = combined
	p.attachMu.Unlock()

	log.Infof("[bpf-policy] attached to veth=%s ifindex=%d", hostVeth, iface.Attrs().Index)
	return nil
}

// DetachBPFPolicyFromVeth removes the policy programs from a veth. Called
// when the NetPool slot is torn down. Idempotent.
func DetachBPFPolicyFromVeth(hostVeth string) {
	p := globalBPFPolicy
	if !p.loaded.Load() {
		return
	}
	p.attachMu.Lock()
	att, ok := p.vethAttach[hostVeth]
	delete(p.vethAttach, hostVeth)
	p.attachMu.Unlock()
	if !ok {
		return
	}
	att.detach()
}

// AttachBPFPolicyToWGIface attaches fc_wg_ingress to the given WG iface
// at INGRESS for compute-host mesh traffic. RelayPolicy separately owns
// the relay device attachment and its map.
// Idempotent per iface.
func AttachBPFPolicyToWGIface(ifaceName string) error {
	if err := globalBPFPolicy.load(); err != nil {
		return err
	}
	p := globalBPFPolicy

	p.attachMu.Lock()
	if _, already := p.wgIfaceAttaches[ifaceName]; already {
		p.attachMu.Unlock()
		return nil
	}
	p.attachMu.Unlock()

	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", ifaceName, err)
	}

	att, err := attachTCPolicy(iface, p.progWGIngress, "ingress")
	if err != nil {
		return fmt.Errorf("wg ingress attach: %w", err)
	}

	p.attachMu.Lock()
	if p.wgIfaceAttaches == nil {
		p.wgIfaceAttaches = make(map[string]*policyAttach)
	}
	p.wgIfaceAttaches[ifaceName] = att
	p.attachMu.Unlock()

	log.Infof("[bpf-policy] fc_wg_ingress attached to %s ifindex=%d", ifaceName, iface.Attrs().Index)
	return nil
}
