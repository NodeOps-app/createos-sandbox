package vm

// bpf_policy_maps.go manages the eBPF maps used by the overlay policy
// programs. The maps are created as pinned hash maps under
// /sys/fs/bpf/createos/ and survive host process restarts. The network
// reconciler and local sandbox lifecycle paths update these maps; the eBPF
// programs (policy.bpf.c) read them.
//
// Pair-allow-list model (option C):
//
//	fc_iface_pair    (ifindex u32, dst_ip u32) (8B) → u8
//	fc_vmip_pair     (src_ip  u32, dst_ip u32) (8B) → u8
//	fc_known_vmips   ip       u32              (4B) → u8
//	fc_iface_to_ip   ifindex  u32              (4B) → u32  (expected src_ip)
//
// One entry per allowed (src, dst) pair. Lookup at packet time is a
// single hash probe; no VNI math in BPF.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const (
	policyMapMaxEntries = 1 << 20 // 1M entries per pair map; ~16 MiB worst-case
	knownVMIPsMax       = 65536
	ifaceToIPMax        = 65536
)

// pairKey is the canonical Go representation of an 8-byte pair-map key.
// Field A is either an ifindex (fc_iface_pair) or a src_ip
// (fc_vmip_pair); field B is always a dst_ip. IPs are stored in
// canonical big-endian-decoded form (the same u32 you get from
// binary.BigEndian.Uint32(ip4)) — ifindices are stored as raw kernel
// values. Encoding into the BPF map's actual bytes depends on which
// half is what: see ifacePairBytes / vmipPairBytes.
type pairKey struct {
	A uint32
	B uint32
}

// overlayMaps is the singleton holder for the policy maps.
type overlayMaps struct {
	mu          sync.Mutex
	reconcileMu sync.Mutex
	once        sync.Once

	ifacePair  *ebpf.Map
	vmipPair   *ebpf.Map
	knownVMIPs *ebpf.Map
	ifaceToIP  *ebpf.Map
}

var globalOverlayMaps = &overlayMaps{}

// EnsureOverlayMaps lazily creates (or re-opens pinned) eBPF maps for
// the overlay policy. Safe to call concurrently; only the first call
// creates.
func EnsureOverlayMaps() error {
	var retErr error
	globalOverlayMaps.once.Do(func() {
		if err := os.MkdirAll(bpfPinDir, 0o755); err != nil {
			retErr = fmt.Errorf("mkdir bpffs: %w", err)
			return
		}
		retErr = globalOverlayMaps.openOrCreate()
	})
	return retErr
}

func (o *overlayMaps) openOrCreate() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	mkPair := func(name string) *ebpf.MapSpec {
		return &ebpf.MapSpec{
			Name:       name,
			Type:       ebpf.Hash,
			KeySize:    8, // pairKey
			ValueSize:  1,
			MaxEntries: policyMapMaxEntries,
			Pinning:    ebpf.PinByName,
		}
	}
	mkSet := func(name string, max uint32) *ebpf.MapSpec {
		return &ebpf.MapSpec{
			Name:       name,
			Type:       ebpf.Hash,
			KeySize:    4,
			ValueSize:  1,
			MaxEntries: max,
			Pinning:    ebpf.PinByName,
		}
	}
	mkU32U32 := func(name string, max uint32) *ebpf.MapSpec {
		return &ebpf.MapSpec{
			Name:       name,
			Type:       ebpf.Hash,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: max,
			Pinning:    ebpf.PinByName,
		}
	}

	open := func(s *ebpf.MapSpec) (*ebpf.Map, error) {
		m, err := ebpf.NewMapWithOptions(s, ebpf.MapOptions{PinPath: bpfPinDir})
		if err != nil {
			return nil, fmt.Errorf("create/open map %s: %w", s.Name, err)
		}
		return m, nil
	}

	var err error
	if o.ifacePair, err = open(mkPair(BPFMapIfacePair)); err != nil {
		return err
	}
	if o.vmipPair, err = open(mkPair(BPFMapVMIPPair)); err != nil {
		return err
	}
	if o.knownVMIPs, err = open(mkSet(BPFMapKnownVMIPs, knownVMIPsMax)); err != nil {
		return err
	}
	if o.ifaceToIP, err = open(mkU32U32(BPFMapIfaceToIP, ifaceToIPMax)); err != nil {
		return err
	}

	log.Infof("[bpf-policy] overlay maps open/created in %s (pair-allow-list model)", bpfPinDir)
	return nil
}

// ipKey returns the 4-byte network-order key for an IPv4 string. BPF
// reads packet headers in network order, so map keys are stored the
// same way.
func ipKey(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP %q", ipStr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("not IPv4: %q", ipStr)
	}
	return binary.BigEndian.Uint32(ip4), nil
}

// ifacePairBytes encodes (ifindex, dst_ip) for fc_iface_pair.
//
// BPF reads ifindex as a native u32 (skb->ifindex), and dst_ip as
// network-byte-order bytes copied from the packet's iphdr.daddr. The
// two halves of the struct in BPF therefore live in memory as
// [ifindex_native | ip_bytes_network] — exactly what this function
// emits.
func ifacePairBytes(ifindex, dstIPNet uint32) [8]byte {
	var b [8]byte
	binary.NativeEndian.PutUint32(b[0:4], ifindex)
	binary.BigEndian.PutUint32(b[4:8], dstIPNet)
	return b
}

// vmipPairBytes encodes (src_ip, dst_ip) for fc_vmip_pair. Both halves
// are IP addresses in network byte order.
func vmipPairBytes(srcIPNet, dstIPNet uint32) [8]byte {
	var b [8]byte
	binary.BigEndian.PutUint32(b[0:4], srcIPNet)
	binary.BigEndian.PutUint32(b[4:8], dstIPNet)
	return b
}

// uint32Key returns the 4-byte native-endian key for a u32 (used for
// ifindex, which BPF stores in native byte order).
func uint32Key(v uint32) [4]byte {
	var k [4]byte
	binary.NativeEndian.PutUint32(k[:], v)
	return k
}

// SetIfacePair adds (ifindex, dstIP) → 1 in fc_iface_pair.
func SetIfacePair(ifindex uint32, dstIPNet uint32) error {
	o := globalOverlayMaps
	if o.ifacePair == nil {
		return nil
	}
	k := ifacePairBytes(ifindex, dstIPNet)
	one := uint8(1)
	return o.ifacePair.Put(k, one)
}

// DeleteIfacePair removes (ifindex, dstIP) from fc_iface_pair.
func DeleteIfacePair(ifindex uint32, dstIPNet uint32) error {
	o := globalOverlayMaps
	if o.ifacePair == nil {
		return nil
	}
	k := ifacePairBytes(ifindex, dstIPNet)
	err := o.ifacePair.Delete(k)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// SetVMIPPair adds (srcIP, dstIP) → 1 in fc_vmip_pair.
func SetVMIPPair(srcIPNet, dstIPNet uint32) error {
	o := globalOverlayMaps
	if o.vmipPair == nil {
		return nil
	}
	k := vmipPairBytes(srcIPNet, dstIPNet)
	one := uint8(1)
	return o.vmipPair.Put(k, one)
}

// DeleteVMIPPair removes (srcIP, dstIP) from fc_vmip_pair.
func DeleteVMIPPair(srcIPNet, dstIPNet uint32) error {
	o := globalOverlayMaps
	if o.vmipPair == nil {
		return nil
	}
	k := vmipPairBytes(srcIPNet, dstIPNet)
	err := o.vmipPair.Delete(k)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// SetKnownVMIP marks ip as a managed VM IP (fc_known_vmips).
func SetKnownVMIP(ipNet uint32) error {
	o := globalOverlayMaps
	if o.knownVMIPs == nil {
		return nil
	}
	k := uint32KeyBE(ipNet)
	one := uint8(1)
	return o.knownVMIPs.Put(k, one)
}

// DeleteKnownVMIP removes ip from fc_known_vmips.
func DeleteKnownVMIP(ipNet uint32) error {
	o := globalOverlayMaps
	if o.knownVMIPs == nil {
		return nil
	}
	k := uint32KeyBE(ipNet)
	err := o.knownVMIPs.Delete(k)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// SetIfaceToIP records the expected src IP for a local veth ifindex
// (anti-spoof bind). Reconciler keeps this in sync with the
// IPAM-assigned VM IP.
func SetIfaceToIP(ifindex uint32, expectedSrcIPNet uint32) error {
	o := globalOverlayMaps
	if o.ifaceToIP == nil {
		return nil
	}
	k := uint32Key(ifindex)
	v := uint32KeyBE(expectedSrcIPNet) // store IP in network byte order to match packet view
	return o.ifaceToIP.Put(k, v)
}

// DeleteIfaceToIP removes the ifindex→ip mapping.
func DeleteIfaceToIP(ifindex uint32) error {
	o := globalOverlayMaps
	if o.ifaceToIP == nil {
		return nil
	}
	k := uint32Key(ifindex)
	err := o.ifaceToIP.Delete(k)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// uint32KeyBE writes a u32 in big-endian (network order). Used for IP
// values so the BPF program — which reads IP addresses straight off the
// packet — sees the same bytes.
func uint32KeyBE(v uint32) [4]byte {
	var k [4]byte
	binary.BigEndian.PutUint32(k[:], v)
	return k
}

// iterU32Set returns every present key in a HASH map with u32 keys and
// u8 values. Used to snapshot fc_known_vmips for diff. The returned map
// holds the IP in network byte order (matches BPF view).
func iterU32Set(m *ebpf.Map) map[uint32]struct{} {
	out := map[uint32]struct{}{}
	if m == nil {
		return out
	}
	iter := m.Iterate()
	var k [4]byte
	var v uint8
	for iter.Next(&k, &v) {
		out[binary.BigEndian.Uint32(k[:])] = struct{}{}
	}
	return out
}

// iterU32U32 returns every (k, v) in a HASH map with u32 keys and u32
// values. Used to snapshot fc_iface_to_ip for diff.
func iterU32U32(m *ebpf.Map) map[uint32]uint32 {
	out := map[uint32]uint32{}
	if m == nil {
		return out
	}
	iter := m.Iterate()
	var k [4]byte
	var v [4]byte
	for iter.Next(&k, &v) {
		// Key is ifindex (native), value is IP (big-endian).
		key := binary.NativeEndian.Uint32(k[:])
		val := binary.BigEndian.Uint32(v[:])
		out[key] = val
	}
	return out
}

// iterIfacePairSet snapshots fc_iface_pair. Key layout: native ifindex
// followed by network-byte-order dst_ip.
func iterIfacePairSet(m *ebpf.Map) map[pairKey]struct{} {
	out := map[pairKey]struct{}{}
	if m == nil {
		return out
	}
	iter := m.Iterate()
	var k [8]byte
	var v uint8
	for iter.Next(&k, &v) {
		out[pairKey{
			A: binary.NativeEndian.Uint32(k[0:4]),
			B: binary.BigEndian.Uint32(k[4:8]),
		}] = struct{}{}
	}
	return out
}

// iterVMIPPairSet snapshots fc_vmip_pair. Both halves are
// network-byte-order IPs.
func iterVMIPPairSet(m *ebpf.Map) map[pairKey]struct{} {
	out := map[pairKey]struct{}{}
	if m == nil {
		return out
	}
	iter := m.Iterate()
	var k [8]byte
	var v uint8
	for iter.Next(&k, &v) {
		out[pairKey{
			A: binary.BigEndian.Uint32(k[0:4]),
			B: binary.BigEndian.Uint32(k[4:8]),
		}] = struct{}{}
	}
	return out
}

// DeleteVMIPVnis removes every policy entry that refers to a VM IP.
// Called synchronously from the destroy path before its network slot can
// be reused by another sandbox. Safe to call when maps are not loaded.
func DeleteVMIPVnis(ipStr string) error {
	ipNet, err := ipKey(ipStr)
	if err != nil {
		return err
	}
	o := globalOverlayMaps
	if o.knownVMIPs == nil {
		return nil
	}

	// Exclude a reconciliation whose control-plane read predates destroy;
	// otherwise it could reinsert the entries immediately after this delete.
	o.reconcileMu.Lock()
	defer o.reconcileMu.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()

	var errs []error
	for k := range iterVMIPPairSet(o.vmipPair) {
		if k.A != ipNet && k.B != ipNet {
			continue
		}
		if err := DeleteVMIPPair(k.A, k.B); err != nil {
			errs = append(errs, fmt.Errorf("delete vmip pair (%s,%s): %w",
				ipString(k.A), ipString(k.B), err))
		}
	}
	if err := DeleteKnownVMIP(ipNet); err != nil {
		errs = append(errs, fmt.Errorf("delete known VM IP %s: %w", ipStr, err))
	}
	return errors.Join(errs...)
}

// DeleteIfaceVnis removes every source-side policy entry for an interface.
// NetPool.Return calls it before making a permanent slot available to a new
// sandbox, so the new occupant cannot inherit the previous occupant's pairs.
func DeleteIfaceVnis(ifindex uint32) error {
	o := globalOverlayMaps
	if o.ifaceToIP == nil {
		return nil
	}

	o.reconcileMu.Lock()
	defer o.reconcileMu.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()

	var errs []error
	for k := range iterIfacePairSet(o.ifacePair) {
		if k.A != ifindex {
			continue
		}
		if err := DeleteIfacePair(k.A, k.B); err != nil {
			errs = append(errs, fmt.Errorf("delete iface pair (%d,%s): %w",
				k.A, ipString(k.B), err))
		}
	}
	if err := DeleteIfaceToIP(ifindex); err != nil {
		errs = append(errs, fmt.Errorf("delete iface-to-IP %d: %w", ifindex, err))
	}
	return errors.Join(errs...)
}

// BindVMIPToIface installs the per-VM policy identity that must exist before
// a borrowed slot starts carrying guest traffic. Return removes this binding
// before cross-tenant reuse; waiting for the periodic reconciler to restore it
// leaves a several-second window where the new VM is running but its packets
// fail the anti-spoof check.
func BindVMIPToIface(hostVeth, ipStr string) error {
	ipNet, err := ipKey(ipStr)
	if err != nil {
		return err
	}
	link, err := netlink.LinkByName(hostVeth)
	if err != nil {
		return fmt.Errorf("lookup veth %s: %w", hostVeth, err)
	}
	ifindex := uint32(link.Attrs().Index)
	if ifindex == 0 {
		return fmt.Errorf("veth %s has zero ifindex", hostVeth)
	}

	o := globalOverlayMaps
	o.reconcileMu.Lock()
	defer o.reconcileMu.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()

	if err := SetKnownVMIP(ipNet); err != nil {
		return fmt.Errorf("set known VM IP %s: %w", ipStr, err)
	}
	if err := SetIfaceToIP(ifindex, ipNet); err != nil {
		_ = DeleteKnownVMIP(ipNet)
		return fmt.Errorf("set iface-to-IP veth=%s ifindex=%d ip=%s: %w",
			hostVeth, ifindex, ipStr, err)
	}
	return nil
}
