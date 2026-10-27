package vm

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

//go:embed bpf/meter.bpf.o
var meterBPFBytes []byte

// bpfMeter is a process-wide singleton holding the loaded BPF programs +
// shared maps. Programs are loaded once at first use, attached per veth
// for each VM. Shared maps means one verifier pass for all sandboxes.
type bpfMeter struct {
	loaded atomic.Bool
	mu     sync.Mutex

	collection *ebpf.Collection

	// Maps (pinned to /sys/fs/bpf/createos/ for restart survivability).
	ifaceToSID   *ebpf.Map // ifindex → sandbox key
	egressBytes  *ebpf.Map // sandbox key → per-CPU bytes
	ingressBytes *ebpf.Map // sandbox key → per-CPU bytes
	capFlags     *ebpf.Map // sandbox key → 0/1
	sidToGw      *ebpf.Map // sandbox key → host-veth gateway IPv4 (BE)
	hostIPs      *ebpf.Map // index → host IPv4 (BE) — allowed control-path dsts

	progEgress  *ebpf.Program
	progIngress *ebpf.Program

	// Per-veth attachments — kept so we can detach on Destroy.
	attachMu    sync.Mutex
	attachments map[string]*meterAttach // veth name → attachment
}

type meterAttach struct {
	ifindex    uint32
	sandboxID  string
	sandboxKey uint32
	// Either egressLink/ingressLink (TCX path) or egressFilter/ingressFilter
	// (legacy clsact path) is populated; the other set is nil. Detach
	// uses whichever is present.
	egressLink    link.Link
	ingressLink   link.Link
	egressFilter  *netlink.BpfFilter
	ingressFilter *netlink.BpfFilter
}

// bpfPinDir is the on-disk path where every BPF map and program we own
// is pinned. Defined as a single constant in naming.go (BPFPinDir);
// aliased here so existing local references compile.
const bpfPinDir = BPFPinDir

var globalBPFMeter = &bpfMeter{
	attachments: make(map[string]*meterAttach),
}

// sandboxKeyFor hashes a sandbox id to a uint32 used as the BPF map key.
// Must be deterministic — same sandbox always hashes to the same key
// across attach/detach so counters carry across operations.
func sandboxKeyFor(id string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return h.Sum32()
}

// load lazily loads the BPF program collection and pins shared maps.
// Idempotent — safe to call concurrently from multiple Manager.Create
// goroutines; only the first call does work.
func (m *bpfMeter) load() error {
	if m.loaded.Load() {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loaded.Load() {
		return nil
	}

	if err := os.MkdirAll(bpfPinDir, 0o755); err != nil {
		return fmt.Errorf("mkdir bpffs pin dir: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(meterBPFBytes))
	if err != nil {
		return fmt.Errorf("load BPF collection spec: %w", err)
	}
	// Pin every map by name so they survive serve restart.
	for name, mspec := range spec.Maps {
		mspec.Pinning = ebpf.PinByName
		_ = name
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: bpfPinDir},
	})
	if err != nil {
		return fmt.Errorf("instantiate BPF collection: %w", err)
	}

	m.collection = coll
	m.ifaceToSID = coll.Maps[BPFMapIfaceToSID]
	m.egressBytes = coll.Maps[BPFMapEgressBytes]
	m.ingressBytes = coll.Maps[BPFMapIngressBytes]
	m.capFlags = coll.Maps[BPFMapCapFlags]
	m.sidToGw = coll.Maps[BPFMapSIDToGw]
	m.hostIPs = coll.Maps[BPFMapHostIPs]
	m.progEgress = coll.Programs[BPFProgMeterEgress]
	m.progIngress = coll.Programs[BPFProgMeterIngress]

	if m.ifaceToSID == nil || m.egressBytes == nil || m.ingressBytes == nil ||
		m.capFlags == nil || m.sidToGw == nil || m.hostIPs == nil ||
		m.progEgress == nil || m.progIngress == nil {
		return errors.New("BPF collection missing required maps/progs")
	}

	// Populate fc_host_ips with every IPv4 the host actually binds on
	// (eth0, internal interfaces…). The BPF cap exemption needs these
	// so the agent's replies — destined to whichever host IP issued
	// the request — make it through the drop when a VM is capped.
	// Failure here is non-fatal: the cap still works, but PTY / exec
	// from non-veth-gateway sources will hang while the VM is capped.
	if err := m.populateHostIPs(); err != nil {
		log.Warnf("[bpf-meter] populate fc_host_ips: %v — agent reply path may break while capped", err)
	}

	m.loaded.Store(true)
	log.Infof("[bpf-meter] loaded; pin dir=%s", bpfPinDir)
	return nil
}

// populateHostIPs walks the host's network interfaces and writes the
// first few non-loopback IPv4 addresses into the fc_host_ips array map.
// These are the IPs the agent's replies legitimately end up destined
// for — the BPF cap-exemption check allows them through. Skips
// loopback (127.0.0.0/8) and the per-VM veth /31s (those are owned by
// the sidToGw map already).
func (m *bpfMeter) populateHostIPs() error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list links: %w", err)
	}
	var ips []uint32
	seen := make(map[uint32]struct{})
	for _, l := range links {
		name := l.Attrs().Name
		// Skip loopback and the fcp* veths the slot pool owns. Everything
		// else is fair game (eth0, wg-hosts, tailscale0, podman bridges…).
		if name == "lo" || strings.HasPrefix(name, "fcp") {
			continue
		}
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip4 := a.IP.To4()
			if ip4 == nil {
				continue
			}
			be := binary.LittleEndian.Uint32(ip4)
			if _, ok := seen[be]; ok {
				continue
			}
			seen[be] = struct{}{}
			ips = append(ips, be)
			if len(ips) >= 4 {
				break
			}
		}
		if len(ips) >= 4 {
			break
		}
	}
	for i := uint32(0); i < 4; i++ {
		var val uint32
		if int(i) < len(ips) {
			val = ips[i]
		}
		if err := m.hostIPs.Update(&i, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update host_ips[%d]: %w", i, err)
		}
	}
	log.Infof("[bpf-meter] registered %d host IP(s) for cap-exempt control path", len(ips))
	return nil
}

// AttachBPFMeterToVeth performs the heavy work — loading + verifying the
// BPF programs (one-time, lazy) and TCX-attaching them to the host veth.
// This is the rtnl_mutex-serialised step that hurts under burst, so we
// call it ONCE per NetPool slot at slot creation, not per VM. Slots are
// permanent; programs stay attached for the slot's lifetime.
//
// Idempotent: returns nil and skips work if veth is already attached.
func AttachBPFMeterToVeth(hostVeth string) error {
	if err := globalBPFMeter.load(); err != nil {
		return err
	}
	m := globalBPFMeter

	m.attachMu.Lock()
	if _, exists := m.attachments[hostVeth]; exists {
		m.attachMu.Unlock()
		return nil
	}
	m.attachMu.Unlock()

	link0, err := netlink.LinkByName(hostVeth)
	if err != nil {
		return fmt.Errorf("lookup veth %s: %w", hostVeth, err)
	}
	ifindex := uint32(link0.Attrs().Index)

	att := &meterAttach{ifindex: ifindex}

	egressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: link0.Attrs().Index,
		Program:   m.progEgress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err == nil {
		att.egressLink = egressLink
	} else {
		egressFilter, ferr := attachViaClsact(link0, m.progEgress, "ingress")
		if ferr != nil {
			return fmt.Errorf("attach egress (TCX: %v / clsact: %w)", err, ferr)
		}
		att.egressFilter = egressFilter
	}

	ingressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: link0.Attrs().Index,
		Program:   m.progIngress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err == nil {
		att.ingressLink = ingressLink
	} else {
		ingressFilter, ferr := attachViaClsact(link0, m.progIngress, "egress")
		if ferr != nil {
			detachAttachment(att)
			return fmt.Errorf("attach ingress (TCX: %v / clsact: %w)", err, ferr)
		}
		att.ingressFilter = ingressFilter
	}

	m.attachMu.Lock()
	m.attachments[hostVeth] = att
	m.attachMu.Unlock()

	log.Infof("[bpf-meter] attached to slot veth=%s ifindex=%d", hostVeth, ifindex)
	return nil
}

// DetachBPFMeterFromVeth tears down the per-veth attachment. Called when
// the NetPool slot is destroyed (Pool.Discard or Pool.Close). Idempotent.
func DetachBPFMeterFromVeth(hostVeth string) {
	m := globalBPFMeter
	if !m.loaded.Load() {
		return
	}
	m.attachMu.Lock()
	att, ok := m.attachments[hostVeth]
	delete(m.attachments, hostVeth)
	m.attachMu.Unlock()
	if !ok {
		return
	}
	detachAttachment(att)
}

// AttachBPFMeter is the per-VM hot-path: registers the sandbox→veth
// binding in the lockless ifindex map. The TCX program is already
// attached to this slot's veth from when the slot was created. So this
// is just a single map update — no rtnl_mutex, no verifier pass.
func AttachBPFMeter(sandboxID, hostVeth string) error {
	if err := globalBPFMeter.load(); err != nil {
		return err
	}
	m := globalBPFMeter

	link0, err := netlink.LinkByName(hostVeth)
	if err != nil {
		return fmt.Errorf("lookup veth %s: %w", hostVeth, err)
	}
	ifindex := uint32(link0.Attrs().Index)
	sandboxKey := sandboxKeyFor(sandboxID)

	// Tolerate slots that were created before the BPF mode was enabled
	// (e.g. operator flipped --bpf-meter on for a running serve): attach
	// on demand. After this, the slot stays attached and subsequent
	// borrowers skip this work.
	m.attachMu.Lock()
	_, attached := m.attachments[hostVeth]
	m.attachMu.Unlock()
	if !attached {
		if err := AttachBPFMeterToVeth(hostVeth); err != nil {
			return fmt.Errorf("lazy slot attach: %w", err)
		}
	}

	// Register ifindex → sandbox key. Lockless map.Update — typical
	// sub-microsecond.
	if err := m.ifaceToSID.Update(&ifindex, &sandboxKey, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("ifaceToSID update: %w", err)
	}
	if err := initPerCPUCounter(m.egressBytes, sandboxKey); err != nil {
		log.Warnf("[bpf-meter] init egress counter for %s: %v", sandboxID, err)
	}
	if err := initPerCPUCounter(m.ingressBytes, sandboxKey); err != nil {
		log.Warnf("[bpf-meter] init ingress counter for %s: %v", sandboxID, err)
	}
	// Register host-veth gateway IP (the IPv4 assigned to the host end
	// of the veth pair). Used by the BPF program to anchor the cap
	// exemption: control-path packets are only exempt when their dst
	// IP equals this address, blocking `curl evil.com:1024` bypasses.
	if gwBE, ok := firstHostVethIPv4(link0); ok {
		if err := m.sidToGw.Update(&sandboxKey, &gwBE, ebpf.UpdateAny); err != nil {
			log.Warnf("[bpf-meter] sidToGw update for %s: %v", sandboxID, err)
		}
	} else {
		log.Warnf("[bpf-meter] %s host-veth %s has no IPv4 — cap exemption will fail closed",
			sandboxID, hostVeth)
	}

	// Stash sandbox-side info on the existing slot attachment so detach
	// can clean up correctly.
	m.attachMu.Lock()
	if a, ok := m.attachments[hostVeth]; ok {
		a.sandboxID = sandboxID
		a.sandboxKey = sandboxKey
	}
	m.attachMu.Unlock()

	return nil
}

// DetachBPFMeter is the per-VM unbind: removes the ifindex→sandbox-key
// entry. The slot's TCX program stays attached for the next borrower.
// Detach happens on Manager.Destroy.
func DetachBPFMeter(sandboxID, hostVeth string) {
	m := globalBPFMeter
	if !m.loaded.Load() {
		return
	}
	m.attachMu.Lock()
	att := m.attachments[hostVeth]
	if att != nil {
		// Clear the per-VM fields but keep the slot attachment record.
		att.sandboxID = ""
		att.sandboxKey = 0
	}
	m.attachMu.Unlock()
	if att == nil {
		return
	}
	_ = m.ifaceToSID.Delete(&att.ifindex)
}

// ResetBPFMeter zeros the egress/ingress counters and clears the cap flag
// for a sandbox. Used on Destroy after the final byte counts have been
// persisted to Postgres so the maps don't grow unbounded.
// firstHostVethIPv4 returns the host-side IPv4 of a veth packed so that
// it byte-equals `iphdr.daddr` as the BPF program reads it. On little-
// endian CPUs the kernel reads `__be32 daddr` as a host-endian u32 with
// the LSB being the first wire byte (e.g. 10.0.0.1 = 0x0100000A). We
// produce the same shape via binary.LittleEndian.Uint32 of the 4-byte
// IP. fails the BPF exemption closed when the veth has no IPv4
// assigned: the cap will drop everything until the IP shows up.
func firstHostVethIPv4(l netlink.Link) (uint32, bool) {
	addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
	if err != nil {
		return 0, false
	}
	for _, a := range addrs {
		ip4 := a.IP.To4()
		if ip4 == nil {
			continue
		}
		return binary.LittleEndian.Uint32(ip4), true
	}
	return 0, false
}

func ResetBPFMeter(sandboxID string) {
	m := globalBPFMeter
	if !m.loaded.Load() {
		return
	}
	key := sandboxKeyFor(sandboxID)
	_ = m.egressBytes.Delete(&key)
	_ = m.ingressBytes.Delete(&key)
	_ = m.capFlags.Delete(&key)
	_ = m.sidToGw.Delete(&key)
}

// ReadBPFMeter returns the cumulative bytes for a sandbox across all CPUs.
func ReadBPFMeter(sandboxID string) (egressBytes, ingressBytes uint64, ok bool) {
	m := globalBPFMeter
	if !m.loaded.Load() {
		return 0, 0, false
	}
	key := sandboxKeyFor(sandboxID)
	egressBytes = sumPerCPU(m.egressBytes, key)
	ingressBytes = sumPerCPU(m.ingressBytes, key)
	return egressBytes, ingressBytes, true
}

// SetBPFMeterCap toggles the per-sandbox drop flag. capped=true installs
// the DROP; capped=false removes it (e.g. after a recharge).
func SetBPFMeterCap(sandboxID string, capped bool) error {
	m := globalBPFMeter
	if !m.loaded.Load() {
		return errors.New("bpf meter not loaded")
	}
	key := sandboxKeyFor(sandboxID)
	var v uint32
	if capped {
		v = 1
	}
	return m.capFlags.Update(&key, &v, ebpf.UpdateAny)
}

func initPerCPUCounter(mp *ebpf.Map, key uint32) error {
	cpus, err := numCPUs()
	if err != nil {
		return err
	}
	zeros := make([]uint64, cpus)
	return mp.Update(&key, zeros, ebpf.UpdateAny)
}

func sumPerCPU(mp *ebpf.Map, key uint32) uint64 {
	var values []uint64
	if err := mp.Lookup(&key, &values); err != nil {
		return 0
	}
	var total uint64
	for _, v := range values {
		total += v
	}
	return total
}

func numCPUs() (int, error) {
	// /sys/devices/system/cpu/possible — same source kernel uses for
	// percpu map sizing. Fallback: runtime.NumCPU.
	b, err := os.ReadFile("/sys/devices/system/cpu/possible")
	if err == nil {
		var lo, hi int
		_, err := fmt.Sscanf(string(b), "%d-%d", &lo, &hi)
		if err == nil {
			return hi + 1, nil
		}
	}
	return 1, nil
}

// detachAttachment closes whichever attachment artifacts are populated
// (TCX link or legacy clsact filter). Safe to call on partially-attached
// state during error rollback.
func detachAttachment(att *meterAttach) {
	if att == nil {
		return
	}
	if att.egressLink != nil {
		_ = att.egressLink.Close()
	}
	if att.ingressLink != nil {
		_ = att.ingressLink.Close()
	}
	if att.egressFilter != nil {
		_ = netlink.FilterDel(att.egressFilter)
	}
	if att.ingressFilter != nil {
		_ = netlink.FilterDel(att.ingressFilter)
	}
}

// attachViaClsact is a legacy-kernel fallback for hosts without TCX
// (kernel < 6.6). Adds a clsact qdisc + classifier filter pointing at
// the BPF program. Slower than TCX but functionally equivalent.
func attachViaClsact(veth netlink.Link, prog *ebpf.Program, parent string) (*netlink.BpfFilter, error) {
	// Ensure clsact qdisc exists. Idempotent: ignore exist errors.
	q := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: veth.Attrs().Index,
			Parent:    netlink.HANDLE_CLSACT,
			Handle:    netlink.MakeHandle(0xffff, 0),
		},
		QdiscType: "clsact",
	}
	_ = netlink.QdiscAdd(q)

	var parentHandle uint32
	switch parent {
	case "ingress":
		parentHandle = netlink.HANDLE_MIN_INGRESS
	case "egress":
		parentHandle = netlink.HANDLE_MIN_EGRESS
	default:
		return nil, fmt.Errorf("invalid parent %q", parent)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: veth.Attrs().Index,
			Parent:    parentHandle,
			Handle:    1,
			Protocol:  3, // ETH_P_ALL
		},
		Fd:           prog.FD(),
		Name:         "fc_meter",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return nil, fmt.Errorf("add bpf filter: %w", err)
	}
	return filter, nil
}

// PinPath returns the bpffs directory used for shared map pinning.
// Exported for ops/debugging tools (e.g. `bpftool map dump pinned`).
func BPFMeterPinDir() string {
	return filepath.Clean(bpfPinDir)
}

// installMeterFor + readMeterFor / readIngressMeterFor +
// installCapFor are the shims used by Manager. BPF/TCX is the only path —
// the iptables fallback was removed (bpffs is now a hard requirement).

func (m *Manager) installMeterFor(id, veth string) error {
	return AttachBPFMeter(id, veth)
}

func (m *Manager) readMeterBytesFor(id string) (uint64, error) {
	eg, _, ok := ReadBPFMeter(id)
	if !ok {
		return 0, errors.New("bpf meter not loaded")
	}
	return eg, nil
}

func (m *Manager) readIngressMeterBytesFor(id string) (uint64, error) {
	_, in, ok := ReadBPFMeter(id)
	if !ok {
		return 0, errors.New("bpf meter not loaded")
	}
	return in, nil
}

func (m *Manager) installCapFor(id string) error {
	return SetBPFMeterCap(id, true)
}

func (m *Manager) removeCapFor(id string) {
	_ = SetBPFMeterCap(id, false)
}
