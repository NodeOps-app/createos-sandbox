package vm

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// PooledNet is one pre-built network slot ready for a Firecracker VM.
type PooledNet struct {
	NetNSPath   string
	TapName     string
	MAC         string
	IP          net.IPNet // VM's /31
	Gateway     net.IP    // unique per-VM gateway IP (other half of the /31)
	DNS         []string
	VMIfName    string
	ContainerID string
	// VsockCID is the guest CID assigned to this slot. Vsock CIDs are
	// per-host namespace; we derive it deterministically from the slot
	// counter (CID 0-2 are reserved, HOST=2). The CID stays with the
	// slot across VM lifetimes — when the slot is reused, the same CID
	// gets the new VM's vsock device.
	VsockCID uint32
	pair     IPPair
	ipam     *StaticIPAM

	// permanent is true for slots the NetPool owns and rotates between
	// VMs (Return re-queues them). False for slots reconstructed from DB
	// by rehydrate — those came from a prior serve's pool and don't fit
	// our current pool's lifecycle, so Return tears them down instead.
	permanent bool
}

// NetPool holds a buffered channel of pre-built networks. It uses an
// in-process StaticIPAM and direct netlink calls (no CNI plugins).
type NetPool struct {
	ready        chan *PooledNet
	replacements chan struct{}
	ipam         *StaticIPAM
	mu           sync.Mutex
	counter      int
	closed       chan struct{}
	// owned tracks every slot containerID this pool currently owns —
	// both slots in the `ready` channel and slots lent out to running
	// VMs. createOne adds, cleanup removes. Used by reconcile sweeps
	// to distinguish legitimate slots from leaked netns.
	owned map[string]struct{}
	// quarantined holds IP pairs whose veth teardown failed. The pair stays
	// out of IPAM until ReapOrphans confirms that the stale interface and
	// netns marker are gone, preventing both cross-tenant reuse and a
	// process-lifetime capacity leak.
	quarantined map[string]quarantinedSlot
	// firecrackerUIDBase, when > 0, makes createOne stamp each slot's
	// tap device with `Owner = base + (cid - 100)` so firecracker
	// (running post-drop as that uid) can attach to it without
	// CAP_NET_ADMIN. 0 keeps today's root-owned-tap behaviour.
	firecrackerUIDBase int
	// kvmGID is set alongside Owner on each slot's tap. The kernel's
	// tun_not_capable() check requires the caller to be in the tap's
	// group (or have CAP_NET_ADMIN) even when the owner uid matches —
	// otherwise an unset/0 group means "must be root group" → EPERM
	// on TUNSETIFF. Setting Group=kvmGID matches the supplementary
	// group firecracker is launched with.
	kvmGID uint32
}

type quarantinedSlot struct {
	pair      IPPair
	sandboxID string // non-empty when sandbox-specific iptables teardown failed
}

// NewNetPool builds and starts the pool. Subnet must be IPv4 in CIDR form
// (e.g. "192.168.127.0/24"); gateway is the address the host owns inside it.
// reservedVMIPs are pulled out of the IPAM before the pool starts handing
// pairs out — used at startup to quarantine the IPs of any orphan VMs that
// survived a previous serve crash. liveContainerIDs are fcpN names
// that belong to currently-rehydrated sandboxes — their netns/veth must
// NOT be torn down.
func NewNetPool(size int, subnet, gateway string, reservedVMIPs []string, liveContainerIDs []string, firecrackerUIDBase int, kvmGID uint32) (*NetPool, error) {
	ipam, err := NewStaticIPAM(subnet, gateway, reservedVMIPs)
	if err != nil {
		return nil, err
	}
	// Counter must skip past any existing fcp* netns left behind by orphan
	// VMs. Otherwise a fresh slot would pick the same N and collide with
	// the orphan's netns and host-side veth (both named fcp<N>).
	startCounter := highestExistingPoolN()
	if err := EnsureDirectNetMasquerade(subnet); err != nil {
		return nil, fmt.Errorf("masquerade: %w", err)
	}
	if err := EnsureInterVMIsolation(subnet); err != nil {
		return nil, fmt.Errorf("vm isolation: %w", err)
	}

	// Adopt clean idle slots and tear down every other orphan netns from prior
	// serve runs. A durable marker is published only after Return has removed
	// all borrower-specific policy and is removed before Get hands the slot to
	// a VM. This lets clean slots survive restarts without ever guessing that
	// an unmarked kernel object is safe for cross-tenant reuse.
	existingNetns := readExistingNetns()
	removeStaleNetSlotMarkers(existingNetns)
	var adopted []*PooledNet
	// Tear down orphan netns from prior serve runs. Without this, old slots
	// accumulate across restarts: they still occupy /31 IPs, host-side
	// veths, and iptables/neigh state, but the new NetPool has no handle
	// on them and builds fresh slots alongside. The pollution makes fresh
	// slots' first SYN drop (host ARP conflicts, leaked MASQUERADE, etc).
	// Skip any ID that's in liveContainerIDs — those belong to rehydrated
	// sandboxes whose netns is in active use.
	live := make(map[string]struct{}, len(liveContainerIDs))
	for _, id := range liveContainerIDs {
		live[id] = struct{}{}
	}
	reaped := 0
	for ns := range existingNetns {
		if parsePoolN(ns) == 0 {
			continue // not one of ours
		}
		if _, keep := live[ns]; keep {
			// A clean marker beside a live VM can only be stale (for example,
			// a crash between claim and filesystem journal flush). Never let a
			// later restart reinterpret it as idle.
			_ = claimPersistedNetSlot(ns)
			continue
		}
		if state, markerErr := loadPersistedNetSlot(ns); markerErr == nil {
			pn, validateErr := validatePersistedNetSlot(state)
			if validateErr == nil && ipam.Reserve(pn.pair) {
				pn.ipam = ipam
				adopted = append(adopted, pn)
				continue
			}
			if validateErr != nil {
				log.Warnf("[netpool] refusing persisted slot=%s: %v; rebuilding", ns, validateErr)
			} else {
				log.Warnf("[netpool] refusing persisted slot=%s: IP pair unavailable; rebuilding", ns)
			}
			_ = claimPersistedNetSlot(ns)
		} else if !os.IsNotExist(markerErr) {
			log.Warnf("[netpool] invalid persisted slot=%s: %v; rebuilding", ns, markerErr)
			_ = claimPersistedNetSlot(ns)
		}
		if err := reapOrphanSlot(ns); err != nil {
			// A stale veth can collide with a fresh slot name or retain an
			// old route. Refuse to create the pool until cleanup succeeds;
			// proceeding would turn a resource-cleanup failure into a tenant
			// isolation risk.
			return nil, fmt.Errorf("reap orphan slot %s: %w", ns, err)
		}
		reaped++
	}
	if reaped > 0 {
		log.Infof("[netpool] reaped %d orphan netns from prior serve runs", reaped)
	}

	// Restore meter attachments and reopen/update pinned policy links for
	// rehydrated slots. Policy links survive daemon exit, so isolation stays
	// enforced while startup rebuilds process-local handles. New slots below
	// receive their attachments in createOne.
	for _, id := range liveContainerIDs {
		hostVeth := vethNameFor(id)
		if err := AttachBPFMeterToVeth(hostVeth); err != nil {
			log.Warnf("[bpf-meter] rehydrate attach veth=%s: %v", hostVeth, err)
		}
		// BPF policy attach IS the only same-host tenant-isolation gate.
		// Retry transient TCX races (common on serve restart) before
		// giving up. If retries exhaust, quarantine the VM at the link
		// layer rather than letting it run unprotected: bring its veth
		// DOWN so cross-tenant traffic is impossible. VM keeps its disk
		// + RAM state; operator either fixes the BPF attach (restart
		// serve / reload program) and `ip link set <veth> up`, or
		// destroys the VM. Symmetric with cold-boot's fail-closed path.
		var policyErr error
		for i := 0; i < 5; i++ {
			if policyErr = AttachBPFPolicyToVeth(hostVeth); policyErr == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if policyErr != nil {
			log.Errorf("[bpf-policy] CRITICAL rehydrate attach failed veth=%s after 5 retries: %v — quarantining (veth set DOWN)", hostVeth, policyErr)
			if link, lerr := netlink.LinkByName(hostVeth); lerr == nil {
				if derr := netlink.LinkSetDown(link); derr != nil {
					log.Errorf("[bpf-policy] CRITICAL veth=%s quarantine FAILED: %v — VM is up WITHOUT tenant isolation; operator must destroy this VM or shut down this host", hostVeth, derr)
				}
			} else {
				log.Errorf("[bpf-policy] CRITICAL veth=%s LinkByName failed during quarantine: %v", hostVeth, lerr)
			}
		}
	}

	// Channel must be large enough to hold every slot the pool could ever
	// own — otherwise Return() blocks when concurrent destroys outpace
	// reuse (buffer fills → send waits for a Get → no Get arrives → the
	// destroy handler hangs for minutes). IPAM capacity caps the slot
	// count at the subnet's /31 pair count, so sizing to that + a small
	// safety margin makes Return() strictly non-blocking for every
	// permanent slot we could physically allocate.
	readyCap := ipam.Capacity() + 16
	p := &NetPool{
		ready:              make(chan *PooledNet, readyCap),
		replacements:       make(chan struct{}, readyCap),
		ipam:               ipam,
		closed:             make(chan struct{}),
		counter:            startCounter,
		owned:              make(map[string]struct{}, readyCap),
		quarantined:        make(map[string]quarantinedSlot),
		firecrackerUIDBase: firecrackerUIDBase,
		kvmGID:             kvmGID,
	}
	if startCounter > 0 {
		log.Infof("[netpool] continuing from %s", NetnsName(startCounter))
	}
	adoptedCount := 0
	for _, pn := range adopted {
		hostVeth := vethNameFor(pn.ContainerID)
		if err := AttachBPFMeterToVeth(hostVeth); err != nil {
			log.Warnf("[bpf-meter] adopted slot attach veth=%s: %v (will retry lazily)", hostVeth, err)
		}
		if err := AttachBPFPolicyToVeth(hostVeth); err != nil {
			_ = claimPersistedNetSlot(pn.ContainerID)
			if cleanupErr := reapOrphanSlot(pn.ContainerID); cleanupErr != nil {
				p.Abort()
				return nil, fmt.Errorf("persisted slot %s BPF attach failed (%v) and cleanup failed: %w",
					pn.ContainerID, err, cleanupErr)
			}
			ipam.Release(pn.pair)
			log.Warnf("[netpool] persisted slot=%s BPF attach failed: %v; rebuilding", pn.ContainerID, err)
			continue
		}
		p.owned[pn.ContainerID] = struct{}{}
		p.ready <- pn
		adoptedCount++
	}
	if adoptedCount > 0 {
		log.Infof("[netpool] adopted %d clean idle slot(s) from prior serve", adoptedCount)
	}

	// Pre-create only the deficit after adopting clean idle slots.
	missing := size - len(p.ready)
	if missing < 0 {
		missing = 0
	}
	initErrs := make(chan error, missing)
	initSlots := make(chan *PooledNet, missing)
	initWorkers := replenishWorkers()
	if initWorkers > missing {
		initWorkers = missing
	}
	jobs := make(chan struct{}, missing)
	for i := 0; i < missing; i++ {
		jobs <- struct{}{}
	}
	close(jobs)
	var wg sync.WaitGroup
	for w := 0; w < initWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				pn, err := p.createOne()
				if err != nil {
					initErrs <- err
					return
				}
				initSlots <- pn
			}
		}()
	}
	wg.Wait()
	close(initErrs)
	close(initSlots)
	if err, ok := <-initErrs; ok {
		for pn := range initSlots {
			p.cleanup(pn)
		}
		p.Abort()
		return nil, fmt.Errorf("pre-create network: %w", err)
	}
	for pn := range initSlots {
		p.ready <- pn
	}

	for i := 0; i < replenishWorkers(); i++ {
		go p.replenish(size)
		go p.replaceDiscarded()
	}
	return p, nil
}

// highestExistingPoolN returns the largest N for which a netns file
// /var/run/netns/fcpN exists on the host. The next createOne()
// increments before use, so all new slots land strictly above any orphan
// left behind by a prior serve.
//
// Orphan sets can be non-contiguous (e.g. 1, 3, 6 if other slots were
// drained during Shutdown), so we must find the *highest* used index —
// returning the lowest free one would cause createOne to collide with a
// higher-numbered orphan a few iterations later.
func highestExistingPoolN() int {
	highest := 0
	for nsName := range readExistingNetns() {
		n := parsePoolN(nsName)
		if n > highest {
			highest = n
		}
	}
	return highest
}

// vethNameFor returns the host-side veth interface name for a slot.
// containerID is the slot's netns name ("fcpN"). The veth name is
// "fcp" + N — so "fcp7" → "fcp7", "fcp9999" → "fcp9999".
// Direct counter encoding (no hash): zero collision risk, names are
// human-readable, and the orphan reaper can recover N by parsing.
// "fcp" + up to 12 digits fits in 15-char IFNAMSIZ (10^12 slots — way
// beyond the IPAM ceiling of ~510 per /22).
//
// Panics on malformed input — createOne always sets "fcpN" so any
// failure here is a programming bug, not a runtime condition.
func vethNameFor(containerID string) string {
	n := parsePoolN(containerID)
	if n <= 0 {
		panic(fmt.Sprintf("vethNameFor: malformed containerID %q", containerID))
	}
	return fmt.Sprintf("fcp%d", n)
}

// parsePoolN extracts N from NetnsPrefix+N (e.g. "fcp7" → 7).
// Returns 0 on miss.
func parsePoolN(name string) int {
	if !strings.HasPrefix(name, NetnsPrefix) {
		return 0
	}
	n, err := strconv.Atoi(name[len(NetnsPrefix):])
	if err != nil {
		return 0
	}
	return n
}

// reapOrphanSlot tears down the host-side artifacts of a `fcpN` netns
// left behind by a prior serve process. Removes the deterministic host
// veth (which also nukes its peer inside the netns) and unmounts + deletes
// the netns bind. The marker is removed only after the veth is gone: callers
// can retry a failed teardown, and startup refuses to build a reusable pool
// while an undiscoverable stale interface could remain.
func reapOrphanSlot(nsName string) error {
	hostVeth := vethNameFor(nsName)
	// Belt-and-suspenders: detach any BPF programs attached to the
	// veth before tearing it down. In the current Manager.Create
	// ordering, BPF attach happens AFTER the DB write of IP +
	// container_id, so reconcile's stuck-creating pass (not this
	// reaper) is the one expected to clear them. But if a future
	// refactor moves BPF attach earlier, this catches the leak —
	// stray TCX/clsact attachments on a soon-to-be-deleted veth
	// would dangle in the kernel until the kobject ref drops.
	//
	// Both functions are veth-keyed and idempotent: they no-op when
	// nothing's attached. No sandbox id required.
	// A quarantine can survive a serve restart only as its netns/veth marker;
	// its in-memory sandbox ID is gone. Remove every fc-owned chain attached
	// to this exact interface before deleting it, otherwise stale jumps could
	// affect a future slot that eventually reuses the same veth name.
	if err := removeIfaceSandboxIPTables(hostVeth); err != nil {
		return fmt.Errorf("cleanup iptables for %s: %w", hostVeth, err)
	}
	DetachBPFPolicyFromVeth(hostVeth)
	DetachBPFMeterFromVeth(hostVeth)

	if err := teardownNetDirect(hostVeth); err != nil {
		// Keep the netns bind mount as a durable discovery marker. Startup
		// and periodic reapers will see it and retry; removing it here would
		// make the stale host veth invisible to both.
		return err
	}
	nsPath := NetnsPathRoot + nsName
	_ = unix.Unmount(nsPath, unix.MNT_DETACH)
	_ = os.Remove(nsPath)
	return nil
}

func readExistingNetns() map[string]bool {
	entries, err := os.ReadDir("/var/run/netns")
	if err != nil {
		return nil
	}
	used := map[string]bool{}
	for _, e := range entries {
		used[e.Name()] = true
	}
	return used
}

// replenishWorkers is the configured number of goroutines that refill the
// NetPool in parallel.
var netPoolWorkers = 8

// SetNetPoolWorkers configures network-slot creation concurrency before the
// pool starts. Non-positive values retain the default.
func SetNetPoolWorkers(workers int) {
	if workers > 0 {
		netPoolWorkers = workers
	}
}

func replenishWorkers() int { return netPoolWorkers }

func (p *NetPool) replenish(target int) {
	for {
		select {
		case <-p.closed:
			return
		default:
			if len(p.ready) < target {
				if pn, err := p.createOne(); err == nil {
					select {
					case p.ready <- pn:
					case <-p.closed:
						p.cleanup(pn)
						return
					}
				}
			} else {
				time.Sleep(50 * time.Millisecond)
			}
		}
	}
}

// replaceDiscarded creates one fresh slot for every permanent slot that was
// torn down because its state could not be cleaned safely. This is separate
// from replenish: replenish only maintains the configured minimum ready
// depth, so an expanded pool can sit above that minimum and would otherwise
// silently shrink after a discard.
func (p *NetPool) replaceDiscarded() {
	for {
		select {
		case <-p.closed:
			return
		case <-p.replacements:
		}

		for {
			pn, err := p.createOne()
			if err != nil {
				log.Warnf("[netpool] replace discarded slot: %v", err)
				select {
				case <-p.closed:
					return
				case <-time.After(50 * time.Millisecond):
					continue
				}
			}
			select {
			case p.ready <- pn:
				log.Infof("[netpool] replaced discarded slot with slot=%s ip=%s",
					pn.ContainerID, pn.IP.IP.String())
			case <-p.closed:
				p.cleanup(pn)
				return
			}
			break
		}
	}
}

func (p *NetPool) requestReplacement() {
	select {
	case p.replacements <- struct{}{}:
	case <-p.closed:
	}
}

// IPAMCapacity returns the maximum number of distinct (vmIP, gwIP) pairs
// the underlying IPAM can hand out — i.e. the absolute ceiling on
// concurrent VMs given the configured subnet.
func (p *NetPool) IPAMCapacity() int {
	if p.ipam == nil {
		return 0
	}
	return p.ipam.Capacity()
}

// IPAM returns the underlying IPAM, exposed so rehydrated Sandboxes can
// release their IPs back into the same pool on Destroy.
func (p *NetPool) IPAM() *StaticIPAM { return p.ipam }

func (p *NetPool) Get() *PooledNet {
	for {
		pn := <-p.ready
		if err := claimPersistedNetSlot(pn.ContainerID); err == nil {
			return pn
		} else {
			log.Warnf("[netpool] claim clean marker failed slot=%s: %v; discarding", pn.ContainerID, err)
			p.Discard(pn)
		}
	}
}

// Depth returns the current count of ready slots in the pool. Read
// without acquiring any lock — the value is a sampled snapshot and
// may be off by one or two by the time the caller reads it. Intended
// for metrics emission, not control flow.
func (p *NetPool) Depth() int { return len(p.ready) }

// GetWithDepth returns a pooled net along with the ready-buffer depth seen
// at Get time (before the pop). Useful for diagnosing pool-starvation tails.
func (p *NetPool) GetWithDepth() (*PooledNet, int) {
	d := len(p.ready)
	return p.Get(), d
}

// Return releases a slot back into the pool for reuse by the next VM.
//
// Slots are PERMANENT — netns, veth, IP pair, iptables MASQUERADE, and the
// host-side ARP preseed entry all persist across borrower changes and clean
// serve restarts. Abort/Discard are the explicit teardown paths.
//
// Why: under sustained churn (thousands of creates/day) the prior
// "cleanup-on-Return" model left the kernel repeatedly doing
// `ip netns add/del`, `ip link add/del`, route and neigh bookkeeping —
// work that doesn't shrink the kernel's associated data structures as fast
// as we produce it. After ~1500–1800 cycles the host got unreliable
// (spontaneous agent-not-ready cascades). Permanent slots amortize every
// setup cost across the slot's lifetime, keep ARP/routing warm, and let
// a host run indefinitely under continuous load — the way a sandbox host
// actually gets used.
//
// Slot count becomes an upper bound on concurrent VMs, but replenish()
// will lazily create more permanent slots whenever the ready channel
// dips below the configured minimum, so the pool self-expands on first
// burst past the warm size.
func (p *NetPool) Return(pn *PooledNet) {
	if !pn.permanent {
		// Rehydrated slot — doesn't belong in our pool's rotation.
		p.Discard(pn)
		return
	}
	// Slot is about to be handed out to a different VM (possibly a
	// different tenant). Synchronously clear every pair involving the old
	// VM IP and every source-side pair for this interface before reuse. If
	// either cleanup fails, discard the slot: making it available with stale
	// authorization would cross tenants.
	if err := cleanupSlotPolicy(pn.ContainerID, pn.IP.IP.String()); err != nil {
		log.Warnf("[netpool] policy cleanup failed slot=%s ip=%s: %v; quarantining",
			pn.ContainerID, pn.IP.IP.String(), err)
		p.quarantine(pn, "")
		p.requestReplacement()
		return
	}
	if err := persistCleanNetSlot(pn); err != nil {
		log.Warnf("[netpool] persist clean slot failed slot=%s: %v; discarding", pn.ContainerID, err)
		p.cleanupAfterPolicy(pn)
		p.requestReplacement()
		return
	}
	select {
	case p.ready <- pn:
		// back in rotation — next Get() hands this exact slot out again
	case <-p.closed:
		// shutting down; tear it down instead of leaking
		p.cleanupAfterPolicy(pn)
	}
}

// Discard tears the slot down instead of recycling it. Use when the
// caller has reason to believe the slot is in a corrupted state that
// won't recover by reuse — e.g. waitForAgent timed out for the full
// 5s with zero accepts, indicating the slot's kernel data path is
// wedged in some way the slot itself can't recover from.
//
// Replenish() picks up the deficit on its next tick (within ~50ms).
// We rebuild a fresh netns + veth + tap, leaving the bad one's name
// out of rotation. Counter still increments, so name collisions are
// impossible across the rebuild.
func (p *NetPool) Discard(pn *PooledNet) {
	if pn == nil {
		return
	}
	log.Warnf("[netpool] discarding slot=%s ip=%s — caller flagged corrupted",
		pn.ContainerID, pn.IP.IP.String())
	replace := pn.permanent
	if err := cleanupSlotPolicy(pn.ContainerID, pn.IP.IP.String()); err != nil {
		log.Warnf("[netpool] discard policy cleanup failed slot=%s ip=%s: %v; quarantining",
			pn.ContainerID, pn.IP.IP.String(), err)
		p.quarantine(pn, "")
	} else {
		p.cleanupAfterPolicy(pn)
	}
	if replace {
		p.requestReplacement()
	}
}

// QuarantineAfterTeardownFailure keeps the interface and IP allocated until
// the orphan reaper can successfully remove the sandbox-specific iptables
// chains. Deleting the veth immediately would lose the source-interface
// lookup needed for cleanup and could leave stale rules for a future name.
func (p *NetPool) QuarantineAfterTeardownFailure(pn *PooledNet, sandboxID string) {
	if pn == nil {
		return
	}
	log.Warnf("[netpool] quarantining slot=%s ip=%s sandbox=%s after iptables teardown failure",
		pn.ContainerID, pn.IP.IP.String(), sandboxID)
	replace := pn.permanent
	p.quarantine(pn, sandboxID)
	if replace {
		p.requestReplacement()
	}
}

func (p *NetPool) Close() {
	close(p.closed)
	// Clean idle slots intentionally survive a graceful serve restart. Their
	// durable markers let the next process validate and adopt them. Borrowed
	// slots have no marker and are handled by normal VM rehydration.
}

// Abort stops the pool and tears down idle slots. Initialization failures use
// this path because no successor process is guaranteed to start and adopt them.
func (p *NetPool) Abort() {
	select {
	case <-p.closed:
	default:
		close(p.closed)
	}
	for {
		select {
		case pn := <-p.ready:
			p.cleanup(pn)
		default:
			return
		}
	}
}

// dropIfaceVnis removes the host-veth's fc_iface_pair permissions and
// fc_iface_to_ip identity binding. Used on slot return and final cleanup
// so a reused interface cannot inherit the previous tenant's access.
// Returns cleanup errors for the caller to handle.
func dropIfaceVnis(hostVeth string) error {
	link, err := netlink.LinkByName(hostVeth)
	if err != nil {
		return fmt.Errorf("lookup veth %s: %w", hostVeth, err)
	}
	idx := uint32(link.Attrs().Index)
	if idx == 0 {
		return fmt.Errorf("veth %s has zero ifindex", hostVeth)
	}
	if err := DeleteIfaceVnis(idx); err != nil {
		return fmt.Errorf("DeleteIfaceVnis veth=%s ifindex=%d: %w", hostVeth, idx, err)
	}
	return nil
}

func cleanupSlotPolicy(containerID, ip string) error {
	return errors.Join(
		DeleteVMIPVnis(ip),
		dropIfaceVnis(vethNameFor(containerID)),
	)
}

// quarantine keeps both the veth discovery marker and IP allocation intact.
// ReapOrphans retries BPF cleanup before deleting either, so a stale IP- or
// ifindex-keyed authorization can never be inherited by another sandbox.
func (p *NetPool) quarantine(pn *PooledNet, sandboxID string) {
	p.mu.Lock()
	if pn.ipam != nil && pn.pair.VMCIDR != "" {
		p.quarantined[pn.ContainerID] = quarantinedSlot{pair: pn.pair, sandboxID: sandboxID}
	}
	delete(p.owned, pn.ContainerID)
	p.mu.Unlock()
}

func (p *NetPool) cleanup(pn *PooledNet) {
	if err := cleanupSlotPolicy(pn.ContainerID, pn.IP.IP.String()); err != nil {
		log.Warnf("[net-pool] best-effort policy cleanup slot=%s ip=%s: %v",
			pn.ContainerID, pn.IP.IP.String(), err)
	}
	p.cleanupAfterPolicy(pn)
}

func (p *NetPool) cleanupAfterPolicy(pn *PooledNet) {
	_ = claimPersistedNetSlot(pn.ContainerID)
	hostVeth := vethNameFor(pn.ContainerID)
	DetachBPFMeterFromVeth(hostVeth)
	DetachBPFPolicyFromVeth(hostVeth)
	teardownErr := teardownNetDirect(hostVeth)
	if teardownErr != nil {
		// Preserve both the netns marker and IP allocation. The orphan
		// reaper can retry the discoverable slot, and the same IP cannot be
		// handed to another tenant while a stale route/interface exists.
		log.Warnf("[net-pool] cleanup veth=%s: %v; preserving netns and IP allocation for retry", hostVeth, teardownErr)
	} else {
		_ = unix.Unmount(pn.NetNSPath, unix.MNT_DETACH)
		_ = os.Remove(pn.NetNSPath)
		if pn.ipam != nil && pn.pair.VMCIDR != "" {
			pn.ipam.Release(pn.pair)
		}
	}
	p.mu.Lock()
	if teardownErr != nil && pn.ipam != nil && pn.pair.VMCIDR != "" {
		p.quarantined[pn.ContainerID] = quarantinedSlot{pair: pn.pair}
	}
	delete(p.owned, pn.ContainerID)
	p.mu.Unlock()
}

func (p *NetPool) createOne() (*PooledNet, error) {
	p.mu.Lock()
	p.counter++
	id := NetnsName(p.counter)
	// Per-slot vsock CID. CIDs 0-2 are reserved (HOST=2). Start at 100
	// to leave headroom for future reserved values.
	cid := uint32(100) + uint32(p.counter)
	// Mark owned BEFORE the netns file appears on disk. ReapOrphans
	// reaps any fcpN netns on disk that's not in p.owned AND not in
	// the manager's live-VM set; without this early marking, the
	// 10-100ms window between createNetNS and the final p.owned[id]=
	// write (when setupNetDirect + BPF attaches finish) lets the
	// 5s reconcile-tick reap the in-progress slot, and the eventual
	// firecracker Start() races on a missing /var/run/netns/fcpN
	// (Statfs EACCES, surfaces as "start (cold)" 500).
	p.owned[id] = struct{}{}
	p.mu.Unlock()

	nsPath, err := createNetNS(id)
	if err != nil {
		p.mu.Lock()
		delete(p.owned, id)
		p.mu.Unlock()
		return nil, err
	}

	pair := p.ipam.Allocate()
	// slotUID==0 means "no drop — keep today's root-owned tap". When set,
	// the tap is created with TUNSETOWNER + TUNSETGROUP so the post-drop
	// firecracker (uid=slotUID, supplementary group=kvm) can TUNSETIFF
	// on it without CAP_NET_ADMIN. Both checks must pass: setting only
	// Owner leaves Group=0 (root) which fails the in_egroup_p check.
	var slotUID, slotGID uint32
	if p.firecrackerUIDBase > 0 {
		slotUID = uint32(p.firecrackerUIDBase) + (cid - 100)
		slotGID = p.kvmGID
	}
	res, err := setupNetDirect(nsPath, id, pair.VMCIDR, pair.Gateway, slotUID, slotGID)
	if err != nil {
		p.ipam.Release(pair)
		_ = unix.Unmount(nsPath, unix.MNT_DETACH)
		os.Remove(nsPath)
		p.mu.Lock()
		delete(p.owned, id)
		p.mu.Unlock()
		return nil, fmt.Errorf("net setup: %w", err)
	}
	ipOnly, ipNet, _ := net.ParseCIDR(pair.VMCIDR)
	ipNet.IP = ipOnly.To4()
	gwIP := net.ParseIP(res.Gateway).To4()
	pn := &PooledNet{
		NetNSPath:   nsPath,
		TapName:     res.TapName,
		MAC:         res.MAC,
		IP:          *ipNet,
		Gateway:     gwIP,
		DNS:         []string{"1.1.1.1", "8.8.8.8"},
		VMIfName:    "eth0",
		ContainerID: id,
		VsockCID:    cid,
		pair:        pair,
		ipam:        p.ipam,
		permanent:   true,
	}
	hostVethName := vethNameFor(id)
	// One-time per-slot BPF meter attach (rtnl_mutex serialised). This
	// runs at slot creation time, NOT per VM, so the burst-time hot path
	// can do a lockless map update instead of paying TCX attach cost.
	// Errors are non-fatal: log and proceed; per-VM AttachBPFMeter retries.
	if err := AttachBPFMeterToVeth(hostVethName); err != nil {
		log.Warnf("[bpf-meter] slot attach veth=%s: %v (will retry lazily)", hostVethName, err)
	}
	// One-time per-slot overlay policy attach. Programs are already loaded
	// by LoadBPFPolicy at manager init; this is just TC attachment.
	// fc_veth_policy is the ONLY same-host tenant isolation gate (WG covers
	// cross-host; iptables doesn't check VM-A↔VM-B network membership). If
	// this attach fails, the slot would boot with no tenant isolation —
	// fail closed: roll back netns/tap/ipam and surface the error so the
	// caller 5xx's. The attach itself is atomic (see attachTCPolicy in
	// bpf_policy.go — ingress is detached if egress fails), so there's no
	// partial BPF state to clean up here.
	if err := AttachBPFPolicyToVeth(hostVethName); err != nil {
		p.cleanup(pn)
		return nil, fmt.Errorf("bpf-policy attach veth=%s: %w (refusing to boot slot without tenant isolation)", hostVethName, err)
	}
	if err := persistCleanNetSlot(pn); err != nil {
		p.cleanupAfterPolicy(pn)
		return nil, fmt.Errorf("persist clean network slot %s: %w", id, err)
	}
	// NOTE: we do NOT call PreseedARP here. pn.MAC is the host-side
	// slot MAC we'd *want* the guest to use, but Firecracker snapshot
	// restore doesn't apply NetworkInterfaces.MacAddress over the MAC
	// baked into vmstate — so the guest eth0 keeps the template VM's
	// original MAC across every slot. A preseeded (ip, slot.MAC) neigh
	// entry sends SYNs with the wrong destination MAC; the guest's
	// virtio-net filter drops them all. Dynamic ARP still works because
	// the guest's outbound UDP-to-gateway packet (in applyNetwork) lets
	// the host learn the real MAC passively.
	// p.owned[id] was set early (before createNetNS) to close the
	// reaper race; no need to write it again here.
	return pn, nil
}

// OwnedContainerIDs returns a snapshot of every slot containerID this
// pool currently owns — slots in the ready channel AND slots lent out
// to running VMs. Used by reconcile sweeps to distinguish legitimate
// netns (still owned) from leaked netns (owned by no one) — leaked
// ones get reaped without disturbing live VMs or warm slots.
func (p *NetPool) OwnedContainerIDs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.owned))
	for id := range p.owned {
		out = append(out, id)
	}
	return out
}

// IsOwned reports whether the pool currently owns a slot with this
// containerID — i.e. the slot is either in the ready channel or lent
// out to a running VM. Callers use this before invoking CleanupOrphan
// so they never tear down a slot the pool is tracking.
func (p *NetPool) IsOwned(containerID string) bool {
	if containerID == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.owned[containerID]
	return ok
}

// ReapOrphans tears down any fcpN netns on the host that this pool
// doesn't own AND isn't in liveContainerIDs (slots currently bound to
// running VMs as known to the Manager). Used by the host's periodic
// reconcile tick as a final safety net: any netns left behind by a
// failed teardown path is removed here, releasing its quarantined IP pair,
// iptables/MASQUERADE entries, and veth + tap interfaces.
//
// Idempotent. Returns the count of orphan slots reaped.
func (p *NetPool) ReapOrphans(liveContainerIDs []string) int {
	keep := make(map[string]struct{})
	p.mu.Lock()
	for id := range p.owned {
		keep[id] = struct{}{}
	}
	p.mu.Unlock()
	for _, id := range liveContainerIDs {
		keep[id] = struct{}{}
	}
	reaped := 0
	for ns := range readExistingNetns() {
		if parsePoolN(ns) == 0 {
			continue
		}
		if _, ok := keep[ns]; ok {
			continue
		}
		p.mu.Lock()
		quarantine, quarantined := p.quarantined[ns]
		if _, owned := p.owned[ns]; owned {
			p.mu.Unlock()
			continue
		}
		if quarantined {
			if quarantine.sandboxID != "" {
				if err := removeSandboxIPTables(quarantine.sandboxID, vethNameFor(ns)); err != nil {
					log.Warnf("[netpool] reap quarantined slot=%s sandbox=%s iptables cleanup: %v; retained for retry",
						ns, quarantine.sandboxID, err)
					p.mu.Unlock()
					continue
				}
			}
			ip, _, err := net.ParseCIDR(quarantine.pair.VMCIDR)
			if err != nil {
				log.Warnf("[netpool] reap quarantined slot=%s: parse IP %q: %v", ns, quarantine.pair.VMCIDR, err)
				p.mu.Unlock()
				continue
			}
			if err := cleanupSlotPolicy(ns, ip.String()); err != nil {
				log.Warnf("[netpool] reap quarantined slot=%s policy cleanup: %v; retained for retry", ns, err)
				p.mu.Unlock()
				continue
			}
		}
		if err := reapOrphanSlot(ns); err != nil {
			log.Warnf("[netpool] reap orphan slot=%s: %v; retained for retry", ns, err)
			p.mu.Unlock()
			continue
		}
		if quarantined {
			delete(p.quarantined, ns)
		}
		p.mu.Unlock()
		if quarantined {
			p.ipam.Release(quarantine.pair)
			log.Infof("[netpool] released quarantined slot=%s ip=%s after successful orphan cleanup",
				ns, quarantine.pair.VMCIDR)
		}
		reaped++
	}
	return reaped
}

func createNetNS(name string) (string, error) {
	nsDir := "/var/run/netns"
	_ = os.MkdirAll(nsDir, 0755)
	nsPath := filepath.Join(nsDir, name)
	f, err := os.Create(nsPath)
	if err != nil {
		return "", err
	}
	f.Close()
	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errCh <- err
			return
		}
		errCh <- unix.Mount("/proc/thread-self/ns/net", nsPath, "none", unix.MS_BIND, "")
	}()
	if err := <-errCh; err != nil {
		os.Remove(nsPath)
		return "", err
	}
	return nsPath, nil
}

// PreseedARP installs a permanent ARP entry on the MAIN HOST (not the netns)
// for the guest IP, pointing at the veth that routes to it. Without this, the
// host kernel's ARP request on first dial gets lost (Firecracker virtio-net
// isn't forwarding yet post-resume) and waits ~1s for retry.
func PreseedARP(pn *PooledNet) {
	ipStr := pn.IP.IP.String()
	out, err := exec.Command("ip", "-o", "route", "get", ipStr).Output()
	if err != nil {
		log.Warnf("[arp] route get %s failed: %v", ipStr, err)
		return
	}
	dev := ""
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			dev = fields[i+1]
			break
		}
	}
	if dev == "" {
		log.Warnf("[arp] no dev for %s in route output: %s", ipStr, out)
		return
	}
	cmd := exec.Command("ip", "neigh", "replace", ipStr, "lladdr", pn.MAC,
		"dev", dev, "nud", "permanent")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Warnf("[arp] preseed failed for %s on %s: %v (%s)", ipStr, dev, err, out)
	}
}
