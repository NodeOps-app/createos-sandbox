package plugins

import (
	"context"
	"sync"
	"time"

	"github.com/NodeOps-app/sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/sandbox/models"
)

// reservation tracks one in-flight schedule decision keyed by sandbox id.
type reservation struct {
	hostID     string
	memMib     int
	vcpu       int   // for multi-dim overcommit admission
	diskMib    int64 // for multi-dim overcommit admission
	reservedAt time.Time
}

// InMemReserver is the default Reserver. State is a per-host map of
// per-sandbox reservations. The sandbox id is the key — minted by control
// before the Schedule call and durably committed to the sandboxes table.
//
// Reconcile drops entries that the durable record now reflects (live SUM
// already accounts for them) or whose row has gone terminal. A grace
// timer covers the remaining case where control crashed between Schedule
// and the durable host_id UPDATE.
type InMemReserver struct {
	mu sync.Mutex
	// usage is the per-host map of reservations keyed by sandbox id.
	usage map[string]map[string]reservation
}

// NewInMemReserver constructs a fresh reserver. The grace period is owned
// by the caller (passed into Reconcile every hydrate tick), so this
// reserver itself holds no timer.
func NewInMemReserver(_ time.Duration) *InMemReserver {
	return &InMemReserver{usage: make(map[string]map[string]reservation)}
}

// Stop is a no-op — kept for API stability with the previous version.
func (r *InMemReserver) Stop() {}

func (r *InMemReserver) Name() string { return "inmem" }

// Reserve checks effective capacity (host's authoritative used + this
// host's pending delta) against the request. On overflow returns
// ErrConflict so the pipeline can try the next host.
func (r *InMemReserver) Reserve(_ context.Context, sbID string, req *framework.Request, h *models.Host) error {
	if sbID == "" {
		// A misuse — keep loud so callers don't accidentally lose the key.
		return framework.ErrUnknownHost
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	hostMap := r.usage[h.ID]
	pendingMem := 0
	pendingVMs := 0
	pendingVCPU := 0
	var pendingDisk int64
	for _, res := range hostMap {
		pendingMem += res.memMib
		pendingVMs++
		pendingVCPU += res.vcpu
		pendingDisk += res.diskMib
	}
	reservedMem := req.ReservedMemoryMiB()
	if h.InUseMib+pendingMem+reservedMem > h.MemCapacityMib {
		return framework.ErrConflict
	}
	if h.MaxVMs > 0 && h.VMCount+pendingVMs+1 > h.MaxVMs {
		return framework.ErrConflict
	}
	// Multi-dim admission against pending+live counters. Treats
	// hosts/requests that haven't advertised the new dimensions as
	// "skip this check" (factor of 0). See OvercommitFilter for the
	// same logic applied against authoritative-only counters.
	if req.VCPU > 0 && h.CPUCount > 0 {
		factor := h.CPUOvercommitX10
		if factor <= 0 {
			factor = DefaultCPUOvercommitX10
		}
		if h.VCPUInUse+pendingVCPU+req.VCPU > h.CPUCount*factor/10 {
			return framework.ErrConflict
		}
	}
	if req.DiskMiB > 0 && h.DiskTotalMib > 0 {
		if h.DiskInUseMib+pendingDisk+req.DiskMiB > DiskCommitLimitMiB(h) {
			return framework.ErrConflict
		}
	}

	if hostMap == nil {
		hostMap = make(map[string]reservation)
		r.usage[h.ID] = hostMap
	}
	hostMap[sbID] = reservation{
		hostID:     h.ID,
		memMib:     reservedMem,
		vcpu:       req.VCPU,
		diskMib:    req.DiskMiB,
		reservedAt: time.Now(),
	}
	return nil
}

// Release drops a reservation by sandbox id. Idempotent: unknown ids are
// silently ignored, which is the right behavior under retries and
// scheduler restarts.
func (r *InMemReserver) Release(_ context.Context, sbID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for hostID, hostMap := range r.usage {
		if _, ok := hostMap[sbID]; ok {
			delete(hostMap, sbID)
			if len(hostMap) == 0 {
				delete(r.usage, hostID)
			}
			return nil
		}
	}
	return nil
}

// Reconcile is called by the scheduler's hydrate tick.
//
//   - live[id]==true       → durable record already reflects this id (it's
//     in the absolute SUM); drop from delta to
//     avoid double-counting.
//   - terminated[id]==true → row is failed/destroyed; drop from delta
//     immediately (don't wait for the grace timer).
//   - reservedAt < cutoff  → control crashed mid-flight; drop.
//   - otherwise            → keep (still in-flight, durable record may
//     simply not have caught up yet).
func (r *InMemReserver) Reconcile(live, terminated map[string]bool, graceCutoff time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for hostID, hostMap := range r.usage {
		for sbID, res := range hostMap {
			switch {
			case live[sbID]:
				delete(hostMap, sbID)
			case terminated[sbID]:
				delete(hostMap, sbID)
			case res.reservedAt.Before(graceCutoff):
				delete(hostMap, sbID)
			}
		}
		if len(hostMap) == 0 {
			delete(r.usage, hostID)
		}
	}
}

// PendingIDs returns the sandbox ids currently held in the delta. Hydrate
// uses this to bound the StatusOfIDs DB lookup (we only need to ask about
// ids we still hold).
func (r *InMemReserver) PendingIDs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0)
	for _, hostMap := range r.usage {
		for sbID := range hostMap {
			out = append(out, sbID)
		}
	}
	return out
}

// Snapshot returns a copy of the per-host pending counters. Test-facing.
type Usage struct {
	UsedMib int
	VMCount int
}

func (r *InMemReserver) Snapshot() map[string]Usage {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]Usage, len(r.usage))
	for hostID, hostMap := range r.usage {
		var u Usage
		for _, res := range hostMap {
			u.UsedMib += res.memMib
			u.VMCount++
		}
		out[hostID] = u
	}
	return out
}

// UpsertCounters is retained for API compatibility but is now a no-op:
// authoritative counters come from the durable record via hydrate, not
// from heartbeat fan-out. Kept so callers don't need to be updated in
// the same change.
func (r *InMemReserver) UpsertCounters(_ string, _ int, _ int) {}

// PendingVMs returns the number of in-flight reservations currently
// targeted at the given host. Used by the SpreadScorer to bias the
// placement decision away from hosts that have already taken many
// pending placements within the current hydrate window — the antidote
// to the "all 100 concurrent decisions pick the same most-free host
// because hydrate is 1s stale" failure mode under burst.
func (r *InMemReserver) PendingVMs(hostID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	hm, ok := r.usage[hostID]
	if !ok {
		return 0
	}
	return len(hm)
}
