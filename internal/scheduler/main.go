// Package scheduler is the control scheduler service. It owns the in-memory
// truth for per-host capacity counters, runs leader election against
// Postgres advisory locks, and exposes an HTTP API for the control plane.
//
// On leadership acquire it hydrates from `sandboxes` (durable record of live
// VMs) into the framework's reserver, then waits one heartbeat cycle before
// opening for traffic. On lock loss it stops accepting Schedule requests
// until re-elected.
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NodeOps-app/sandbox/internal/httpx"
	"github.com/NodeOps-app/sandbox/internal/leader"
	"github.com/NodeOps-app/sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/sandbox/internal/scheduler/plugins"
	"github.com/NodeOps-app/sandbox/internal/vmcapacity"
	"github.com/NodeOps-app/sandbox/models"
)

// State is the readiness state machine. See api.ReadyzResponse for the
// strings these values map to.
type State int32

const (
	StateFollower State = iota
	StateHydrating
	StateWarming
	StateLeaderActive
	StateLostLock
)

func (s State) String() string {
	switch s {
	case StateFollower:
		return "follower"
	case StateHydrating:
		return "hydrating"
	case StateWarming:
		return "warming"
	case StateLeaderActive:
		return "leader_active"
	case StateLostLock:
		return "lost_lock"
	}
	return "unknown"
}

// Config configures an Instance.
type Config struct {
	LeaderID       string        // identifier for /readyz; defaults to hostname-flavoured "scheduler"
	WarmingPeriod  time.Duration // default 10s — gap after hydrate before accepting traffic
	ReservationTTL time.Duration // default plugins.DefaultReservationTTL — applies to both the inmem sweeper and the published ExpiresAtMs

	// HydrateInterval is the cadence at which the scheduler re-reads the
	// durable record (listLiveSandboxes + statusOfIDs) to refresh the host
	// cache and reconcile in-mem reservations. Default 5s.
	//
	// Tradeoff: smaller intervals close the "destroy → next-create sees
	// stale capacity" window faster, at the cost of more DB queries. For
	// typical workloads (sandbox lifetimes of minutes–hours), 5s is
	// invisible. Tune below this for latency-sensitive burst tests.
	HydrateInterval time.Duration

	// ReservationGracePeriod is how long an in-mem delta entry can survive
	// without appearing in the durable record before being dropped. Catches
	// reservations orphaned by a control-plane crash between Schedule and
	// the host_id UPDATE. Default 60s. This protects the short pre-durable
	// reservation gap; it is independent of the longer creating-row watchdog.
	ReservationGracePeriod time.Duration

	// PendingCap, when > 0, overrides the PendingCapFilter's hardcoded
	// default. Tunable knob for fleet operators: raise to absorb larger
	// bursts at the cost of deeper per-host queues; lower to fail-fast
	// sooner.
	PendingCap int

	// Disk headroom is subtracted from the final logical commitment limit after
	// the host's sparse-disk overcommit factor is applied.
	// Defaults: 10% plus 20 GiB per host.
	DiskSafetyPercent       int
	DiskTransientReserveMiB int64
	DiskHeadroomConfigured  bool

	PipelineSpec framework.PipelineSpec // default = plugins.DefaultPipelineSpec()
	Logger       *slog.Logger
	Repo         *models.Repo
}

// Instance is the running scheduler. Cheap to construct; call Run with the
// elector and Repo wired in to start serving.
type Instance struct {
	cfg    Config
	logger *slog.Logger
	repo   *models.Repo

	registry *framework.Registry
	pipeline *framework.Pipeline
	reserver *plugins.InMemReserver

	// Atomics — readable from any goroutine without locking.
	state     atomic.Int32
	epoch     atomic.Int64
	startedAt time.Time

	// hostCache is the metadata view used for filtering. Populated from
	// listActiveHosts on hydrate and on each pollBackstop tick. Capacity
	// counters in this cache are the absolute DB-reported values; the
	// reserver layers an in-mem delta on top.
	mu        sync.RWMutex
	hostCache map[string]models.Host
}

// NewInstance constructs an Instance with the built-in plugins registered.
// Does not start any goroutines.
func NewInstance(cfg Config) (*Instance, error) {
	if cfg.Repo == nil {
		return nil, errors.New("scheduler: Repo is required")
	}
	if cfg.WarmingPeriod == 0 {
		cfg.WarmingPeriod = 10 * time.Second
	}
	if cfg.ReservationTTL <= 0 {
		cfg.ReservationTTL = plugins.DefaultReservationTTL
	}
	if cfg.HydrateInterval <= 0 {
		cfg.HydrateInterval = 5 * time.Second
	}
	if cfg.ReservationGracePeriod <= 0 {
		cfg.ReservationGracePeriod = 60 * time.Second
	}
	if !cfg.DiskHeadroomConfigured {
		cfg.DiskSafetyPercent = 10
		cfg.DiskTransientReserveMiB = 20 * 1024
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	logger := cfg.Logger.With(slog.String("component", "scheduler"))
	if cfg.LeaderID == "" {
		cfg.LeaderID = "scheduler"
	}

	spec := cfg.PipelineSpec
	if len(spec.Filters) == 0 && len(spec.Scorers) == 0 && spec.Reserver == "" {
		spec = plugins.DefaultPipelineSpec()
	}

	reg := framework.NewRegistry()
	plugins.RegisterBuiltins(reg, cfg.ReservationTTL)
	pipeline, err := reg.BuildPipeline(spec)
	if err != nil {
		return nil, fmt.Errorf("build pipeline: %w", err)
	}
	reserver, ok := pipeline.Reserver.(*plugins.InMemReserver)
	if !ok && pipeline.Reserver != nil {
		// Currently we only ship the in-mem reserver; future reservers
		// would need their own hydration adapter. Fail loudly so a config
		// typo (e.g. selecting an unimplemented "lwt" reserver) doesn't
		// silently bypass capacity tracking.
		return nil, fmt.Errorf("scheduler: only the in-mem reserver supports hydration today")
	}

	// Late-bind the reserver's PendingVMs into any SpreadScorer /
	// PendingCapFilter instances. Without this they're no-ops
	// (PendingFn=nil). Done after BuildPipeline because the factory
	// pattern in the registry doesn't let us inject the reserver at
	// construction time.
	if reserver != nil {
		for _, sc := range pipeline.Scorers {
			if s, ok := sc.(*plugins.SpreadScorer); ok {
				s.PendingFn = reserver.PendingVMs
			}
		}
		for _, fl := range pipeline.Filters {
			if f, ok := fl.(*plugins.PendingCapFilter); ok {
				f.PendingFn = reserver.PendingVMs
				if cfg.PendingCap > 0 {
					f.Cap = cfg.PendingCap
				}
			}
		}
	}

	i := &Instance{
		cfg:       cfg,
		logger:    logger,
		repo:      cfg.Repo,
		registry:  reg,
		pipeline:  pipeline,
		reserver:  reserver,
		startedAt: time.Now(),
		hostCache: make(map[string]models.Host),
	}
	i.state.Store(int32(StateFollower))
	return i, nil
}

// Stop releases instance-owned resources (sweeper goroutines, etc).
func (i *Instance) Stop() {
	if i.reserver != nil {
		i.reserver.Stop()
	}
}

// Epoch returns the leader epoch. Increments on every acquisition.
func (i *Instance) Epoch() int64 { return i.epoch.Load() }

// State returns the current readiness state. Atomic.
func (i *Instance) State() State { return State(i.state.Load()) }

// Ready reports whether the instance is currently accepting Schedule traffic.
func (i *Instance) Ready() bool { return i.State() == StateLeaderActive }

// LeaderCallbacks returns Callbacks suitable for handing to the leader
// package. The OnAcquire callback runs hydrate + warm-up; OnLose flips
// state to LostLock.
func (i *Instance) LeaderCallbacks() leader.Callbacks {
	return leader.Callbacks{
		OnAcquire: i.onAcquire,
		OnLose:    i.onLose,
	}
}

// SetEpoch updates the published epoch. Called by the elector wire-up in
// main_server.go after a successful acquisition (before OnAcquire fires
// the elector has already incremented its own epoch counter, but our
// Ready/Schedule paths consume i.epoch which we keep in lockstep here).
func (i *Instance) SetEpoch(e int64) { i.epoch.Store(e) }

// onAcquire is the leader callback. Blocks until ctx is cancelled.
func (i *Instance) onAcquire(ctx context.Context) error {
	i.state.Store(int32(StateHydrating))
	i.logger.Info("hydrating from DB")
	if err := i.hydrate(ctx); err != nil {
		// On hydrate failure: stay in Hydrating so /readyz reports it.
		// Returning here drops out of OnAcquire; the elector keeps the
		// lock until liveness fails or shutdown. A future tick will
		// retry hydrate via the poll backstop.
		i.logger.Warn("hydrate failed, will retry on backstop tick", slog.String("err", err.Error()))
	}

	i.state.Store(int32(StateWarming))
	i.logger.Info("warming", slog.Duration("for", i.cfg.WarmingPeriod))
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(i.cfg.WarmingPeriod):
	}

	i.state.Store(int32(StateLeaderActive))
	i.logger.Info("leader_active")

	// Hydrate cadence: refresh host metadata + capacity from the durable
	// record. See Config.HydrateInterval for the tuning story.
	t := time.NewTicker(i.cfg.HydrateInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := i.refreshHostCache(ctx); err != nil {
				i.logger.Debug("host cache refresh failed", slog.String("err", err.Error()))
			}
		}
	}
}

func (i *Instance) onLose() {
	i.state.Store(int32(StateLostLock))
	// Drop host cache so a future re-acquire forces a fresh hydrate. The
	// in-mem reserver's per-host deltas reset when UpsertCounters runs
	// on the next heartbeat, so they're not actively wrong while we're
	// not leader — Schedule simply won't run.
	i.mu.Lock()
	i.hostCache = make(map[string]models.Host)
	i.mu.Unlock()
	i.logger.Info("lost leadership")
}

// hydrate refreshes the host cache and the reserver's in-mem delta from
// the durable record. Two queries:
//  1. listActiveHosts — host metadata (capacity, status, rootfses).
//  2. listLiveSandboxes — per-row (id, host_id, mem) for creating/running.
//
// Aggregates 2 into per-host SUM (drives absolute view) and a per-id
// seen set (drives reserver.Reconcile). Pending reserver entries that
// didn't appear in the live set get their durable status looked up so
// terminal rows drop fast instead of waiting on the grace timer.
func (i *Instance) hydrate(ctx context.Context) error {
	hosts, err := i.repo.ListActiveHosts(ctx)
	if err != nil {
		return fmt.Errorf("list active hosts: %w", err)
	}
	live, err := i.repo.ListLiveSandboxes(ctx)
	if err != nil {
		return fmt.Errorf("list live sandboxes: %w", err)
	}

	type hostUsage struct {
		used    int   // guest memory plus per-shape Firecracker overhead
		count   int   // vm count
		vcpu    int   // vcpu SUM (for multi-dim admission)
		diskMib int64 // disk_mib SUM (for multi-dim admission)
	}
	absolute := make(map[string]hostUsage, len(hosts))
	liveSet := make(map[string]bool, len(live))
	for _, ls := range live {
		u := absolute[ls.HostID]
		u.used += vmcapacity.ReservedMemoryMiB(ls.Shape, ls.MemMib)
		u.count++
		u.vcpu += ls.VCPU
		u.diskMib += ls.DiskMib
		absolute[ls.HostID] = u
		liveSet[ls.ID] = true
	}

	// Hydrate per-host template cache. One extra query per hydrate tick;
	// pivot into a map[host_id][]tpl_id. Errors here are non-fatal — we
	// fall through with empty CachedTemplates which just means the
	// TemplateAvailability scorer won't bias placement this tick.
	tplsByHost := map[string][]string{}
	if recs, err := i.repo.ListHostsForTemplate(ctx); err == nil {
		for _, r := range recs {
			tplsByHost[r.HostID] = append(tplsByHost[r.HostID], r.TplID)
		}
	}

	// Build cache from active hosts; layer in absolute counters.
	cache := make(map[string]models.Host, len(hosts))
	for _, h := range hosts {
		h.DiskHeadroomMib = diskHeadroomMiB(
			h.DiskTotalMib,
			i.cfg.DiskSafetyPercent,
			i.cfg.DiskTransientReserveMiB,
		)
		if u, ok := absolute[h.ID]; ok {
			h.InUseMib = u.used
			h.VMCount = u.count
			h.VCPUInUse = u.vcpu
			h.DiskInUseMib = u.diskMib
		}
		if tpls := tplsByHost[h.ID]; len(tpls) > 0 {
			h.CachedTemplates = tpls
		}
		cache[h.ID] = h
	}

	// For any reservation still in-flight that isn't in the live set,
	// look up its durable status — failed/destroyed rows drop the delta
	// entry immediately. Bounded by len(pending), typically small.
	terminated := make(map[string]bool)
	if i.reserver != nil {
		pending := i.reserver.PendingIDs()
		var orphans []string
		for _, id := range pending {
			if !liveSet[id] {
				orphans = append(orphans, id)
			}
		}
		if len(orphans) > 0 {
			statuses, err := i.repo.StatusOfIDs(ctx, orphans)
			if err != nil {
				i.logger.Warn("status lookup failed; relying on grace timer",
					slog.String("err", err.Error()),
					slog.Int("orphans", len(orphans)))
			} else {
				for id, st := range statuses {
					if st == "failed" || st == "destroyed" {
						terminated[id] = true
					}
				}
			}
		}
		i.reserver.Reconcile(liveSet, terminated, time.Now().Add(-i.cfg.ReservationGracePeriod))
	}

	i.mu.Lock()
	i.hostCache = cache
	i.mu.Unlock()
	i.logger.Debug("hydrated",
		slog.Int("hosts", len(hosts)),
		slog.Int("live", len(live)),
		slog.Int("terminated", len(terminated)))
	return nil
}

// diskHeadroomMiB is withheld after the disk overcommit limit is calculated,
// so a 2x sparse-disk factor never also overcommits operational headroom.
func diskHeadroomMiB(totalMiB int64, safetyPercent int, transientMiB int64) int64 {
	if totalMiB <= 0 {
		return 0
	}
	reserve := totalMiB*int64(safetyPercent)/100 + transientMiB
	return reserve
}

// refreshHostCache pulls the latest host rows + usage. Called every second
// by the poll backstop; semantically a partial re-hydrate.
func (i *Instance) refreshHostCache(ctx context.Context) error {
	return i.hydrate(ctx)
}

// hostsSnapshot returns a copy of the current host cache as a slice.
func (i *Instance) hostsSnapshot() []models.Host {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]models.Host, 0, len(i.hostCache))
	for _, h := range i.hostCache {
		out = append(out, h)
	}
	return out
}

// HostsSnapshot is the exported version of hostsSnapshot — returns a
// stable copy of the host metadata cache (including authoritative SUMs
// from the last hydrate). Used by the /v1/capacity endpoint to expose
// per-dimension committed-vs-limit to dashboards + ops tooling.
func (i *Instance) HostsSnapshot() []models.Host {
	return i.hostsSnapshot()
}

// Schedule runs the pipeline against the current host cache. Returns
// ErrNotReady if the instance is not in StateLeaderActive. The sandbox
// id is the reservation key used by the reserver; control must have
// INSERTed the row before calling Schedule so the durable record exists
// for hydrate to pick up.
func (i *Instance) Schedule(ctx context.Context, sbID string, req *framework.Request) (*framework.Decision, *models.Host, error) {
	started := time.Now()
	if !i.Ready() {
		return nil, nil, ErrNotReady
	}
	// Region must exist and not be disabled. Fail fast before running the
	// pipeline so callers get a precise error instead of an opaque
	// "no host has region=foo" rejection from RegionFilter.
	if req.Region == "" {
		return nil, nil, ErrInvalidRegion
	}
	regionStarted := time.Now()
	r, err := i.repo.GetRegion(ctx, req.Region)
	regionDur := time.Since(regionStarted)
	if err != nil {
		return nil, nil, fmt.Errorf("region lookup: %w", err)
	}
	if r == nil {
		return nil, nil, ErrInvalidRegion
	}
	if !r.IsActive() {
		return nil, nil, ErrRegionDisabled
	}
	snapshotStarted := time.Now()
	hosts := i.hostsSnapshot()
	snapshotDur := time.Since(snapshotStarted)
	pipelineStarted := time.Now()
	d, err := i.pipeline.Schedule(ctx, sbID, req, hosts)
	pipelineDur := time.Since(pipelineStarted)
	if err != nil {
		i.logger.Info("schedule timing",
			slog.String("request_id", httpx.RequestID(ctx)), slog.String("sandbox_id", sbID),
			slog.Duration("region", regionDur), slog.Duration("snapshot", snapshotDur),
			slog.Duration("pipeline", pipelineDur), slog.Duration("total", time.Since(started)),
			slog.String("error", err.Error()))
		return nil, nil, err
	}
	lookupStarted := time.Now()
	i.mu.RLock()
	h := i.hostCache[d.HostID]
	i.mu.RUnlock()
	lookupDur := time.Since(lookupStarted)
	i.logger.Info("schedule timing",
		slog.String("request_id", httpx.RequestID(ctx)), slog.String("sandbox_id", sbID),
		slog.Duration("region", regionDur), slog.Duration("snapshot", snapshotDur),
		slog.Duration("pipeline", pipelineDur), slog.Duration("lookup", lookupDur),
		slog.Duration("total", time.Since(started)), slog.String("host_id", d.HostID))
	return d, &h, nil
}

// Release calls through to the configured reserver. Idempotent: unknown
// sandbox ids are accepted silently.
func (i *Instance) Release(ctx context.Context, sbID string) error {
	if i.pipeline.Reserver == nil {
		return nil
	}
	return i.pipeline.Reserver.Release(ctx, sbID)
}

// UpsertHostCounters lets the heartbeat fan-out path push authoritative
// counters into the in-mem reserver.
func (i *Instance) UpsertHostCounters(hostID string, usedMib, vmCount int) {
	if i.reserver != nil {
		i.reserver.UpsertCounters(hostID, usedMib, vmCount)
	}
	i.mu.Lock()
	if h, ok := i.hostCache[hostID]; ok {
		h.InUseMib = usedMib
		h.VMCount = vmCount
		i.hostCache[hostID] = h
	}
	i.mu.Unlock()
}

// LeaderID is the identifier the instance reports in /readyz.
func (i *Instance) LeaderID() string { return i.cfg.LeaderID }

// ReservationTTL is the lifetime of a reservation token. Used by the HTTP
// handler to compute ExpiresAtMs so the published deadline matches the
// in-mem sweeper's actual expiry.
func (i *Instance) ReservationTTL() time.Duration { return i.cfg.ReservationTTL }

// UptimeMs is milliseconds since NewInstance.
func (i *Instance) UptimeMs() int64 {
	return time.Since(i.startedAt).Milliseconds()
}

// ErrNotReady is returned by Schedule when the instance is not the active
// leader or is still warming.
var (
	ErrNotReady       = errors.New("scheduler: not ready")
	ErrInvalidRegion  = errors.New("scheduler: region is required and must exist")
	ErrRegionDisabled = errors.New("scheduler: region is disabled")
)
