package plugins

import (
	"time"

	"github.com/NodeOps-app/sandbox/internal/scheduler/framework"
)

// DefaultReservationTTL is the fallback when RegisterBuiltins is called
// with ttl <= 0. Long enough to cover a slow control→host create
// (forward + host-side spawn rarely exceeds a few seconds), short enough
// that an orphaned reservation from a control-plane crash gets released
// before the next heartbeat overwrites the host counters anyway.
const DefaultReservationTTL = 30 * time.Second

// RegisterBuiltins registers every in-tree filter, scorer, and reserver
// against reg under their canonical names. The reservation TTL is the
// single source of truth for both the inmem reserver's sweeper and the
// scheduler's published ExpiresAtMs — pass the same value to NewInstance
// and they'll agree. ttl <= 0 falls back to DefaultReservationTTL.
func RegisterBuiltins(reg *framework.Registry, ttl time.Duration) {
	if ttl <= 0 {
		ttl = DefaultReservationTTL
	}

	reg.RegisterFilter("capacity", func() framework.Filter { return CapacityFilter{} })
	reg.RegisterFilter("status", func() framework.Filter { return StatusFilter{} })
	reg.RegisterFilter("schedule_enabled", func() framework.Filter { return ScheduleEnabledFilter{} })
	reg.RegisterFilter("maxvms", func() framework.Filter { return MaxVMsFilter{} })
	reg.RegisterFilter("rootfs", func() framework.Filter { return RootfsFilter{} })
	reg.RegisterFilter("hostpin", func() framework.Filter { return HostPinFilter{} })
	reg.RegisterFilter("label_selector", func() framework.Filter { return LabelSelectorFilter{} })
	reg.RegisterFilter("exclude_hosts", func() framework.Filter { return ExcludeHostsFilter{} })
	reg.RegisterFilter("region", func() framework.Filter { return RegionFilter{} })
	// pending_cap is registered with default Cap=100. With a host-side
	// boot semaphore of 20, this gives a queue depth of up to 80 behind
	// the in-flight 20 — worst-case tail wait per accepted request is
	// ~4s (4 batches × ~1s each spawn). Fleet-wide in-flight ceiling is
	// hosts × Cap; under-capped hosts get 503 with no contention. Cap
	// is configurable via the scheduler's --pending-cap flag (see
	// SchedulerFlags); 0 disables the filter entirely.
	reg.RegisterFilter("pending_cap", func() framework.Filter { return &PendingCapFilter{Cap: 100} })
	// overcommit checks vCPU + memory + disk against per-host
	// oversubscription factors. Backward-compat: skips dimensions
	// where the request or host doesn't advertise the field.
	reg.RegisterFilter("overcommit", func() framework.Filter { return OvercommitFilter{} })
	// cpu_compat is in DefaultPipelineSpec: it pins resume to a same-vendor
	// host (firecracker bakes source CPUID into vmstate; cross-vendor
	// restore SIGILLs). No-op on cold-create (empty SourceCPUVendor) and on
	// single-vendor fleets. Control populates SourceCPUVendor on resume.
	reg.RegisterFilter("cpu_compat", func() framework.Filter { return CPUCompatFilter{} })

	reg.RegisterScorer("least_used_pct", func() framework.Scorer { return LeastUsedPctScorer{} })
	// balanced_alloc is the multi-dimensional successor to least_used_pct:
	// scores by post-placement DOMINANT-resource utilization across
	// cpu/mem/disk instead of memory alone. Avoids the stranding pathology
	// where CPU pegs while memory sits unused.
	reg.RegisterScorer("balanced_alloc", func() framework.Scorer { return BalancedAllocScorer{} })
	// best_fit complements balanced_alloc: for BIG requests (≥20% of any
	// host dim) it prefers hosts where the placement fills the gap snugly,
	// avoiding fragmentation. Small requests get a neutral score (50) so
	// balanced wins them. See BestFitScorer doc for the rationale.
	reg.RegisterScorer("best_fit", func() framework.Scorer { return BestFitScorer{} })
	reg.RegisterScorer("fewest_vms", func() framework.Scorer { return FewestVMsScorer{} })
	// spread is registered with a nil PendingFn; the scheduler instance
	// wires the reserver in after BuildPipeline. The factory keeps the
	// registry API stable (no DI through the registry).
	reg.RegisterScorer("spread", func() framework.Scorer { return &SpreadScorer{} })
	reg.RegisterScorer("random", func() framework.Scorer { return RandomScorer{} })
	reg.RegisterScorer("locality", func() framework.Scorer { return LocalityScorer{} })
	reg.RegisterScorer("template_availability", func() framework.Scorer { return TemplateAvailabilityScorer{} })
	reg.RegisterScorer("region_match", func() framework.Scorer { return RegionScorer{Wt: 100} })
	// cpu_compat scorer is REGISTERED but deliberately NOT in
	// DefaultPipelineSpec. Adds a soft preference for same-vendor hosts
	// on cold creates so users' future pause/resume options stay broad.
	reg.RegisterScorer("cpu_compat", func() framework.Scorer { return CPUCompatScorer{Wt: 1} })

	reg.RegisterReserver("inmem", func() framework.Reserver {
		return NewInMemReserver(ttl)
	})
}

// DefaultPipelineSpec returns the spec that reproduces the previous
// monolithic Pick: hostpin + status + capacity + maxvms + rootfs filters,
// LeastUsedPct + FewestVMs scorers, in-mem reserver. Random scorer is
// omitted from the default — the pipeline already randomises among
// hosts tied at the maximum score.
func DefaultPipelineSpec() framework.PipelineSpec {
	return framework.PipelineSpec{
		Filters: []string{"region", "hostpin", "status", "schedule_enabled", "capacity", "overcommit", "maxvms", "pending_cap", "rootfs", "label_selector", "exclude_hosts", "cpu_compat"},
		Scorers: []framework.ScorerSpec{
			{Name: "balanced_alloc", Weight: 0}, // multi-dim binder (spread)
			{Name: "best_fit", Weight: 0},       // tight-fit for BIG requests (pack)
			{Name: "least_used_pct", Weight: 0}, // memory-only tie-break (legacy)
			{Name: "fewest_vms", Weight: 0},
			{Name: "spread", Weight: 0},
			{Name: "locality", Weight: 0},
			{Name: "template_availability", Weight: 0},
			{Name: "region_match", Weight: 0},
		},
		Reserver: "inmem",
	}
}
