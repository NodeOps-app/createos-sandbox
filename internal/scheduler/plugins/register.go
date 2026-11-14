package plugins

import (
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/scheduler/framework"
)

// DefaultReservationTTL is retained for configuration compatibility. The
// current in-memory reserver ignores it and uses the hydrate grace cutoff.
const DefaultReservationTTL = 30 * time.Second

// RegisterBuiltins registers the built-in filters, scorers, and reserver.
// The ttl argument is retained for compatibility with the reserver factory.
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
	// Default to 100 pending reservations per host. NewInstance applies
	// positive PendingCap overrides; a zero config value retains this default.
	reg.RegisterFilter("pending_cap", func() framework.Filter { return &PendingCapFilter{Cap: 100} })
	// overcommit checks vCPU + memory + disk against per-host
	// oversubscription factors. Backward-compat: skips dimensions
	// where the request or host doesn't advertise the field.
	reg.RegisterFilter("overcommit", func() framework.Filter { return OvercommitFilter{} })
	// Reject mismatched or unknown destination vendors when the request
	// carries a source vendor. This is not a full restore-compatibility check.
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
	// Optional same-vendor preference, inactive when SourceCPUVendor is empty.
	// This scorer is not included in the default pipeline.
	reg.RegisterScorer("cpu_compat", func() framework.Scorer { return CPUCompatScorer{Wt: 1} })

	reg.RegisterReserver("inmem", func() framework.Reserver {
		return NewInMemReserver(ttl)
	})
}

// DefaultPipelineSpec combines placement and capacity filters with resource,
// spread, and locality scorers. Zero scorer weights select plugin defaults.
// The pipeline breaks equal scores randomly and reserves capacity in memory.
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
