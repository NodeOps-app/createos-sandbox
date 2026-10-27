package plugins

import (
	"github.com/NodeOps-app/sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/sandbox/models"
)

// BalancedAllocScorer scores a host by its post-placement DOMINANT
// resource utilization (the highest util across cpu/mem/disk).
// Higher score = lower peak utilization after placing this request.
//
// This is Dominant Resource Fairness (DRF) scoring — the same
// principle Mesos and k8s use for multi-dim bin-packing. The intuition:
//
//	placing a request on host H consumes (vcpu, mem, disk) units
//	the BINDER is whichever dim ends up most utilized
//	we want to spread placements so no host's binder spikes
//
// Without this, the existing LeastUsedPctScorer (memory-only) would
// happily pile sandboxes onto a host with 90% CPU committed but 30%
// mem used — eventually the OvercommitFilter starts rejecting at CPU,
// and meanwhile other hosts' memory sits unused. This scorer picks the
// host where ALL dimensions stay balanced, draining CPU and memory
// proportionally.
//
// Backward-compat: legacy hosts with CPUCount=0 or DiskTotalMib=0 fall
// back to memory-only scoring, matching LeastUsedPctScorer behavior.
//
// Returns 0..100 like other scorers; framework's weighted sum still
// works correctly.
type BalancedAllocScorer struct{}

func (BalancedAllocScorer) Name() string { return "balanced_alloc" }

// Weight 20 — twice LeastUsedPct, so multi-dim wins ties on
// memory-only behavior. Composes with FewestVMs (1) and Spread (100):
// Spread dominates under burst, BalancedAlloc steers steady-state.
func (BalancedAllocScorer) Weight() int { return 20 }

func (BalancedAllocScorer) Score(req *framework.Request, h *models.Host) int {
	if h == nil {
		return 0
	}

	// Compute per-dim post-placement utilization in [0,1].
	// A dim with zero limit (legacy or unconfigured) is skipped — it
	// doesn't pin the host's binder. Mem is always present; CPU and
	// disk may be 0 on legacy hosts.
	maxUtil := 0.0
	anyDim := false

	if h.MemCapacityMib > 0 {
		factor := h.MemOvercommitX10
		if factor <= 0 {
			factor = DefaultMemOvercommitX10
		}
		limit := h.MemCapacityMib * factor / 10
		if limit > 0 {
			u := float64(h.InUseMib+req.ReservedMemoryMiB()) / float64(limit)
			if u > maxUtil {
				maxUtil = u
			}
			anyDim = true
		}
	}

	if h.CPUCount > 0 {
		factor := h.CPUOvercommitX10
		if factor <= 0 {
			factor = DefaultCPUOvercommitX10
		}
		limit := h.CPUCount * factor / 10
		if limit > 0 {
			u := float64(h.VCPUInUse+req.VCPU) / float64(limit)
			if u > maxUtil {
				maxUtil = u
			}
			anyDim = true
		}
	}

	if h.DiskTotalMib > 0 {
		limit := DiskCommitLimitMiB(h)
		if limit > 0 {
			u := float64(h.DiskInUseMib+req.DiskMiB) / float64(limit)
			if u > maxUtil {
				maxUtil = u
			}
			anyDim = true
		}
	}

	// Nothing to score against — host hasn't advertised any limits.
	if !anyDim {
		return 0
	}

	// Clamp util into [0,1], then map to a 0..100 score where 100 =
	// completely empty after placement and 0 = at-or-over the binder
	// limit. Over-cap requests would have been rejected by the filter,
	// but this clamp keeps the scorer's contract pure.
	if maxUtil < 0 {
		maxUtil = 0
	}
	if maxUtil > 1 {
		maxUtil = 1
	}
	score := 100 - int(maxUtil*100)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}
