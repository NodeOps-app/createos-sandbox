package plugins

import (
	"github.com/NodeOps-app/sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/sandbox/models"
)

// BestFitScorer optimizes for bin-packing density on BIG requests:
// when a request would consume a significant fraction of a host's
// capacity in any dimension, prefer hosts where placing it leaves the
// SMALLEST residual gap. Complements BalancedAllocScorer which spreads
// load — together they handle both heterogeneous (mix of small + big
// requests) and homogeneous (all small) workloads correctly.
//
// Why a separate scorer instead of folding into BalancedAlloc:
//
//	BalancedAlloc says: "pick the host with most headroom on the binder"
//	BestFit says:       "for big requests, pick the host where the fit
//	                     is tightest, even if that host has less total
//	                     headroom"
//
// These goals can conflict — a 60 GiB-mem request placed on the
// emptiest host wastes that host's remaining capacity, but the same
// request placed on a moderately-loaded host fills the gap perfectly.
// BestFit pulls toward tight fits; BalancedAlloc pulls toward
// dispersed load. Their weighted sum produces a hybrid that:
//   - on small requests: BestFit returns neutral (50) so balanced wins
//   - on big requests: BestFit dominates with a high signal so
//     placement lands on a host that fills snugly
//
// Threshold for "big" is 20% of the host's effective limit in ANY
// dimension. Below that, the request is "small" and we don't intervene.
//
// Backward-compat: legacy hosts (CPUCount=0, DiskTotalMib=0) score by
// memory only. Returns 0 when the request wouldn't fit at all
// (admission filter will reject too, but be defensive).
type BestFitScorer struct{}

func (BestFitScorer) Name() string { return "best_fit" }

// Weight 15 — between BalancedAlloc (20) and LeastUsedPct (10). For
// small requests this scorer is a no-op (returns neutral 50); for big
// requests it tilts the decision toward tight-fit hosts to avoid
// memory/disk fragmentation. Operators can tune the weight if their
// workload is more mixed-size than ours.
func (BestFitScorer) Weight() int { return 15 }

// bigDimThreshold is the request-to-host-limit ratio above which a
// request is considered "big" in that dimension. 20% is a
// conservative middle ground — typical sandbox shapes (1 GiB mem
// on 120 GiB hosts = 0.8%) stay below, while custom large shapes
// (60 GiB disk on 936 GiB hosts = 6.4%) approach it, and very large
// requests (32 GiB mem) blow past it.
const bigDimThreshold = 0.20

func (BestFitScorer) Score(req *framework.Request, h *models.Host) int {
	if h == nil {
		return 0
	}

	// Track the "biggest" dimension by request-to-limit ratio, and
	// what that dim's snugness would be (snug = host-becomes-full).
	// We use the binder-of-this-request dim, not the binder-of-host —
	// what matters for fragmentation is which dim THIS req fills the
	// most.
	bestSnugness := 0.0
	anyBigDim := false
	anyDim := false

	// Memory dimension
	if h.MemCapacityMib > 0 {
		factor := h.MemOvercommitX10
		if factor <= 0 {
			factor = DefaultMemOvercommitX10
		}
		limit := h.MemCapacityMib * factor / 10
		reservedMem := req.ReservedMemoryMiB()
		if limit > 0 && reservedMem > 0 {
			anyDim = true
			reqFrac := float64(reservedMem) / float64(limit)
			// Wouldn't fit at all — defensive.
			postUsed := h.InUseMib + reservedMem
			if postUsed > limit {
				return 0
			}
			snugness := float64(postUsed) / float64(limit)
			if reqFrac >= bigDimThreshold {
				anyBigDim = true
				if snugness > bestSnugness {
					bestSnugness = snugness
				}
			}
		}
	}

	// CPU dimension
	if h.CPUCount > 0 {
		factor := h.CPUOvercommitX10
		if factor <= 0 {
			factor = DefaultCPUOvercommitX10
		}
		limit := h.CPUCount * factor / 10
		if limit > 0 && req.VCPU > 0 {
			anyDim = true
			reqFrac := float64(req.VCPU) / float64(limit)
			postUsed := h.VCPUInUse + req.VCPU
			if postUsed > limit {
				return 0
			}
			snugness := float64(postUsed) / float64(limit)
			if reqFrac >= bigDimThreshold {
				anyBigDim = true
				if snugness > bestSnugness {
					bestSnugness = snugness
				}
			}
		}
	}

	// Disk dimension
	if h.DiskTotalMib > 0 {
		limit := DiskCommitLimitMiB(h)
		if limit > 0 && req.DiskMiB > 0 {
			anyDim = true
			reqFrac := float64(req.DiskMiB) / float64(limit)
			postUsed := h.DiskInUseMib + req.DiskMiB
			if postUsed > limit {
				return 0
			}
			snugness := float64(postUsed) / float64(limit)
			if reqFrac >= bigDimThreshold {
				anyBigDim = true
				if snugness > bestSnugness {
					bestSnugness = snugness
				}
			}
		}
	}

	// No usable dimension data — defensive.
	if !anyDim {
		return 0
	}

	// Small request in every dim → neutral. Balanced decides.
	if !anyBigDim {
		return 50
	}

	// Snugness in [0,1]. Higher = tighter fit = better packing.
	// Map to 0..100 score.
	if bestSnugness < 0 {
		bestSnugness = 0
	}
	if bestSnugness > 1 {
		bestSnugness = 1
	}
	score := int(bestSnugness * 100)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}
