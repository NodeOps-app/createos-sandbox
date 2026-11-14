package plugins

import (
	"github.com/NodeOps-app/createos-sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// BestFitScorer favors tighter fits for requests using at least 20% of a
// host's effective limit in a dimension. It scores the highest post-placement
// utilization among qualifying dimensions, or 50 when all are small.
// Missing dimensions are skipped; a request exceeding a checked limit scores
// zero. Other scorers still contribute to the final placement decision.
type BestFitScorer struct{}

func (BestFitScorer) Name() string { return "best_fit" }

// Weight 15 — between BalancedAlloc (20) and LeastUsedPct (10). For
// small requests this scorer is a no-op (returns neutral 50); for big
// requests it tilts the decision toward tight-fit hosts to avoid
// memory/disk fragmentation. Operators can tune the weight if their
// workload is more mixed-size than ours.
func (BestFitScorer) Weight() int { return 15 }

// bigDimThreshold is the minimum request-to-limit ratio for a dimension
// to contribute to the tight-fit score.
const bigDimThreshold = 0.20

func (BestFitScorer) Score(req *framework.Request, h *models.Host) int {
	if h == nil {
		return 0
	}

	// Track maximum post-placement utilization across all dimensions
	// where the request reaches the threshold.
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

	// Small request in every dimension: other scorers determine placement.
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
