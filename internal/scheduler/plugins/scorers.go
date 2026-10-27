package plugins

import (
	"math/rand/v2"

	"github.com/NodeOps-app/sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/sandbox/models"
)

// LeastUsedPctScorer prefers hosts with a lower used-memory percentage.
// score = 100 - int(used/capacity * 100). Mirrors the old Pick's primary
// sort key (least percent used first) under "higher score wins".
type LeastUsedPctScorer struct{}

func (LeastUsedPctScorer) Name() string { return "least_used_pct" }
func (LeastUsedPctScorer) Weight() int  { return 10 }
func (LeastUsedPctScorer) Score(_ *framework.Request, h *models.Host) int {
	if h.MemCapacityMib <= 0 {
		return 0
	}
	pct := float64(h.InUseMib) / float64(h.MemCapacityMib) * 100.0
	score := 100 - int(pct)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

// FewestVMsScorer is the old tie-breaker — hosts running fewer VMs win.
// Mapped to a 0..100 score so the framework's weighted sum still works.
// Saturates at 100 below the cliff; weight 1 ensures it only matters when
// LeastUsedPct ties.
type FewestVMsScorer struct{}

func (FewestVMsScorer) Name() string { return "fewest_vms" }
func (FewestVMsScorer) Weight() int  { return 1 }
func (FewestVMsScorer) Score(_ *framework.Request, h *models.Host) int {
	score := 100 - h.VMCount
	if score < 0 {
		score = 0
	}
	return score
}

// RandomScorer adds entropy as the final tie-breaker. Pipeline already
// randomises picks among hosts tied at the maximum score, but a low-weight
// random scorer ensures that wide ties (e.g., empty fleet) get spread over
// time even when the upstream sort is stable.
type RandomScorer struct{}

func (RandomScorer) Name() string { return "random" }
func (RandomScorer) Weight() int  { return 1 }
func (RandomScorer) Score(_ *framework.Request, _ *models.Host) int {
	return rand.IntN(100)
}

// SpreadScorer biases against hosts that already have many in-flight
// reservations in this hydrate window. Without it, every concurrent
// decision sees the same stale `InUseMib` from the last hydrate tick
// and piles onto the same most-free host until hydrate catches up —
// the bug that caused our 500-burst test to dump 384 sandboxes on a
// single host. With it, the i-th decision in a tight burst sees the
// (i-1)-th decision's host as "less attractive" and rotates to the
// next, giving an effective round-robin.
//
// Score: 100 - 2*pending, clamped to 0. The 2-per-pending decay keeps
// the score differentiating up to 50 pending; with a 10× weight
// multiplier vs LeastUsedPct, a 5-VM-pending gap between two hosts
// (score 90 vs 100 here, weighted ×10 = 100 point gap in aggregate)
// dominates any natural memory-pct variation between hosts. Past 50
// pending all hosts saturate at 0 and LeastUsedPct decides — but at
// that point the burst is so heavy that perfect distribution barely
// matters compared to host-side spawn throughput.
//
// PendingFn is injected after pipeline build (see scheduler.NewInstance);
// nil means "no in-mem reservations available" and the scorer returns
// 100 for everyone (no influence on ranking).
type SpreadScorer struct {
	PendingFn func(hostID string) int
	Wt        int
}

func (s *SpreadScorer) Name() string { return "spread" }
func (s *SpreadScorer) Weight() int {
	if s.Wt > 0 {
		return s.Wt
	}
	return 100 // 10× LeastUsedPct's 10, so spread dominates under burst
}
func (s *SpreadScorer) Score(_ *framework.Request, h *models.Host) int {
	if s.PendingFn == nil {
		return 100
	}
	pending := s.PendingFn(h.ID)
	score := 100 - 2*pending
	if score < 0 {
		score = 0
	}
	return score
}

// RegionScorer rewards hosts whose region matches the request. With
// RegionFilter installed (strict) this is essentially redundant — every
// candidate already matches — but kept as a defensive tiebreaker if
// the filter is ever swapped for a soft variant. Score: 100 on match,
// 0 otherwise.
type RegionScorer struct{ Wt int }

func (s RegionScorer) Name() string { return "region_match" }
func (s RegionScorer) Weight() int  { return s.Wt }
func (s RegionScorer) Score(req *framework.Request, h *models.Host) int {
	if req.Region != "" && h.Region == req.Region {
		return 100
	}
	return 0
}
