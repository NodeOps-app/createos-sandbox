package plugins

import (
	"math/rand/v2"

	"github.com/NodeOps-app/createos-sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/createos-sandbox/models"
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

// FewestVMsScorer favors hosts with fewer VMs using max(0, 100-VMCount).
// Its weighted contribution can affect rankings even without a tie in other
// scorers; it is not a strict tie-breaker.
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

// RandomScorer adds a random 0..99 contribution to the weighted score.
// It can change rankings beyond ties and is not enabled by default.
type RandomScorer struct{}

func (RandomScorer) Name() string { return "random" }
func (RandomScorer) Weight() int  { return 1 }
func (RandomScorer) Score(_ *framework.Request, _ *models.Host) int {
	return rand.IntN(100)
}

// SpreadScorer favors hosts with fewer pending reservations between hydration
// ticks. Its score is max(0, 100-2*pending), with default weight 100.
// Other scorers still contribute; this does not enforce round-robin placement.
// PendingFn is injected by NewInstance. If nil, every host scores 100.
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
