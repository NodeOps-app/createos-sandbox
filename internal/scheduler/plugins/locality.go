package plugins

import (
	"github.com/NodeOps-app/sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/sandbox/models"
)

// LocalityBaseWeight is the contribution-at-zero-utilization for a
// cached host. Configurable globally so operators can tune via env.
// Default 50 = at idle, locality contributes 50 score points; at
// 50% loaded → 25; at 90% loaded → 5; at full → 0. The taper is
// what avoids hot-spotting cached hosts under burst.
var LocalityBaseWeight = 50

// LocalityScorer is a soft preference for the host that originally
// paused a sandbox. score = LocalityBaseWeight × (1 − host.utilization)
// when host.id matches Request.CachedHostID; 0 otherwise. Hard
// filters still gate the candidate; this scorer only changes
// preference order among already-eligible hosts.
type LocalityScorer struct{}

func (LocalityScorer) Name() string { return "locality" }
func (LocalityScorer) Weight() int  { return 1 } // taper is in Score; weight stays 1

func (LocalityScorer) Score(req *framework.Request, h *models.Host) int {
	if req == nil || req.CachedHostID == "" || h == nil || h.ID != req.CachedHostID {
		return 0
	}
	if h.MemCapacityMib <= 0 {
		return 0
	}
	used := float64(h.InUseMib) / float64(h.MemCapacityMib)
	if used < 0 {
		used = 0
	}
	if used > 1 {
		used = 1
	}
	score := int(float64(LocalityBaseWeight) * (1.0 - used))
	if score < 0 {
		score = 0
	}
	return score
}

// ExcludeHostsFilter drops candidates that previously failed to
// resume this bundle. Used by the resume host-rotation logic so the
// scheduler doesn't keep picking the same broken host.
type ExcludeHostsFilter struct{}

func (ExcludeHostsFilter) Name() string { return "exclude_hosts" }

func (ExcludeHostsFilter) Filter(req *framework.Request, h *models.Host) (bool, string) {
	if req == nil || len(req.ExcludeHosts) == 0 || h == nil {
		return true, ""
	}
	for _, excluded := range req.ExcludeHosts {
		if excluded == h.ID {
			return false, "host previously failed to resume this sandbox"
		}
	}
	return true, ""
}
