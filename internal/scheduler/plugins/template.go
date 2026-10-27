package plugins

import (
	"strings"

	"github.com/NodeOps-app/sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/sandbox/models"
)

// TemplateAvailabilityWeight is the score boost a host gets when it has
// the requested template's ext4 already cached locally. The big latency
// cliff is "ext4 on disk vs not": a cold host pays a ~10s WAN download
// before its first sandbox boots; a warm host boots in ~50ms (snapshot)
// or ~1.7s (cold-boot). Weighting at 25 keeps it dominant over the
// least_used_pct (max 100) tie-breaker but doesn't completely override
// capacity-based placement when warm hosts are full.
var TemplateAvailabilityWeight = 25

// TemplateAvailabilityScorer biases placement toward hosts that already
// have the requested template's ext4 cached. The scorer is a no-op for
// non-template requests (rootfs without "tpl_" prefix). Cold hosts
// still pass the filter chain — they just lose the score tie.
type TemplateAvailabilityScorer struct{}

func (TemplateAvailabilityScorer) Name() string { return "template_availability" }
func (TemplateAvailabilityScorer) Weight() int  { return 1 }

func (TemplateAvailabilityScorer) Score(req *framework.Request, h *models.Host) int {
	if req == nil || h == nil {
		return 0
	}
	if !strings.HasPrefix(req.Rootfs, models.TemplateIDPrefix) {
		return 0
	}
	if !h.HasCachedTemplate(req.Rootfs) {
		return 0
	}
	return TemplateAvailabilityWeight
}
