package plugins

import (
	"strings"

	"github.com/NodeOps-app/createos-sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// TemplateAvailabilityWeight is the score bonus for a locally cached template
// ext4. It reduces download work but does not override hard capacity filters
// or guarantee placement over the combined scores of other plugins.
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
