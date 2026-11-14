package plugins

import (
	"github.com/NodeOps-app/createos-sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// CPUCompatFilter requires a matching destination CPU vendor when the
// request carries the source snapshot's vendor. Empty source vendors impose
// no constraint. Matching vendors alone do not prove restore compatibility:
// CPU features, TSC scaling, KVM state, and the snapshot runtime still matter.
type CPUCompatFilter struct{}

func (CPUCompatFilter) Name() string { return "cpu_compat" }

func (CPUCompatFilter) Filter(req *framework.Request, h *models.Host) (bool, string) {
	if req == nil || req.SourceCPUVendor == "" || h == nil {
		// Cold-create or pre-vendor-capture row → no vendor constraint.
		return true, ""
	}
	if h.CPUVendor == "" {
		// Fail closed when the destination has not reported its vendor.
		return false, "candidate host has no cpu_vendor recorded"
	}
	if h.CPUVendor != req.SourceCPUVendor {
		return false, "cpu vendor mismatch: source=" + req.SourceCPUVendor + " candidate=" + h.CPUVendor
	}
	return true, ""
}

// CPUCompatScorer adds a soft preference for a matching SourceCPUVendor.
// It returns zero when the request omits the vendor and does not inspect the
// user's other sandboxes. It is not part of the default pipeline.
type CPUCompatScorer struct {
	// Wt scales the vendor-match score; nonpositive values use weight 1.
	Wt int
}

func (CPUCompatScorer) Name() string { return "cpu_compat" }

func (s CPUCompatScorer) Weight() int {
	if s.Wt <= 0 {
		return 1
	}
	return s.Wt
}

func (CPUCompatScorer) Score(req *framework.Request, h *models.Host) int {
	if req == nil || req.SourceCPUVendor == "" || h == nil {
		return 0
	}
	if h.CPUVendor != "" && h.CPUVendor == req.SourceCPUVendor {
		return 10
	}
	return 0
}
