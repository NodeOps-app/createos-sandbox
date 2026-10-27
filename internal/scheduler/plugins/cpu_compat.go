package plugins

import (
	"github.com/NodeOps-app/sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/sandbox/models"
)

// CPUCompatFilter rejects candidate hosts whose CPU vendor differs from
// the source host's (the host that paused the sandbox). Cold-create
// requests have an empty SourceCPUVendor and pass through transparently.
//
// Why: firecracker bakes the source host's CPUID into vmstate at
// snapshot time. Resuming on a different vendor (AMD → Intel, e.g.)
// SIGILLs the guest the moment it touches an instruction the target
// CPU doesn't advertise (SHA-NI fast paths in curl, AVX-512 in numpy,
// etc.). Pinning the resume to the source vendor is the cleanest fix
// short of using a CPU template at create time — and our firecracker
// SDK (v1.0.0) only exposes Intel templates, so vendor pinning is the
// only working option for a mixed AMD+Intel fleet.
//
// Status: wired into plugins.DefaultPipelineSpec().Filters. Control
// populates framework.Request.SourceCPUVendor at resume-request build
// time (placementpolicy.BuildResumeScheduleRequest) from the row's cpu_vendor
// lineage, with the origin host's live vendor as a fallback.
type CPUCompatFilter struct{}

func (CPUCompatFilter) Name() string { return "cpu_compat" }

func (CPUCompatFilter) Filter(req *framework.Request, h *models.Host) (bool, string) {
	if req == nil || req.SourceCPUVendor == "" || h == nil {
		// Cold-create or pre-vendor-capture row → no vendor constraint.
		return true, ""
	}
	if h.CPUVendor == "" {
		// Candidate host hasn't reported its vendor yet (just registered,
		// running pre-2026-05-22 code, etc.). Conservative: refuse —
		// better a clear "no compatible host" 503 than a silent SIGILL
		// after resume.
		return false, "candidate host has no cpu_vendor recorded"
	}
	if h.CPUVendor != req.SourceCPUVendor {
		return false, "cpu vendor mismatch: source=" + req.SourceCPUVendor + " candidate=" + h.CPUVendor
	}
	return true, ""
}

// CPUCompatScorer is a SOFT preference for same-vendor hosts on
// non-resume schedules. Returns a fixed bonus when source and candidate
// vendors match; zero otherwise. Useful as a tie-breaker so that even
// fresh creates land on hosts whose vendor matches the user's other
// sandboxes (locality of future pause/resume options).
//
// Status: NOT YET in the default pipeline; see CPUCompatFilter.
type CPUCompatScorer struct {
	// Wt controls how much a vendor match contributes. Default 1 keeps
	// it as a tie-breaker; raise to outrank locality if you want fresh
	// creates to actively avoid mixed-vendor scenarios.
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
