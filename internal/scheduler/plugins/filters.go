// Package plugins contains the in-tree scheduler plugins that ship with
// createos. Filters and scorers preserve the exact behaviour of the
// previous monolithic Pick in internal/apiserver/scheduler.go; the InMem
// reserver replaces the in-memory delta map that used to live on Server.
package plugins

import (
	"fmt"
	"strings"

	"github.com/NodeOps-app/sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/sandbox/models"
)

// PendingCapFilter hard-rejects hosts that already have too many
// in-flight reservations. Together with SpreadScorer this gives the
// scheduler a graceful-degradation story under burst: SpreadScorer
// nudges placements away from busy hosts; PendingCapFilter says "stop,
// pick a different one." Above the cap on every host the scheduler
// returns no-capacity (503), letting clients back off instead of
// dumping into a host queue that's already 30s deep.
//
// PendingFn is wired up after pipeline build in scheduler.NewInstance
// (same pattern as SpreadScorer). When nil the filter is a no-op so a
// fresh registry with no reserver doesn't accidentally reject every
// host.
type PendingCapFilter struct {
	PendingFn func(hostID string) int
	Cap       int // 0 = no cap (filter passes everything)
}

func (f *PendingCapFilter) Name() string { return "pending_cap" }
func (f *PendingCapFilter) Filter(_ *framework.Request, h *models.Host) (bool, string) {
	if f.PendingFn == nil || f.Cap <= 0 {
		return true, ""
	}
	pending := f.PendingFn(h.ID)
	if pending >= f.Cap {
		return false, fmt.Sprintf("pending %d >= cap %d", pending, f.Cap)
	}
	return true, ""
}

// CapacityFilter rejects hosts that don't have enough free memory.
type CapacityFilter struct{}

func (CapacityFilter) Name() string { return "capacity" }
func (CapacityFilter) Filter(req *framework.Request, h *models.Host) (bool, string) {
	free := h.MemCapacityMib - h.InUseMib
	reserved := req.ReservedMemoryMiB()
	if free < reserved {
		return false, fmt.Sprintf("only %d MiB free, need %d", free, reserved)
	}
	return true, ""
}

// StatusFilter accepts only hosts whose status is models.HostStatusActive.
type StatusFilter struct{}

func (StatusFilter) Name() string { return "status" }
func (StatusFilter) Filter(_ *framework.Request, h *models.Host) (bool, string) {
	if h.Status != models.HostStatusActive {
		return false, "status=" + h.Status
	}
	return true, ""
}

// ScheduleEnabledFilter rejects hosts that the operator has explicitly
// cordoned via scheduling_disabled=true. Independent of StatusFilter —
// a host can be active-but-cordoned (drained then status flipped back)
// and remain unschedulable until the operator uncordons.
type ScheduleEnabledFilter struct{}

func (ScheduleEnabledFilter) Name() string { return "schedule_enabled" }
func (ScheduleEnabledFilter) Filter(_ *framework.Request, h *models.Host) (bool, string) {
	if h.SchedulingDisabled {
		return false, "scheduling_disabled (cordoned)"
	}
	return true, ""
}

// MaxVMsFilter rejects hosts that have hit their advertised MaxVMs ceiling.
// MaxVMs == 0 means "unlimited" and is preserved for legacy hosts.
type MaxVMsFilter struct{}

func (MaxVMsFilter) Name() string { return "maxvms" }
func (MaxVMsFilter) Filter(_ *framework.Request, h *models.Host) (bool, string) {
	if h.MaxVMs > 0 && h.VMCount >= h.MaxVMs {
		return false, fmt.Sprintf("at MaxVMs cap (%d)", h.MaxVMs)
	}
	return true, ""
}

// RootfsFilter rejects hosts that don't advertise the requested rootfs.
// Empty req.Rootfs matches any host. Hosts with an empty Rootfses list
// are legacy registrations and match every rootfs (HostRecord.HasRootfs
// already encodes this).
type RootfsFilter struct{}

func (RootfsFilter) Name() string { return "rootfs" }
func (RootfsFilter) Filter(req *framework.Request, h *models.Host) (bool, string) {
	if req.Rootfs == "" {
		return true, ""
	}
	// Templates (tpl_<ulid>) are lazy-fetched: every host can fetch the
	// ext4 from R2 on first use. Don't reject hosts that don't yet have
	// the template cached — TemplateAvailability scorer biases placement
	// toward warm hosts but cold hosts remain eligible. See DESIGN/templates.md.
	if strings.HasPrefix(req.Rootfs, models.TemplateIDPrefix) {
		return true, ""
	}
	if !h.HasRootfs(req.Rootfs) {
		return false, fmt.Sprintf("does not advertise rootfs %q", req.Rootfs)
	}
	return true, ""
}

// LabelSelectorFilter implements k8s NodeSelector-style equality matching.
// Every label in the request's selector must match a label on the host
// (same key, same value). Empty selector matches every host. A host that
// has extra labels not mentioned in the selector is fine.
type LabelSelectorFilter struct{}

func (LabelSelectorFilter) Name() string { return "label_selector" }
func (LabelSelectorFilter) Filter(req *framework.Request, h *models.Host) (bool, string) {
	if len(req.Labels) == 0 {
		return true, ""
	}
	for k, want := range req.Labels {
		got, ok := h.Labels[k]
		if !ok {
			return false, fmt.Sprintf("label %q missing", k)
		}
		if got != want {
			return false, fmt.Sprintf("label %s=%s (want %q)", k, got, want)
		}
	}
	return true, ""
}

// HostPinFilter narrows the candidate set to a single host id when the
// request supplies one. No silent fallback — if the pinned host doesn't
// pass the other filters, nothing else is considered.
type HostPinFilter struct{}

func (HostPinFilter) Name() string { return "hostpin" }
func (HostPinFilter) Filter(req *framework.Request, h *models.Host) (bool, string) {
	if req.HostID == "" {
		return true, ""
	}
	if h.ID != req.HostID {
		return false, "not pinned host"
	}
	return true, ""
}

// RegionFilter accepts only hosts in the same region as the request.
// Strict: empty req.Region or mismatched host.Region rejects.
//
// Region validity (exists + not disabled) is checked separately at the
// scheduler entry point; this filter assumes a valid region and just
// pairs sandbox to host by name.
type RegionFilter struct{}

func (RegionFilter) Name() string { return "region" }
func (RegionFilter) Filter(req *framework.Request, h *models.Host) (bool, string) {
	if req.Region == "" {
		return false, "request has no region"
	}
	if h.Region != req.Region {
		return false, fmt.Sprintf("region mismatch (host=%s want=%s)", h.Region, req.Region)
	}
	return true, ""
}
