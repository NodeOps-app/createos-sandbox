// Package framework defines the pluggable scheduler pipeline: Filter,
// Scorer, Reserver. Built-in plugins live in
// github.com/NodeOps-app/createos-sandbox/internal/scheduler/plugins; this package contains only
// the abstract pipeline machinery.
package framework

import "github.com/NodeOps-app/createos-sandbox/internal/vmcapacity"

// Request carries resource requirements, hard placement constraints, and
// locality hints for the scheduling pipeline. Labels are host selectors.
type Request struct {
	SnapshotID string // owner-authorized reusable snapshot, used only for cache locality
	Shape      string
	Rootfs     string
	MemMiB     int
	// VCPU and DiskMiB drive the multi-dimensional admission filter.
	// Caller (control plane) populates these from the shape catalog
	// at /v1/schedule time. 0 means "don't filter on this dimension"
	// — kept for backwards compatibility with old callers; the filter
	// degrades gracefully to mem-only when not set.
	VCPU    int
	DiskMiB int64
	HostID  string // pin; "" = any
	Region  string // required; scheduler rejects placement if region missing/disabled
	Labels  map[string]string
	// PreferredHostIDs is a soft first-choice tier. Hard filters still apply,
	// with fallback to other eligible regional hosts when reservation fails.
	PreferredHostIDs []string

	// Resume-only: soft preference for the host that paused this
	// sandbox (locality cache). Empty for non-resume schedules.
	// LocalityScorer applies a utilization-scaled bonus when a
	// candidate host's id matches CachedHostID; hard filters still
	// gate the candidate.
	CachedHostID string

	// Resume-only: hosts that have already failed to resume this
	// sandbox bundle. ExcludeHostsFilter drops them from the
	// candidate set. Empty on create or fresh resume.
	ExcludeHosts []string

	// Source snapshot CPU vendor for resume or full-snapshot restore. Empty
	// on cold creates. The default filter rejects unknown or different
	// destination vendors; a match does not prove full CPU compatibility.
	SourceCPUVendor string
}

// ReservedMemoryMiB returns the physical host memory this VM consumes,
// including Firecracker overhead. MemMiB remains guest-visible memory.
func (r *Request) ReservedMemoryMiB() int {
	if r == nil {
		return 0
	}
	return vmcapacity.ReservedMemoryMiB(r.Shape, r.MemMiB)
}

// Decision is what a successful Schedule returns. Reservation tracking is
// keyed by the sandbox id the caller passed to Schedule, so Decision
// doesn't carry a token.
type Decision struct {
	HostID string
	Score  int
}
