// Package framework defines the pluggable scheduler pipeline: Filter,
// Scorer, Reserver. Built-in plugins live in
// github.com/NodeOps-app/sandbox/internal/scheduler/plugins; this package contains only
// the abstract pipeline machinery.
package framework

import "github.com/NodeOps-app/sandbox/internal/vmcapacity"

// Request is the placement request fed to the pipeline. Mirrors today's
// Pick(host, mem, rootfs) plus a hint for host-pinning and a future-use
// label map.
type Request struct {
	Shape  string
	Rootfs string
	MemMiB int
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

	// Resume-only: CPU vendor of the host that took the snapshot.
	// Consumed by the cpu_compat filter (wired into the default
	// pipeline). When set, the filter rejects any candidate whose
	// CPUVendor differs — required because firecracker bakes source
	// CPUID into vmstate and resuming on a different vendor SIGILLs the
	// guest. Control populates it from the row's cpu_vendor lineage
	// (origin host as fallback) before calling /v1/schedule. "" on
	// cold-create.
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
