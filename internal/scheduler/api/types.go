// Package api defines the wire types exchanged between the control plane
// and the scheduler service. Importing this package gives clients full
// type safety without pulling in the scheduler's Fiber server or framework.
package api

import "github.com/NodeOps-app/createos-sandbox/internal/proto"

// HealthzResponse is the body of GET /healthz — process liveness.
type HealthzResponse struct {
	Up bool `json:"up"`
}

// ReadyzResponse is the body of GET /readyz — leadership + warming state.
//
// State is one of:
//   - "follower"   — not the active leader
//   - "hydrating"  — leader, loading hosts + capacity from DB
//   - "warming"    — leader, initial hydration attempted, waiting for the warm-up timer
//   - "leader_active" — leader, accepting Schedule traffic
//   - "lost_lock"  — was leader, lock released, next acquire pending
type ReadyzResponse struct {
	Ready    bool   `json:"ready"`
	State    string `json:"state"`
	Reason   string `json:"reason,omitempty"`
	Epoch    int64  `json:"epoch"`
	Leader   string `json:"leader,omitempty"`
	UptimeMs int64  `json:"uptime_ms"`
}

// ScheduleRequest is the body of POST /v1/schedule. SandboxID is the
// durable id of the sandbox being created or resumed; the scheduler keys
// its in-memory reservation on it.
type ScheduleRequest struct {
	SnapshotID string `json:"snapshot_id,omitempty"`
	SandboxID  string `json:"sandbox_id"`
	Shape      string `json:"shape"`
	Rootfs     string `json:"rootfs,omitempty"`
	MemMiB     int    `json:"mem_mib"`
	// VCPU + DiskMiB drive multi-dimensional admission. Empty/zero =
	// "skip this dimension" (kept for backwards compat with callers
	// that haven't been updated yet).
	VCPU    int               `json:"vcpu,omitempty"`
	DiskMiB int64             `json:"disk_mib,omitempty"`
	HostID  string            `json:"host_id,omitempty"` // pin
	Region  string            `json:"region"`            // required; scheduler 4xxs if region missing/disabled
	Labels  map[string]string `json:"labels,omitempty"`
	// PreferredHostIDs is trusted control-plane policy, not a public API
	// field. All hard filters still apply.
	PreferredHostIDs []string `json:"preferred_host_ids,omitempty"`

	// Resume-only: soft preference for the host that paused this
	// sandbox (locality cache hint). Empty for non-resume schedules.
	CachedHostID string `json:"cached_host_id,omitempty"`

	// Resume-only: hosts that previously failed to resume this
	// bundle. Scheduler excludes them from the candidate pool.
	ExcludeHosts []string `json:"exclude_hosts,omitempty"`

	// Source snapshot CPU vendor for resume or full-snapshot restore.
	// A same-vendor destination is required when set, but other restore
	// compatibility constraints still apply. Empty on cold creates.
	SourceCPUVendor string `json:"source_cpu_vendor,omitempty"`
}

// ScheduleResponse is the body of a successful POST /v1/schedule.
// HostAddr is included so the control plane can forward the create RPC
// without a second `repo.GetHost` lookup. No token — the request's
// SandboxID serves that purpose.
type ScheduleResponse struct {
	SnapshotCache *proto.SnapshotCachePolicy `json:"snapshot_cache,omitempty"`
	HostID        string                     `json:"host_id"`
	HostAddr      string                     `json:"host_addr"`
	Epoch         int64                      `json:"epoch"`
}

const ReasonNoCapacity = "no_capacity"

// ErrorResponse is carried in the data field of a JSend fail response.
// Reason distinguishes deterministic capacity rejection from service failures.
type ErrorResponse struct {
	Reason string `json:"reason,omitempty"`
	Error  string `json:"error"`
	Code   int    `json:"code"`
}

// CapacityResponse is the body of GET /v1/capacity — operator-visible
// snapshot of per-host committed-vs-limit across the 4 admission
// dimensions. Built from the scheduler's hostCache after the latest
// hydrate. Sums reflect live sandboxes only (no pending reservations).
type CapacityResponse struct {
	Hosts []HostCapacity `json:"hosts"`
}

// HostCapacity is one host's slice of CapacityResponse.
type HostCapacity struct {
	ID     string `json:"id"`
	Addr   string `json:"addr"`
	Status string `json:"status"`
	Region string `json:"region"`

	CPU  DimensionUsage `json:"cpu"`
	Mem  DimensionUsage `json:"mem"`
	Disk DimensionUsage `json:"disk"`
	IPs  DimensionUsage `json:"ips"` // max_vms-based; effectively 1.0× cap (kernel-limited)
}

// DimensionUsage reports committed resources against the effective limit.
// CPU/memory/IP limits use physical capacity times the factor; disk also
// subtracts operational headroom. Util is committed/limit and can exceed 1.
// OverX10 contains the resolved factor in tenths (20 = 2x).
type DimensionUsage struct {
	Committed int64   `json:"committed"`
	Physical  int64   `json:"physical"`
	Limit     int64   `json:"limit"`
	Util      float64 `json:"util"`
	OverX10   int     `json:"over_x10"`
}
