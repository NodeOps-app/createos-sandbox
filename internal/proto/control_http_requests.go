package proto

import (
	"encoding/json"
	"time"
)

// Shared JSON request bodies for control and host handlers. Parsing and
// authorization remain the receiving handler's responsibility; some handlers
// use strict JSON decoding rather than Fiber BodyParser. Internal-only fields
// in shared types must be rejected at the public boundary.

// ── Public sandbox API ────────────────────────────────────────────────

// SnapshotCreateReq contains only caller-controlled capture options. The source
// sandbox comes from the route; ownership, placement and sizing come from its row.
type SnapshotCreateReq struct {
	Name *string `json:"name,omitempty"` // optional, non-unique display label
	Type string  `json:"type"`           // "disk" or "full"
}

// NetworkEntry is one element of CreateReq.Networks.
type NetworkEntry struct {
	ID string `json:"id"` // network name or net_<ulid>
}

// SnapshotCachePolicy is scheduler-owned disk headroom, never caller input.
// Budget consumes part of the existing safety reserve; FreeFloor preserves the
// remaining safety reserve and all transient workspace. Values are in MiB.
type SnapshotCachePolicy struct {
	BudgetMiB    int64 `json:"budget_mib"`
	FreeFloorMiB int64 `json:"free_floor_mib"`
}

// CreateReq is the request body for POST /v1/sandboxes. The sandbox id
// is NEVER taken from the user — control mints it server-side and passes
// it to the host via the X-Sandbox-ID header on the forwarded request.
type CreateReq struct {
	// SnapshotCache is populated only by control from the scheduler decision.
	SnapshotCache *SnapshotCachePolicy `json:"snapshot_cache,omitempty"`

	// SnapshotID selects an owned, ready reusable snapshot instead of rootfs.
	// Omitted shape and disk_mib inherit the snapshot's captured configuration.
	SnapshotID *string `json:"snapshot_id,omitempty"`

	Shape  string  `json:"shape"`  // catalog shape; defaults to captured shape with snapshot_id
	Rootfs *string `json:"rootfs"` // required without snapshot_id; mutually exclusive with it

	// Name is the user-facing VM name, unique per user among non-terminal
	// sandboxes. Empty/omitted → control auto-generates a Docker-style
	// "<adjective>-<surname>-<suffix>" name. The sandbox id stays the only
	// addressing handle; name is purely a label/hostname/DNS-name.
	Name *string `json:"name,omitempty"`

	// Labels are user-defined metadata used to organize and filter sandboxes.
	// Control validates at most 100 key/value pairs and persists them without
	// forwarding any scheduling meaning to the host.
	Labels map[string]string `json:"labels,omitempty"`

	DiskMib    int64    `json:"disk_mib,omitempty"`    // optional override; 0 = shape's default
	Egress     []string `json:"egress,omitempty"`      // allowlist; empty/nil = allow all
	SSHPubkeys []string `json:"ssh_pubkeys,omitempty"` // authorized pubkeys for SSH gateway access

	// NodeSelector pins placement to hosts whose labels match every entry
	// here (k8s NodeSelector semantics). Empty/missing matches any host.
	// Example: {"gpu":"nvidia-l4","region":"nyc1"}
	NodeSelector map[string]string `json:"node_selector,omitempty"`

	// BandwidthQuotaBytes is NOT settable at create. The field stays on
	// the request type for backwards-compat decoding; control rejects
	// any non-zero value (400) and stamps the cluster default
	// (--default-bandwidth-quota-bytes, default 50 GiB) onto every new
	// sandbox. To grow the budget post-create, call
	// POST /v1/sandboxes/:id/bandwidth/recharge.
	BandwidthQuotaBytes int64 `json:"bandwidth_quota_bytes,omitempty"`

	// Region pins the sandbox to a region. Optional — when omitted the
	// local region is tried first; operator-enabled capacity fallback may select
	// the other region. An explicit region disables capacity fallback.
	Region string `json:"region,omitempty"`

	// HostID pins the sandbox to a specific host by id (hostname). Empty =
	// let the scheduler pick. When set, the scheduler still validates
	// capacity and rootfs availability and returns 503 if the host can't
	// accept the VM — it never silently falls back to a different host.
	HostID string `json:"host_id,omitempty"`

	// IngressEnabled, when true, opts the sandbox into HTTP ingress
	// (<ulid>-<port>.<DomainSuffix> reaches the VM). Pointer so the
	// API can distinguish unset (default false) from explicit false.
	IngressEnabled *bool `json:"ingress_enabled,omitempty"`

	// Networks is the list of overlay networks to join at create time.
	// Each entry is {id: "<name|net-ulid>"}. Membership is pure metadata
	// — no extra IP or veth per entry; the sandbox's name is its
	// in-network hostname.
	Networks []NetworkEntry `json:"networks,omitempty"`

	// Envs is a server-side env-var map persisted on the sandbox.
	// Every /exec call against this sandbox injects these vars into
	// the spawned process inside the VM (merged after os.Environ() so
	// user vars win). Validation happens in control: max 64 entries,
	// keys must match ^[A-Za-z_][A-Za-z0-9_]*$, no NUL in values,
	// values <= 4096 bytes, total JSON <= 64 KiB.
	Envs map[string]string `json:"envs,omitempty"`

	// Disks attaches one or more user-registered disks at create time.
	// Each entry references a `disk_<ulid>` (or user-scoped name) and
	// the absolute mount path inside the guest. Disks are mounted by
	// the agent at boot via the agent's MMDS-driven mount loop.
	Disks []DiskAttachment `json:"disks,omitempty"`

	// DisksResolved is the **internal** form, populated by control after
	// it validates ownership and decrypts credentials. Never set by the
	// user — control strips Disks and writes this on the forwarded body
	// before sending to the host. Hosts read this field only.
	DisksResolved []ResolvedDisk `json:"disks_resolved,omitempty"`

	// AutoPauseAfterSeconds, when set, enables idle-pause: the sandbox is
	// automatically paused after this many seconds with no detected activity.
	// Valid range: 60–86400 (1 min – 24 h). Null/omitted = disabled.
	AutoPauseAfterSeconds *int `json:"auto_pause_after_seconds,omitempty"`
}

// DiskAttachment is one element of CreateReq.Disks — the user-facing
// shape (no credentials, just a reference).
type DiskAttachment struct {
	DiskID    string `json:"disk_id"`    // disk_<ulid> OR user-scoped name
	MountPath string `json:"mount_path"` // absolute path inside the VM, e.g. /mnt/data
	// SubPath is an optional sub-folder within the bucket to expose at
	// MountPath. Empty = mount the bucket root. Non-empty must not start
	// with '/', must not contain '..'. When set, the guest sees only
	// files under that prefix.
	SubPath string `json:"sub_path,omitempty"`
}

// ResolvedDisk is the host-bound form of one disk attachment. Credentials
// are plaintext (just decrypted by control); the field exists only on the
// in-flight forwarded request and is never persisted or echoed back.
type ResolvedDisk struct {
	DiskID      string          `json:"disk_id"`
	Kind        string          `json:"kind"`
	Config      json.RawMessage `json:"config"`
	Credentials json.RawMessage `json:"credentials"`
	MountPath   string          `json:"mount_path"`
	SubPath     string          `json:"sub_path,omitempty"`
}

// SetEgressReq is the request body for PUT /v1/sandboxes/:id/egress.
// rules == nil (i.e. field missing) is treated as allow-all; an explicit
// empty array is also allow-all.
type SetEgressReq struct {
	Egress []string `json:"egress"`
}

// RechargeReq is the request body for POST /v1/sandboxes/:id/bandwidth/recharge.
type RechargeReq struct {
	AddBytes int64 `json:"add_bytes"`
}

// ── Disks ─────────────────────────────────────────────────────────────

// ── Admin API ─────────────────────────────────────────────────────────

// ── Templates ─────────────────────────────────────────────────────────

// ── Control: host registration / heartbeat ────────────────────────────

// ControlHostRegisterReq is the body for POST /v1/internal/hosts/register —
// sent by the host's hostagent, parsed by control.
type ControlHostRegisterReq struct {
	ID             string            `json:"id"`
	Addr           string            `json:"addr"`
	MemCapacityMib int               `json:"mem_capacity_mib"`
	CPUCount       int               `json:"cpu_count,omitempty"`
	DiskTotalMib   int64             `json:"disk_total_mib,omitempty"`
	DiskUsedMib    int64             `json:"disk_used_mib,omitempty"`
	MaxVMs         int               `json:"max_vms,omitempty"`
	Rootfses       []string          `json:"rootfses,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	// PublicKey is the host's Ed25519 verify key (32 bytes).
	PublicKey []byte `json:"public_key,omitempty"`
	// UnderlayIP is the host's public underlay address. Used as the
	// WireGuard endpoint by peer hosts to send encrypted overlay traffic.
	UnderlayIP string `json:"underlay_ip,omitempty"`
	// Region pins the host to one regions.name. Required at first
	// register; control refuses to add the host if region is missing
	// or disabled. Stamped to hosts.region.
	Region string `json:"region"`
	// CPU identity from /proc/cpuinfo. The default scheduler pipeline uses
	// CPUVendor to reject mismatched snapshot destinations. Matching vendors
	// alone do not establish CPU/TSC/KVM restore compatibility.
	CPUVendor string `json:"cpu_vendor,omitempty"` // GenuineIntel | AuthenticAMD | ...
	CPUFamily string `json:"cpu_family,omitempty"` // family:model:stepping
	// WGPublicKey is the host's WireGuard mesh public key (32-byte
	// Curve25519). Required for hosts participating in the WG mesh.
	WGPublicKey []byte `json:"wg_public_key,omitempty"`

	// Role distinguishes "compute" hosts (run VMs) from "relay" hosts
	// (terminate user-device WG and forward into the mesh). Empty/absent
	// defaults to "compute" for backward compat with existing serve
	// registrations. Stamped on hosts.role at register time.
	Role string `json:"role,omitempty"`

	// RelayDevicesPubkey is the WG pubkey for the relay's `wg-devices`
	// iface — the iface that terminates user-device tunnels. Distinct
	// from WGPublicKey (which is the wg-hosts mesh key). Only meaningful
	// when Role="relay"; ignored otherwise. The session-create handler
	// pulls this into the client wg-quick config so clients handshake
	// with the right key.
	RelayDevicesPubkey []byte `json:"relay_devices_pubkey,omitempty"`

	// Per-host oversubscription factors for the scheduler's multi-
	// dimensional admission. Integer 10ths (20 = 2.0×). 0 = use the
	// scheduler's defaults (cpu=80, mem=10, disk=20). Operators set
	// these in host config to match the host's hardware tier.
	CPUOvercommitX10  int `json:"cpu_overcommit_x10,omitempty"`
	MemOvercommitX10  int `json:"mem_overcommit_x10,omitempty"`
	DiskOvercommitX10 int `json:"disk_overcommit_x10,omitempty"`
}

// CachedSnapshot is an expiring locality hint, never proof of ownership or
// restore compatibility. Report only complete, verified artifact sets.
type CachedSnapshot struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}

const MaxCachedSnapshotHints = 256

// ControlHostHeartbeatReq is the body for POST /v1/internal/hosts/heartbeat.
type ControlHostHeartbeatReq struct {
	CachedSnapshots []CachedSnapshot `json:"cached_snapshots"`
	ID              string           `json:"id"`
	InUseMib        int              `json:"in_use_mib"`
	VMCount         int              `json:"vm_count"`
	Status          string           `json:"status,omitempty"`
	DiskUsedMib     int64            `json:"disk_used_mib,omitempty"`
}

// ── Control internal DB proxy — mutation bodies ───────────────────────
//
// Bodies parsed by control's /v1/internal/db/* handlers and sent by the
// host's controlclient.Client. One definition, both sides — they
// cannot drift.

// ControlMarkDestroyedReq — PATCH /v1/internal/db/sandboxes/:id/destroyed
type ControlMarkDestroyedReq struct {
	At   time.Time `json:"at"`
	Note *string   `json:"note,omitempty"`
}

// ControlMarkFailedReq — PATCH /v1/internal/db/sandboxes/:id/failed
type ControlMarkFailedReq struct {
	ErrText *string   `json:"err_text,omitempty"`
	At      time.Time `json:"at"`
}

// ControlMarkFailedFromCreatingCASReq — PATCH
// /v1/internal/db/sandboxes/:id/failed-from-creating. Used by host
// reconcile to atomically self-heal stuck 'creating' rows pinned to
// itself. HostID pins the CAS to the caller's own host so a buggy
// caller can't flip another host's row.
type ControlMarkFailedFromCreatingCASReq struct {
	HostID  string    `json:"host_id"`
	ErrText *string   `json:"err_text,omitempty"`
	At      time.Time `json:"at"`
}

// ControlMarkFailedFromCreatingCASResp — { flipped: true } when the
// CAS hit, { flipped: false } when status had already moved out from
// under us. Caller checks before doing local side-effects.
type ControlMarkFailedFromCreatingCASResp struct {
	Flipped bool `json:"flipped"`
}

// ControlSetSandboxHostReq — PATCH /v1/internal/db/sandboxes/:id/host
type ControlSetSandboxHostReq struct {
	HostID *string `json:"host_id,omitempty"`
}

// ControlSetSSHPubkeysReq — PATCH /v1/internal/db/sandboxes/:id/ssh-pubkeys
type ControlSetSSHPubkeysReq struct {
	Keys []string `json:"keys"`
}

// ControlSetEgressReq — PATCH /v1/internal/db/sandboxes/:id/egress
type ControlSetEgressReq struct {
	Rules []string `json:"rules"`
}

// ControlSetDiskMibReq — PATCH /v1/internal/db/sandboxes/:id/disk
type ControlSetDiskMibReq struct {
	DiskMib int64 `json:"disk_mib"`
}

// ControlSetRuntimeReq — PATCH /v1/internal/db/sandboxes/:id/runtime
type ControlSetRuntimeReq struct {
	APISock     *string `json:"api_sock,omitempty"`
	ContainerID *string `json:"container_id,omitempty"`
	FCPid       int     `json:"fc_pid"`
	OverlayPath *string `json:"overlay_path,omitempty"`
}

// ControlBandwidthValueReq carries one int64 — the bandwidth quota /
// used / ingress PATCH endpoints all share this body shape.
type ControlBandwidthValueReq struct {
	Value int64 `json:"value"`
}

// ControlBandwidthCappedReq — PATCH /v1/internal/db/sandboxes/:id/bandwidth/capped
type ControlBandwidthCappedReq struct {
	Value bool `json:"value"`
}

// ControlSetIngressEnabledReq — PATCH /v1/internal/db/sandboxes/:id/ingress
type ControlSetIngressEnabledReq struct {
	Enabled bool `json:"enabled"`
}

// ControlHeartbeatHostReq — PATCH /v1/internal/db/hosts/:id/heartbeat
type ControlHeartbeatHostReq struct {
	InUseMib    int       `json:"in_use_mib"`
	VMCount     int       `json:"vm_count"`
	Status      string    `json:"status"`
	DiskUsedMib int64     `json:"disk_used_mib,omitempty"`
	At          time.Time `json:"at"`
}

// ControlSetDiskStatusReq is the body for PATCH /v1/internal/db/sandboxes/:id/disks/:disk_id/status.
// Sent by the host's disk-status poller when an agent-reported value
// differs from the last-known DB row.
type ControlSetDiskStatusReq struct {
	MountPath string `json:"mount_path"`      // disambiguates when one disk is mounted at multiple paths
	Status    string `json:"status"`          // "pending" | "mounted" | "failed"
	Error     string `json:"error,omitempty"` // truncated to ~1 KiB upstream
}

// ── Control internal DB proxy — pause / resume / fork CAS bodies ──────

// ControlMarkPausingReq — POST /v1/internal/db/pause/mark-pausing
type ControlMarkPausingReq struct {
	ID string    `json:"id"`
	At time.Time `json:"at"`
}

// ControlMarkPausedReq — POST /v1/internal/db/pause/mark-paused. Reaching this
// endpoint means the complete snapshot bundle is already durable in storage.
type ControlMarkPausedReq struct {
	ID           string          `json:"id"`
	PausedAt     time.Time       `json:"paused_at"`
	URI          *string         `json:"uri,omitempty"`
	Manifest     json.RawMessage `json:"manifest"`
	CachedHostID *string         `json:"cached_host_id,omitempty"`
	CachedUntil  time.Time       `json:"cached_until"`
}

// ControlMarkPauseRolledBackReq — POST /v1/internal/db/pause/mark-rolled-back
type ControlMarkPauseRolledBackReq struct {
	ID  string    `json:"id"`
	Err *string   `json:"err,omitempty"`
	At  time.Time `json:"at"`
}

// ControlMarkResumedReq — POST /v1/internal/db/pause/mark-resumed
type ControlMarkResumedReq struct {
	ID          string    `json:"id"`
	IP          *string   `json:"ip,omitempty"`
	MAC         *string   `json:"mac,omitempty"`
	APISock     *string   `json:"api_sock,omitempty"`
	ContainerID *string   `json:"container_id,omitempty"`
	OverlayPath *string   `json:"overlay_path,omitempty"`
	FCPid       int       `json:"fc_pid"`
	RunningAt   time.Time `json:"running_at"`
	Host        string    `json:"host"`
}

// ControlMarkResumeFailedReq — POST /v1/internal/db/pause/mark-resume-failed
type ControlMarkResumeFailedReq struct {
	ID   string    `json:"id"`
	Host string    `json:"host"`
	Err  *string   `json:"err,omitempty"`
	At   time.Time `json:"at"`
}

// ControlIDReq is a bare id body — POST /v1/internal/db/pause/mark-destroying
type ControlIDReq struct {
	ID string `json:"id"`
}

// ControlClearLocalCacheReq — POST /v1/internal/db/pause/clear-local-cache
type ControlClearLocalCacheReq struct {
	ID   string `json:"id"`
	Host string `json:"host"`
}

// ControlLocalCacheStateResp is the least-privilege answer used by a host
// sweeping its local paused-snapshot directory. It intentionally exposes no
// sandbox metadata: the caller only learns whether its own cached copy is live.
type ControlLocalCacheStateResp struct {
	Keep bool `json:"keep"`
}

// ControlUpsertHostCachedTemplateReq — POST /v1/internal/db/host-cached-templates/upsert
type ControlUpsertHostCachedTemplateReq struct {
	HostID      string    `json:"host_id"`
	TplID       string    `json:"tpl_id"`
	CachedUntil time.Time `json:"cached_until"`
}

// Snapshot progress actions are shared by control and host workers. Captured
// records a checkpoint; it is not a new persisted snapshot status.
const (
	SnapshotActionCaptured = "captured"
	SnapshotActionReady    = "ready"
	SnapshotActionFailed   = "failed"
)

// Stable failure codes accepted by the snapshot progress endpoint.
const (
	SnapshotErrorCaptureFailed     = "capture_failed"
	SnapshotErrorSourceUnavailable = "source_unavailable"
	SnapshotErrorUploadTimeout     = "upload_timeout"
	SnapshotErrorCheckpointMissing = "checkpoint_missing"
)

// ControlSnapshotProgressReq has no owner, host, region or storage URI input.
// Control derives these from the mTLS worker and its assigned snapshot row.
type ControlSnapshotProgressReq struct {
	Manifest  json.RawMessage `json:"manifest,omitempty"`
	ErrorCode string          `json:"error_code,omitempty"`
}
