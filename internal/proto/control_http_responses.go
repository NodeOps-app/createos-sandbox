package proto

import (
	"time"
)

// All structs in this file are JSend "success" data payloads — what gets
// marshalled under `{"status":"success","data":<here>}`.

// ── Sandbox lifecycle ─────────────────────────────────────────────────

// CreateResp is the response body for POST /v1/sandboxes.
// `mode` (snapshot vs cold-boot) is intentionally not exposed — it's an
// operational detail of the boot path, not part of the user contract.
type CreateResp struct {
	SnapshotID          *string           `json:"snapshot_id,omitempty"`
	ID                  string            `json:"id"`
	Status              string            `json:"status"`
	Name                *string           `json:"name,omitempty"`
	Labels              map[string]string `json:"labels,omitempty"`
	IP                  string            `json:"ip"`
	Shape               string            `json:"shape"`
	Rootfs              *string           `json:"rootfs,omitempty"`
	VCPU                int               `json:"vcpu"`
	MemMib              int               `json:"mem_mib"`
	DiskMib             int64             `json:"disk_mib"`
	SpawnMs             float64           `json:"spawn_ms"`
	Egress              []string          `json:"egress,omitempty"`
	BandwidthQuotaBytes int64             `json:"bandwidth_quota_bytes,omitempty"`

	// IngressURLTemplate is set when ingress_enabled=true and the
	// control plane knows its cluster's public domain suffix. Format:
	// "https://<ulid>-<port>.<domain>" — a single wildcard suffix is
	// used cluster-wide since the WG mesh made ingress region-agnostic.
	// The "<port>" placeholder is left literal — clients substitute
	// the port their service is bound to inside the sandbox.
	IngressURLTemplate string `json:"ingress_url_template,omitempty"`
}

// ExecResp is the response body for POST /v1/sandboxes/:id/exec.
type ExecResp struct {
	Result *ExecResponse `json:"result"`
	ExecMs float64       `json:"exec_ms"`
}

// DestroyResp is the ack returned by DELETE /v1/sandboxes/:id.
//
// `id` always carries the sandbox id the caller supplied (NOT an error
// message — that was the previous misuse of SandboxNotFound). `status`
// is the row's state at the moment of the response — `destroying` for
// a fresh delete, or the existing `destroyed`/`failed` terminal state
// (DELETE is idempotent so this is still 200).
type DestroyResp struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// SandboxView is the public sandbox projection for list/get responses. It
// omits host placement, bucket URIs, cache hints, and raw internal error text.
type SandboxView struct {
	SnapshotID  *string           `json:"snapshot_id,omitempty"`
	ID          string            `json:"id"`
	Name        *string           `json:"name,omitempty"`
	Status      string            `json:"status"`
	IP          *string           `json:"ip,omitempty"`
	VCPU        int               `json:"vcpu"`
	MemMib      int               `json:"mem_mib"`
	DiskMib     int64             `json:"disk_mib"`
	CreatedAt   time.Time         `json:"created_at"`
	RunningAt   *time.Time        `json:"running_at,omitempty"`
	DestroyedAt *time.Time        `json:"destroyed_at,omitempty"`
	SpawnMs     float64           `json:"spawn_ms,omitempty"`
	Shape       string            `json:"shape,omitempty"`
	Rootfs      *string           `json:"rootfs,omitempty"`
	Egress      []string          `json:"egress,omitempty"`
	SSHPubkeys  []string          `json:"ssh_pubkeys,omitempty"`
	CreatedBy   string            `json:"created_by,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`

	// HTTP ingress fields.
	Region                string `json:"region"`
	IngressEnabled        bool   `json:"ingress_enabled"`
	BandwidthIngressBytes int64  `json:"bandwidth_ingress_bytes,omitempty"`
	// IngressURLTemplate is set when ingress_enabled=true and the
	// control plane knows its cluster's public domain suffix. Same
	// shape as CreateResp.IngressURLTemplate — clients substitute
	// `<port>` for the bound port.
	IngressURLTemplate string `json:"ingress_url_template,omitempty"`

	// Envs lists the KEYS of the sandbox's persistent env-var map.
	// VALUES are NEVER returned to API callers — they're stamped at
	// create time, may contain credentials, and exist only to be
	// injected at exec time inside the VM. Operators reading the API
	// see what's set, not what it's set to.
	Envs []string `json:"envs,omitempty"`

	// Pause / resume / fork projection. Lifecycle timestamps and the
	// fork provenance pointer only — never host names, bucket URIs,
	// or raw error strings.
	PausedAt      *time.Time `json:"paused_at,omitempty"`
	LastResumedAt *time.Time `json:"last_resumed_at,omitempty"`
	ForkedFrom    *string    `json:"forked_from,omitempty"`

	// Auto-pause on inactivity. Null when disabled.
	AutoPauseAfterSeconds *int `json:"auto_pause_after_seconds,omitempty"`
}

// BandwidthView is the response body for GET /v1/sandboxes/:id/bandwidth.
type BandwidthView struct {
	ID             string `json:"id"`
	QuotaBytes     int64  `json:"quota_bytes"`
	UsedBytes      int64  `json:"used_bytes"`    // egress (VM-initiated) — billed against quota
	IngressBytes   int64  `json:"ingress_bytes"` // inbound — observation only, never enforces cap
	RemainingBytes int64  `json:"remaining_bytes"`
	Capped         bool   `json:"capped"`
}

// EgressView: {"id": ..., "egress": [...]} — GET/PUT /v1/sandboxes/:id/egress.
type EgressView struct {
	ID     string   `json:"id"`
	Egress []string `json:"egress"`
}

// ── Host-side by-ip lookup (proxy consumer) ───────────────────────────

// SandboxByIP is the lowercase-JSON projection the proxy decodes from
// GET /v1/internal/db/sandboxes/by-ip/:ip. Must match internal/hostproxy
// client's expected shape.
type SandboxByIP struct {
	ID     string   `json:"id"`
	IP     string   `json:"ip"`
	Egress []string `json:"egress"`
}

// ── Catalogs ──────────────────────────────────────────────────────────

// Shape is a named (vcpu, mem) pair in the catalog. IDs follow
// DigitalOcean's slug convention: `<class>-<vcpu>vcpu-<mem>`, e.g.
// "s-1vcpu-1gb". Disk is not part of the shape — users pick it
// per-request. The host's vm.Shape is an alias of this type.
type Shape struct {
	ID          string `json:"id" yaml:"id"`
	VCPU        int    `json:"vcpu" yaml:"vcpu"`
	MemMib      int    `json:"mem_mib" yaml:"mem_mib"`
	DefaultDisk int64  `json:"default_disk_mib" yaml:"default_disk_mib"`
	// CPUQuotaPct is the cgroup v2 cpu.max quota expressed as a percent
	// of one CPU. 0 = unlimited (default). 25 = 0.25 vCPU (burstable
	// shared-CPU shapes), 50 = 0.5 vCPU. Values >100 cap above a single
	// core. vCPU count and scheduler oversubscription are separate from
	// this per-VM execution quota.
	CPUQuotaPct int `json:"cpu_quota_pct,omitempty" yaml:"cpu_quota_pct,omitempty"`
}

// RootfsView is the response shape of GET /v1/rootfs.
//
// `rootfs` and `default` are kept as the original simple-list view for
// backward compatibility with older createos-cli clients. `entries` carries the
// richer per-rootfs metadata (description, deprecation, successor) that
// the control plane joins from rootfs_catalog. Disabled rootfses are
// omitted from BOTH `rootfs` and `entries` — they are treated as
// non-existent from the user's point of view.
type RootfsView struct {
	Rootfs  []string      `json:"rootfs"`
	Default string        `json:"default"`
	Entries []RootfsEntry `json:"entries,omitempty"`
}

type RootfsEntry struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	Deprecated  bool    `json:"deprecated,omitempty"`
	Successor   *string `json:"successor,omitempty"`
}

// ── Health ────────────────────────────────────────────────────────────

// HealthzResp: {"up": true} — GET /healthz.
type HealthzResp struct {
	Up bool `json:"up"`
}

// ReadyzResp is the typed body of GET /readyz. Ready==false populates Reason
// so operators can distinguish DB unreachable from scheduler unreachable
// without grepping logs.
type ReadyzResp struct {
	Ready                bool   `json:"ready"`
	Reason               string `json:"reason,omitempty"`
	SchedulerLastOkMsAgo int64  `json:"scheduler_last_ok_ms_ago,omitempty"`
}

// ── Admin / host registry ─────────────────────────────────────────────

// HostRegisterResp: {"id": ...} — POST /v1/internal/hosts/register.
// Host registration uses its mTLS identity rather than a per-host bearer.
// SubnetCIDR and UnderlayIP are set when the control
// plane has assigned a /22 to this host (overlay networking).
type HostRegisterResp struct {
	ID         string `json:"id"`
	SubnetCIDR string `json:"subnet_cidr,omitempty"` // e.g. "10.0.4.0/22"
	UnderlayIP string `json:"underlay_ip,omitempty"` // VTEP IP
	// WGIP is the host's assigned WireGuard mesh address (172.30.0.<idx>).
	WGIP string `json:"wg_ip,omitempty"`
	// Shapes is the control-resolved shape catalog the host should serve.
	// Sourced from control's shape catalog (the `shapes` DB table); empty
	// if the DB is unavailable and no cached catalog has warmed. Pushed
	// again on every heartbeat so SQL edits propagate without a host
	// restart.
	Shapes []Shape `json:"shapes,omitempty"`
	// Storage is the object-storage backend config the host should use
	// for pause/resume bundle upload + template artifact fetches.
	// Delivered here so hosts don't carry S3 credentials in their own
	// serve.yaml — control is the single source of truth, host caches
	// in memory for the process lifetime. Rotation = restart hosts.
	Storage *HostStorageInfo `json:"storage,omitempty"`
}

// HostStorageInfo is the storage block delivered to hosts at register
// time. Identical shape to control's own StorageConfig, JSON-tagged for
// the wire. Hosts never persist this — in-memory only.
type HostStorageInfo struct {
	Bucket          string `json:"bucket"`
	Endpoint        string `json:"endpoint"`
	Region          string `json:"region"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	Secure          bool   `json:"secure"`
}

// HostHeartbeatResp is the body of POST /v1/internal/hosts/heartbeat.
// Today it carries the resolved shape catalog so the host can detect and
// apply operator-driven changes without restarting. Other fields may
// follow as we move more host-side configuration onto the control plane.
type HostHeartbeatResp struct {
	// Shapes is the control-resolved shape catalog (read from the
	// `shapes` DB table). Same semantics as HostRegisterResp.Shapes —
	// empty means "no change announced" and the host keeps using its
	// current catalog. If the host never received a non-empty catalog,
	// it prewarms nothing until one arrives via heartbeat.
	Shapes []Shape `json:"shapes,omitempty"`
}

// IDResp: {"id": <id>} — the canonical ack for single-row mutations in
// the internal DB proxy.
type IDResp struct {
	ID string `json:"id"`
}

// NewIDResp is a convenience constructor.
func NewIDResp(id string) IDResp { return IDResp{ID: id} }

// ── Admin API keys ────────────────────────────────────────────────────

// ── Templates ──────────────────────────────────────────────────────────

// ── Control internal DB proxy — response bodies ───────────────────────

// ControlIngressRouteResp is the narrow sandbox-routing projection returned
// to trusted internal callers, including the ingress-role mTLS endpoint.
type ControlIngressRouteResp struct {
	ID              string `json:"id"`
	HostAddr        string `json:"host_addr"`
	Status          string `json:"status"`
	IngressEnabled  bool   `json:"ingress_enabled"`
	Region          string `json:"region"`
	BandwidthCapped bool   `json:"bandwidth_capped"`
}

// CASStatusResp: {"status": "<new status>"} — reply shape for every
// pause/resume/fork CAS marker. Empty status means "row had moved".
type CASStatusResp struct {
	Status string `json:"status"`
}

// ── Control: hosts / networks views ───────────────────────────────────

// ── Per-user metrics (GET /v1/metrics, /v1/metrics/timeseries) ────────

// ── Device VPN (GET/POST /v1/devices, /v1/devices/:id/networks, ...) ──

// ── Relay reconciler state (GET /v1/internal/relay-state) ─────────────

// RelaySessionView is one active wg-devices peer entry. Pubkey is base64
// (32-byte Curve25519); ExpiresAtUnix is the session TTL deadline so the
// relay can sanity-cross-check.
type RelaySessionView struct {
	SessionID     string `json:"session_id"`
	Pubkey        string `json:"pubkey"` // base64
	ClientIP      string `json:"client_ip"`
	ExpiresAtUnix int64  `json:"expires_at_unix"`
}

// RelayPairView is one (src_ip, dst_ip) BPF-policy allow-list entry.
type RelayPairView struct {
	SrcIP string `json:"src_ip"`
	DstIP string `json:"dst_ip"`
}

// RelayStateResp is the full reconcile payload returned on each tick.
// Three lists drive the relay's local state:
//   - Sessions      → wg-devices peer table
//   - DevicePairs   → relay policy entries for device↔device traffic
//   - DeviceVMPairs → relay policy entries for device↔VM traffic
type RelayStateResp struct {
	Sessions      []RelaySessionView `json:"sessions"`
	DevicePairs   []RelayPairView    `json:"device_pairs"`
	DeviceVMPairs []RelayPairView    `json:"device_vm_pairs"`
}
