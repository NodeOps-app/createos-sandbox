package models

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/NodeOps-app/createos-sandbox/database"

	"github.com/jackc/pgx/v5"
)

// PoolUserID is the sentinel value stamped on sandboxes.created_by
// while a row is owned by the predictive prewarm pool. Rewritten to
// the real user_id atomically at claim. Referenced by:
//   - ClaimPoolSandbox (SQL guard)
//   - billingemit.EmitInTx (suppress emission while pool-owned)
//   - audit emitter (same suppression)
const PoolUserID = "pool"

// IsPoolOwnerID identifies both the current pool sentinel and the temporary
// per-control owner IDs used by the retired reservation-buffer experiment.
// Legacy rows and immutable billing payloads can outlive the code that minted
// them, so lifecycle processing must continue to treat both forms as
// synthetic, non-billable owners.
func IsPoolOwnerID(owner string) bool {
	return owner == PoolUserID || strings.HasPrefix(owner, "poolbuf-")
}

// query resolves a named SQL string from the Db's parsed queries.sql.
// Inlined equivalent of pgRepo.query — every model function uses it.
func query(d *database.Db, name string) (string, error) {
	q, ok := d.GetQuery(name)
	if !ok {
		return "", fmt.Errorf("query %q not found", name)
	}
	return q, nil
}

// Status is the sandboxes.status enum.
type Status string

const (
	StatusCreating   Status = "creating"
	StatusRunning    Status = "running"
	StatusDestroyed  Status = "destroyed"
	StatusFailed     Status = "failed"
	StatusPausing    Status = "pausing"    // host is taking the snapshot + uploading
	StatusPaused     Status = "paused"     // bundle in R2 + (maybe) locality cache; no live VM
	StatusResuming   Status = "resuming"   // host is downloading + spawning fc
	StatusForking    Status = "forking"    // R2 server-side copy in flight on a brand-new row
	StatusDestroying Status = "destroying" // teardown in flight; no other ops allowed
	StatusError      Status = "error"      // resume exhausted RESUME_MAX_HOSTS; user can retry
)

// Sandbox is one row of the sandboxes table (mirror of store.Record).
type Sandbox struct {
	ID          string            `json:"id" sql:"id"`
	Status      Status            `json:"status" sql:"status"`
	Mode        *string           `json:"mode,omitempty" sql:"mode"` // "cold" or "snapshot"
	IP          *string           `json:"ip,omitempty" sql:"ip"`
	MAC         *string           `json:"mac,omitempty" sql:"mac"`
	VCPU        int               `json:"vcpu" sql:"vcpu"`
	MemMib      int               `json:"mem_mib" sql:"mem_mib"`
	DiskMib     int64             `json:"disk_mib" sql:"disk_mib"`
	CreatedAt   time.Time         `json:"created_at" sql:"created_at"`
	RunningAt   *time.Time        `json:"running_at" sql:"running_at"`
	DestroyedAt *time.Time        `json:"destroyed_at,omitempty" sql:"destroyed_at"`
	SpawnMs     float64           `json:"spawn_ms" sql:"spawn_ms"`
	ErrorText   *string           `json:"error_text,omitempty" sql:"error_text"`
	Note        *string           `json:"note,omitempty" sql:"note"`
	Egress      []string          `json:"egress" sql:"egress"`             // allowlist entries: "host[:port]", "ip[:port]", "cidr[:port]", "*"
	HostID      *string           `json:"host_id,omitempty" sql:"host_id"` // id of the createos host running this sandbox (multi-host mode)
	SSHPubkeys  []string          `json:"ssh_pubkeys" sql:"ssh_pubkeys"`   // OpenSSH-formatted pubkeys authorized to tunnel to this sandbox
	Shape       string            `json:"shape" sql:"shape"`               // catalog shape ID (e.g. "s-1vcpu-1gb")
	Rootfs      *string           `json:"rootfs,omitempty" sql:"rootfs"`   // rootfs catalog name (e.g. "python")
	CreatedBy   string            `json:"created_by" sql:"created_by"`     // user_id of the API key that created this sandbox
	Labels      map[string]string `json:"labels,omitempty" sql:"labels"`   // user-defined metadata for filtering

	// Name is the user-facing VM name — a Docker-style "<adjective>-<animal>"
	// label, unique per user among non-terminal sandboxes. Purely a
	// label/hostname/DNS-name; the id stays the only addressing handle.
	Name *string `json:"name,omitempty" sql:"name"`

	// Bandwidth quota — total bytes the VM may transfer (upload+download
	// across its veth) before connectivity is capped. Always positive
	// for sandboxes created post-policy: control resolves request 0 to
	// the cluster default (ControlConfig.DefaultBandwidthQuotaBytes)
	// and rejects negatives. Legacy rows may carry 0; the host's meter
	// loop treats 0/negative as unmetered, but new creates never hit it.
	BandwidthQuotaBytes int64 `json:"bandwidth_quota_bytes" sql:"bandwidth_quota_bytes"`
	BandwidthUsedBytes  int64 `json:"bandwidth_used_bytes" sql:"bandwidth_used_bytes"`
	BandwidthCapped     bool  `json:"bandwidth_capped" sql:"bandwidth_capped"`

	// Runtime identifiers. Captured at create time so that a restarted
	// serve can rehydrate its in-memory Manager state (rather than
	// destroying surviving VMs).
	APISock     *string `json:"api_sock,omitempty" sql:"api_sock"`
	ContainerID *string `json:"container_id,omitempty" sql:"container_id"` // netpool slot id, e.g. "fcp7"
	FCPid       int     `json:"fc_pid" sql:"fc_pid"`                       // firecracker PID; 0 if unknown
	OverlayPath *string `json:"overlay_path,omitempty" sql:"overlay_path"`

	// HTTP ingress.
	IngressEnabled        bool   `json:"ingress_enabled" sql:"ingress_enabled"`
	BandwidthIngressBytes int64  `json:"bandwidth_ingress_bytes" sql:"bandwidth_ingress_bytes"`
	Region                string `json:"region" sql:"region"`

	// SecretToken is the per-sandbox shared secret the host stamps into
	// MMDS at boot and presents on every dial into the guest agent's
	// :1024/:1025/:1026 listeners.
	SecretToken *string `json:"secret_token,omitempty" sql:"secret_token"`

	// Envs is the persistent server-side env-var map injected into every
	// /exec call against this sandbox.
	Envs map[string]string `json:"envs,omitempty" sql:"envs"`

	// SnapshotID records the reusable snapshot used at creation, not captures of this VM.
	SnapshotID *string `json:"snapshot_id,omitempty" sql:"snapshot_id"`

	// Pause / resume / fork state. All NULL on a fresh `running` row.
	PausedAt            *time.Time      `json:"paused_at,omitempty" sql:"paused_at"`
	SnapshotURI         *string         `json:"snapshot_uri,omitempty" sql:"snapshot_uri"`
	SnapshotManifest    json.RawMessage `json:"snapshot_manifest,omitempty" sql:"snapshot_manifest"`
	CachedHostID        *string         `json:"cached_host_id,omitempty" sql:"cached_host_id"`
	CachedUntil         *time.Time      `json:"cached_until,omitempty" sql:"cached_until"`
	LastResumedAt       *time.Time      `json:"last_resumed_at,omitempty" sql:"last_resumed_at"`
	ResumeFailedHosts   []string        `json:"resume_failed_hosts,omitempty" sql:"resume_failed_hosts"`
	LastResumeError     *string         `json:"last_resume_error,omitempty" sql:"last_resume_error"`
	LastResumeAttemptAt *time.Time      `json:"last_resume_attempt_at,omitempty" sql:"last_resume_attempt_at"`
	LastPauseError      *string         `json:"last_pause_error,omitempty" sql:"last_pause_error"`
	LastPauseAttemptAt  *time.Time      `json:"last_pause_attempt_at,omitempty" sql:"last_pause_attempt_at"`
	ForkedFrom          *string         `json:"forked_from,omitempty" sql:"forked_from"`
	BundleUploadedAt    *time.Time      `json:"bundle_uploaded_at,omitempty" sql:"bundle_uploaded_at"`

	// CPU lineage. Stamped at first create (host writes its own
	// CPUVendor/CPUFamily into the insert payload). Forks inherit from
	// the parent row byte-identical (insertForkRow's INSERT ... SELECT).
	// CPUVendor is the canonical source for resume's cpu_compat vendor
	// pin — see placementpolicy.BuildResumeScheduleRequest.
	CPUVendor *string `json:"cpu_vendor,omitempty" sql:"cpu_vendor"`
	CPUFamily *string `json:"cpu_family,omitempty" sql:"cpu_family"`

	// DrainPauseAttempts counts consecutive failed pause-trigger attempts
	// while the owning host is in 'draining' state. Sweep falls back to
	// destroy when this hits drainPauseMaxAttempts.
	DrainPauseAttempts int `json:"drain_pause_attempts" sql:"drain_pause_attempts"`

	// Auto-pause on inactivity. AutoPauseAfterSeconds is null when disabled.
	AutoPauseAfterSeconds *int      `json:"auto_pause_after_seconds,omitempty" sql:"auto_pause_after_seconds"`
	LastActivityAt        time.Time `json:"last_activity_at" sql:"last_activity_at"`
	LastMeteredBytes      int64     `json:"last_metered_bytes" sql:"last_metered_bytes"`
}

// IngressRoute is the projection the ingress subcommand pulls per request.
type IngressRoute struct {
	ID              string `json:"id" sql:"id"`
	HostAddr        string `json:"host_addr" sql:"addr"`
	Status          string `json:"status" sql:"status"`
	IngressEnabled  bool   `json:"ingress_enabled" sql:"ingress_enabled"`
	Region          string `json:"region" sql:"region"`
	BandwidthCapped bool   `json:"bandwidth_capped" sql:"bandwidth_capped"`
}

// LiveSandbox is one row's contribution to scheduler bookkeeping.
// Used by scheduler hydration to derive reserved host memory from shape plus
// mem_mib, and to sum vcpu/disk_mib for the other admission dimensions.
type LiveSandbox struct {
	ID      string `json:"id" sql:"id"`
	HostID  string `json:"host_id" sql:"host_id"`
	Shape   string `json:"shape" sql:"shape"`
	MemMib  int    `json:"mem_mib" sql:"mem_mib"`
	VCPU    int    `json:"vcpu" sql:"vcpu"`
	DiskMib int64  `json:"disk_mib" sql:"disk_mib"`
}

// HostUsage captures one host's live capacity consumption summed from the
// sandboxes table.
type HostUsage struct {
	UsedMib int `json:"used_mib" sql:"used_mib"`
	VMCount int `json:"vm_count" sql:"vm_count"`
}

// scannable covers both pgx.Row (QueryRow) and pgx.Rows (Query)'s Scan
// method so scanSandbox/scanHost can be reused for single-row and
// multi-row code paths.
type scannable interface {
	Scan(dest ...any) error
}

// envCipher is the optional AES-256-GCM cipher used to encrypt
// sandboxes.envs at rest. Set once at control startup via SetEnvCipher;
// nil = legacy plaintext mode (write plaintext, read plaintext). When
// set, write path always encrypts and read path detects-and-decrypts
// the envelope shape so legacy plaintext rows still load.
var envCipher EnvCipher

// EnvCipher is the minimal contract for transparent envs encryption.
// *diskcrypto.Cipher satisfies it directly.
type EnvCipher interface {
	Encrypt(plaintext []byte) (json.RawMessage, error)
	Decrypt(envelope json.RawMessage) ([]byte, error)
}

// SetEnvCipher installs the cipher used to encrypt sandboxes.envs at
// rest. Call once at control startup; safe to leave unset for callers
// (scheduler / ingress / builder) that never write sandboxes — they'll
// keep reading any existing plaintext rows.
func SetEnvCipher(c EnvCipher) { envCipher = c }

// marshalEnvs encodes a Sandbox.Envs map for the envs JSONB column.
// When envCipher is set, the JSON-encoded map is AES-256-GCM-wrapped
// and stored as the diskcrypto envelope (`{"v":1,"nonce":"...","ct":"..."}`).
// Empty maps stay as the canonical "{}" plaintext so the NOT NULL
// DEFAULT '{}' continues to apply.
func marshalEnvs(envs map[string]string) ([]byte, error) {
	if len(envs) == 0 {
		return []byte("{}"), nil
	}
	plain, err := json.Marshal(envs)
	if err != nil {
		return nil, err
	}
	if envCipher == nil {
		return plain, nil
	}
	return envCipher.Encrypt(plain)
}

// unmarshalEnvs decodes the envs JSONB column. Handles both shapes:
// plaintext map (legacy rows + the empty "{}") AND the diskcrypto
// envelope written by marshalEnvs after SetEnvCipher landed.
func unmarshalEnvs(raw []byte) (map[string]string, error) {
	if len(raw) == 0 || string(raw) == "{}" {
		return nil, nil
	}
	// Envelope detection: a JSON object whose top-level fields are
	// {"v","nonce","ct"} is our wrapper; everything else is legacy
	// plaintext. Trying envelope first is cheap — a wrong shape just
	// falls through to the plaintext branch.
	if envCipher != nil {
		var probe struct {
			V     int    `json:"v"`
			Nonce string `json:"nonce"`
			CT    string `json:"ct"`
		}
		if err := json.Unmarshal(raw, &probe); err == nil && probe.V > 0 && probe.Nonce != "" && probe.CT != "" {
			plain, err := envCipher.Decrypt(raw)
			if err != nil {
				return nil, fmt.Errorf("decrypt envs: %w", err)
			}
			out := make(map[string]string)
			if err := json.Unmarshal(plain, &out); err != nil {
				return nil, fmt.Errorf("decode decrypted envs: %w", err)
			}
			return out, nil
		}
	}
	out := make(map[string]string)
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode envs: %w", err)
	}
	return out, nil
}

// nullableTime returns the pointer as-is; pgx encodes *time.Time nil as NULL.
func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

// nullableStrings normalises an empty/nil slice to an empty TEXT[]
// (Postgres can't infer a NULL cast from an untyped nil slice).
func nullableStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// scanIDList scans rows.Scan(&id) into a []string.
func scanIDList(rows pgx.Rows) ([]string, error) {
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// scanCASStatus reads a single status string from a CAS UPDATE
// ... RETURNING status; returns "" if no row matched (CAS missed).
func scanCASStatus(row pgx.Row) (string, error) {
	var s string
	err := row.Scan(&s)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return s, err
}

func scanSandbox(s scannable) (*Sandbox, error) {
	var (
		rec         Sandbox
		runningAt   *time.Time
		destroyedAt *time.Time
		statusStr   string
		egress      []string
		sshPubkeys  []string
		envsRaw     []byte // JSONB
		labelsRaw   []byte // JSONB

		pausedAt            *time.Time
		snapshotURI         *string
		snapshotManifest    []byte // JSONB; may be nil
		cachedHostID        *string
		cachedUntil         *time.Time
		lastResumedAt       *time.Time
		resumeFailedHosts   []string
		lastResumeError     *string
		lastResumeAttemptAt *time.Time
		lastPauseError      *string
		lastPauseAttemptAt  *time.Time
		forkedFrom          *string
		bundleUploadedAt    *time.Time
		name                *string
		cpuVendor           *string
		cpuFamily           *string
	)
	err := s.Scan(
		&rec.ID, &rec.HostID, &statusStr, &rec.Mode, &rec.IP, &rec.MAC,
		&rec.VCPU, &rec.MemMib, &rec.DiskMib, &rec.Shape, &rec.Rootfs, &rec.CreatedBy,
		&rec.CreatedAt, &runningAt, &destroyedAt,
		&rec.SpawnMs, &rec.ErrorText, &rec.Note,
		&egress, &sshPubkeys,
		&rec.BandwidthQuotaBytes, &rec.BandwidthUsedBytes, &rec.BandwidthCapped,
		&rec.APISock, &rec.ContainerID, &rec.FCPid, &rec.OverlayPath,
		&rec.IngressEnabled, &rec.BandwidthIngressBytes, &rec.Region,
		&rec.SecretToken,
		&envsRaw, &labelsRaw,
		&pausedAt, &snapshotURI, &snapshotManifest,
		&cachedHostID, &cachedUntil, &lastResumedAt,
		&resumeFailedHosts,
		&lastResumeError, &lastResumeAttemptAt,
		&lastPauseError, &lastPauseAttemptAt,
		&forkedFrom,
		&bundleUploadedAt,
		&name,
		&cpuVendor, &cpuFamily,
		&rec.DrainPauseAttempts,
		&rec.AutoPauseAfterSeconds, &rec.LastActivityAt, &rec.LastMeteredBytes,
		&rec.SnapshotID,
	)
	if err != nil {
		return nil, err
	}
	rec.Status = Status(statusStr)
	rec.Name = name
	rec.RunningAt = runningAt
	rec.DestroyedAt = destroyedAt
	rec.Egress = egress
	rec.SSHPubkeys = sshPubkeys
	if len(envsRaw) > 0 {
		envs, err := unmarshalEnvs(envsRaw)
		if err != nil {
			return nil, err
		}
		if len(envs) > 0 {
			rec.Envs = envs
		}
	}
	if len(labelsRaw) > 0 {
		if err := json.Unmarshal(labelsRaw, &rec.Labels); err != nil {
			return nil, fmt.Errorf("unmarshal sandbox labels: %w", err)
		}
	}
	rec.PausedAt = pausedAt
	rec.SnapshotURI = snapshotURI
	if len(snapshotManifest) > 0 {
		rec.SnapshotManifest = json.RawMessage(snapshotManifest)
	}
	rec.CachedHostID = cachedHostID
	rec.CachedUntil = cachedUntil
	rec.LastResumedAt = lastResumedAt
	rec.ResumeFailedHosts = resumeFailedHosts
	rec.LastResumeError = lastResumeError
	rec.LastResumeAttemptAt = lastResumeAttemptAt
	rec.LastPauseError = lastPauseError
	rec.LastPauseAttemptAt = lastPauseAttemptAt
	rec.ForkedFrom = forkedFrom
	rec.BundleUploadedAt = bundleUploadedAt
	rec.CPUVendor = cpuVendor
	rec.CPUFamily = cpuFamily
	return &rec, nil
}

// scanIDs runs a named query expecting a single id column per row.
func scanIDs(ctx context.Context, d *database.Db, queryName string, args ...any) ([]string, error) {
	q, err := query(d, queryName)
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func InsertSandbox(ctx context.Context, d *database.Db, rec Sandbox) error {
	q, err := query(d, "insertSandbox")
	if err != nil {
		return err
	}
	envsJSON, err := marshalEnvs(rec.Envs)
	if err != nil {
		return fmt.Errorf("marshal envs: %w", err)
	}
	labelsJSON := []byte(`{}`)
	if len(rec.Labels) > 0 {
		labelsJSON, err = json.Marshal(rec.Labels)
		if err != nil {
			return fmt.Errorf("marshal labels: %w", err)
		}
	}
	_, err = d.Con.Exec(ctx, q,
		rec.ID, rec.HostID, string(rec.Status), rec.Mode, rec.IP, rec.MAC,
		rec.VCPU, rec.MemMib, rec.DiskMib, rec.Shape, rec.Rootfs, rec.CreatedBy,
		rec.CreatedAt, nullableTime(rec.RunningAt), nullableTime(rec.DestroyedAt),
		rec.SpawnMs, rec.ErrorText, rec.Note,
		nullableStrings(rec.Egress), nullableStrings(rec.SSHPubkeys),
		rec.BandwidthQuotaBytes, rec.BandwidthUsedBytes, rec.BandwidthCapped,
		rec.APISock, rec.ContainerID, rec.FCPid, rec.OverlayPath,
		rec.IngressEnabled, rec.BandwidthIngressBytes, rec.Region,
		rec.SecretToken,
		envsJSON, labelsJSON,
		rec.Name,
		rec.CPUVendor, rec.CPUFamily,
		rec.AutoPauseAfterSeconds, rec.SnapshotID, rec.SnapshotURI, rec.SnapshotManifest,
	)
	return err
}

// CompleteSandboxCreate publishes only host-owned runtime facts and performs
// an atomic creating→running transition pinned to the assigned host. It never
// accepts tenant ownership, access-policy, or billing fields from the host.
func CompleteSandboxCreate(ctx context.Context, d *database.Db, rec Sandbox, hostID string) (bool, error) {
	q, err := query(d, "completeSandboxCreate")
	if err != nil {
		return false, err
	}
	tag, err := d.Con.Exec(ctx, q,
		rec.ID, hostID, rec.Mode, rec.IP, rec.MAC,
		nullableTime(rec.RunningAt), rec.SpawnMs, rec.ErrorText, rec.Note,
		rec.APISock, rec.ContainerID, rec.FCPid, rec.OverlayPath,
		rec.SecretToken, rec.CPUVendor, rec.CPUFamily,
	)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// MarkSandboxDestroyed flips status to 'destroyed' and emits a
// sandbox.destroyed billing event in the SAME transaction so both
// commit-or-roll-back atomically. emitter=nil is a no-op (status still
// commits). An already-destroyed or missing row is a no-op; retries preserve
// the original destruction time and do not emit another billing event.
func MarkSandboxDestroyed(ctx context.Context, d *database.Db, id string, at time.Time, note *string, emitter BillingEmitter) error {
	q, err := query(d, "markSandboxDestroyed")
	if err != nil {
		return err
	}
	tx, err := d.Con.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var changedID string
	err = tx.QueryRow(ctx, q, id, at, note).Scan(&changedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := emitInTx(ctx, tx, emitter, id, BillingEventSandboxDestroyed, ""); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// MarkSandboxDestroyedOnDeadHost rejects stale sweeper observations. Sandbox
// and host locks serialize capture/migration and heartbeat recovery respectively.
// Billing and resource cleanup commit only for the winning transition.
func MarkSandboxDestroyedOnDeadHost(ctx context.Context, d *database.Db, id, hostID, region string, cutoff, at time.Time, note *string, emitter BillingEmitter) (bool, error) {
	if region == "" || hostID == "" {
		return false, nil
	}
	lock, err := query(d, "lockDeadHostEviction")
	if err != nil {
		return false, err
	}
	destroy, err := query(d, "markSandboxDestroyed")
	if err != nil {
		return false, err
	}
	tx, ok, err := beginCaptureOperation(ctx, d, id)
	if err != nil || !ok {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var got string
	err = tx.QueryRow(ctx, lock, id, hostID, region, cutoff).Scan(&got)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err = tx.QueryRow(ctx, destroy, id, at, note).Scan(&got); err != nil {
		return false, err
	}
	if err = emitInTx(ctx, tx, emitter, id, BillingEventSandboxDestroyed, ""); err != nil {
		return false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// MarkSandboxDestroyingFromTerminalCAS atomically claims a paused/error row
// for deletion. False means a concurrent operation (most importantly resume)
// moved it first, so the caller must not delete its snapshot bundle.
func MarkSandboxDestroyingFromTerminalCAS(ctx context.Context, d *database.Db, id string) (bool, error) {
	st, err := guardedSandboxTransition(ctx, d, id, "markSandboxDestroyingFromTerminalCAS", id)
	return st == string(StatusDestroying), err
}

// MarkSandboxDestroyedFromDestroyingCAS publishes completion of asynchronous
// deletion and emits billing in the same transaction. The CAS makes an
// in-process cleanup worker safe to race the durable sweeper.
func MarkSandboxDestroyedFromDestroyingCAS(ctx context.Context, d *database.Db, id string, at time.Time, note *string, emitter BillingEmitter) (bool, error) {
	q, err := query(d, "markSandboxDestroyedFromDestroyingCAS")
	if err != nil {
		return false, err
	}
	tx, err := d.Con.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var newStatus string
	err = tx.QueryRow(ctx, q, id, at, note).Scan(&newStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := emitInTx(ctx, tx, emitter, id, BillingEventSandboxDestroyed, ""); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return newStatus == string(StatusDestroyed), nil
}

// MarkSandboxFailed flips a nonterminal row to 'failed' and emits a
// sandbox.failed billing event in the SAME transaction. Late callbacks after
// deletion starts or failure completes are no-ops, including billing.
func MarkSandboxFailed(ctx context.Context, d *database.Db, id string, errText *string, at time.Time, emitter BillingEmitter) error {
	q, err := query(d, "markSandboxFailed")
	if err != nil {
		return err
	}
	tx, err := d.Con.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, q, id, errText, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	if err := emitInTx(ctx, tx, emitter, id, BillingEventSandboxFailed, ""); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// MarkSandboxFailedFromCreatingCAS atomically flips a row from
// 'creating' → 'failed' iff (id, host_id) match the args. Returns
// (true, nil) when the CAS hit; (false, nil) when status had moved
// or host_id didn't match. Same billing semantics as MarkSandboxFailed
// — sandbox.failed event emitted IN THE SAME TX so a failed-but-not-
// billed row can't exist.
//
// Used by hosts/reconcile so a host restart self-heals 'creating'
// rows pinned to itself, without waiting up to 60s for sweep.
func MarkSandboxFailedFromCreatingCAS(ctx context.Context, d *database.Db, id, hostID string, errText *string, at time.Time, emitter BillingEmitter) (bool, error) {
	q, err := query(d, "markSandboxFailedFromCreatingCAS")
	if err != nil {
		return false, err
	}
	tx, err := d.Con.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var newStatus string
	if err := tx.QueryRow(ctx, q, id, hostID, errText, at).Scan(&newStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// CAS lost. Don't emit billing.
			return false, nil
		}
		return false, err
	}
	if err := emitInTx(ctx, tx, emitter, id, BillingEventSandboxFailed, ""); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func GetSandbox(ctx context.Context, d *database.Db, id string) (*Sandbox, error) {
	q, err := query(d, "getSandbox")
	if err != nil {
		return nil, err
	}
	row := d.Con.QueryRow(ctx, q, id)
	rec, err := scanSandbox(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// GetSandboxExecRoute loads only the fields required to authorize, route, and
// account for an exec request. It intentionally returns a partial Sandbox;
// callers must not use it as a complete API representation.
func GetSandboxExecRoute(ctx context.Context, d *database.Db, id string) (*Sandbox, error) {
	q, err := query(d, "getSandboxExecRoute")
	if err != nil {
		return nil, err
	}
	var (
		rec       Sandbox
		hostID    string
		statusStr string
	)
	err = d.Con.QueryRow(ctx, q, id).Scan(
		&rec.ID, &hostID, &statusStr, &rec.CreatedBy,
		&rec.AutoPauseAfterSeconds, &rec.BandwidthUsedBytes, &rec.BandwidthIngressBytes,
		&rec.IngressEnabled,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rec.Status = Status(statusStr)
	if hostID != "" {
		rec.HostID = &hostID
	}
	return &rec, nil
}

func GetSandboxByIP(ctx context.Context, d *database.Db, ip string) (*Sandbox, error) {
	q, err := query(d, "getSandboxByIp")
	if err != nil {
		return nil, err
	}
	row := d.Con.QueryRow(ctx, q, ip)
	rec, err := scanSandbox(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// GetSandboxByIPForUser scopes the IP lookup to a single owner. Tightens
// the cross-tenant timing oracle: callers asking about another tenant's
// IP always hit the same ErrNoRows branch.
func GetSandboxByIPForUser(ctx context.Context, d *database.Db, userID, ip string) (*Sandbox, error) {
	q, err := query(d, "getSandboxByIPForUser")
	if err != nil {
		return nil, err
	}
	row := d.Con.QueryRow(ctx, q, ip, userID)
	rec, err := scanSandbox(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return rec, nil
}

func ListSandboxes(ctx context.Context, d *database.Db, host, userID, status string, labels map[string]string, limit, offset int) ([]Sandbox, error) {
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	var err error
	labelsJSON := []byte(`{}`)
	if len(labels) > 0 {
		labelsJSON, err = json.Marshal(labels)
		if err != nil {
			return nil, fmt.Errorf("marshal label filter: %w", err)
		}
	}
	name := "listSandboxes"
	args := []any{host, userID, status, labelsJSON, limit, offset}
	// Host reconciliation polls these states repeatedly. Its dedicated query
	// keeps generic plans on the small transient-state index. Never drop a
	// caller's owner or label filter when selecting this path.
	if host != "" && userID == "" && len(labels) == 0 {
		switch Status(status) {
		case StatusPausing, StatusResuming, StatusDestroying:
			name = "listHostTransitionSandboxes"
			args = []any{host, status, limit, offset}
		}
	}
	q, err := query(d, name)
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sandbox
	for rows.Next() {
		rec, err := scanSandbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

// CountSandboxesForList returns the total number of sandboxes matching
// the same filters ListSandboxes uses, ignoring limit/offset. Drives
// pagination.total on GET /v1/sandboxes.
func CountSandboxesForList(ctx context.Context, d *database.Db, host, userID, status string, labels map[string]string) (int, error) {
	q, err := query(d, "countSandboxesForList")
	if err != nil {
		return 0, err
	}
	var n int
	labelsJSON := []byte(`{}`)
	if len(labels) > 0 {
		labelsJSON, err = json.Marshal(labels)
		if err != nil {
			return 0, fmt.Errorf("marshal label filter: %w", err)
		}
	}
	if err := d.Con.QueryRow(ctx, q, host, userID, status, labelsJSON).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// ListPinnedToHost returns every non-terminal sandbox still bound to `host`
// directly (host_id), plus paused rows whose cached_host_id points there.
// Used by the sweep's drain pass; terminal history is excluded in SQL before
// LIMIT so it cannot hide live work.
func ListPinnedToHost(ctx context.Context, d *database.Db, host string, limit int) ([]Sandbox, error) {
	if limit <= 0 {
		limit = 1000
	}
	q, err := query(d, "listSandboxesPinnedToHost")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, host, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sandbox
	for rows.Next() {
		rec, err := scanSandbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

func ListRunningIDs(ctx context.Context, d *database.Db, host string) ([]string, error) {
	return scanIDs(ctx, d, "listRunningSandboxIds", host)
}

func ListLiveIDs(ctx context.Context, d *database.Db, host string) ([]string, error) {
	return scanIDs(ctx, d, "listLiveSandboxIdsByHost", host)
}

func SetSandboxHost(ctx context.Context, d *database.Db, sandboxID string, hostID *string) error {
	q, err := query(d, "setSandboxHost")
	if err != nil {
		return err
	}
	tag, err := d.Con.Exec(ctx, q, sandboxID, hostID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("sandbox %s not found", sandboxID)
	}
	return nil
}

func SetSandboxSSHPubkeys(ctx context.Context, d *database.Db, sandboxID string, keys []string) error {
	q, err := query(d, "setSandboxSshPubkeys")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, sandboxID, nullableStrings(keys))
	return err
}

func SetSandboxEgress(ctx context.Context, d *database.Db, sandboxID string, rules []string) error {
	q, err := query(d, "setSandboxEgress")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, sandboxID, nullableStrings(rules))
	return err
}

func SetSandboxEnvs(ctx context.Context, d *database.Db, sandboxID string, envs map[string]string) error {
	q, err := query(d, "setSandboxEnvs")
	if err != nil {
		return err
	}
	envsJSON, err := marshalEnvs(envs)
	if err != nil {
		return fmt.Errorf("marshal envs: %w", err)
	}
	_, err = d.Con.Exec(ctx, q, sandboxID, envsJSON)
	return err
}

func SetSandboxDiskMib(ctx context.Context, d *database.Db, sandboxID string, diskMib int64) error {
	q, err := query(d, "setSandboxDiskMib")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, sandboxID, diskMib)
	return err
}

func SetSandboxRuntime(ctx context.Context, d *database.Db, id string, apiSock, containerID, overlayPath *string, fcPid int) error {
	q, err := query(d, "setSandboxRuntime")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, id, apiSock, containerID, overlayPath, fcPid)
	return err
}

func SetSandboxBandwidthQuota(ctx context.Context, d *database.Db, sandboxID string, quotaBytes int64) error {
	q, err := query(d, "setSandboxBandwidthQuota")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, sandboxID, quotaBytes)
	return err
}

// RechargeSandboxBandwidth adds addBytes to a sandbox's
// bandwidth_quota_bytes atomically. Returns the new quota. Caller is
// responsible for rejecting addBytes <= 0.
func RechargeSandboxBandwidth(ctx context.Context, d *database.Db, sandboxID string, addBytes int64) error {
	if addBytes <= 0 {
		return fmt.Errorf("addBytes must be > 0, got %d", addBytes)
	}
	q, err := query(d, "addSandboxBandwidthQuota")
	if err != nil {
		return err
	}
	var newQuota int64
	return d.Con.QueryRow(ctx, q, sandboxID, addBytes).Scan(&newQuota)
}

func SetSandboxBandwidthUsed(ctx context.Context, d *database.Db, sandboxID string, usedBytes int64) error {
	q, err := query(d, "setSandboxBandwidthUsed")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, sandboxID, usedBytes)
	return err
}

func SetSandboxBandwidthCapped(ctx context.Context, d *database.Db, sandboxID string, capped bool) error {
	q, err := query(d, "setSandboxBandwidthCapped")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, sandboxID, capped)
	return err
}

func SetSandboxIngressEnabled(ctx context.Context, d *database.Db, id string, enabled bool) error {
	q, err := query(d, "setSandboxIngressEnabled")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, id, enabled)
	return err
}

// SetSandboxEgressIfPaused stores a policy for the next resume. The false,
// nil result means the sandbox left paused state before the update committed.
func SetSandboxEgressIfPaused(ctx context.Context, d *database.Db, id string, rules []string) (bool, error) {
	q, err := query(d, "setSandboxEgressIfPaused")
	if err != nil {
		return false, err
	}
	var updatedID string
	err = d.Con.QueryRow(ctx, q, id, rules).Scan(&updatedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// SetAutoPause sets or clears auto_pause_after_seconds for a sandbox.
// Pass nil to disable auto-pause.
func SetAutoPause(ctx context.Context, d *database.Db, id string, seconds *int) error {
	q, err := query(d, "setAutoPause")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, id, seconds)
	return err
}

func SetSandboxLabels(ctx context.Context, d *database.Db, id string, labels map[string]string) error {
	q, err := query(d, "setSandboxLabels")
	if err != nil {
		return err
	}
	raw, err := json.Marshal(labels)
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, id, raw)
	return err
}

// TouchActivity bumps last_activity_at to now and updates last_metered_bytes
// for the idle-pause sweeper.
func TouchActivity(ctx context.Context, d *database.Db, id string, meteredBytes int64) error {
	q, err := query(d, "touchActivity")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, id, meteredBytes)
	return err
}

// TouchInteractiveActivity keeps an open interactive connection active while
// taking the bandwidth baseline from the current row rather than from a stale
// sandbox record captured when the connection opened.
func TouchInteractiveActivity(ctx context.Context, d *database.Db, id string) error {
	q, err := query(d, "touchInteractiveActivity")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, id)
	return err
}

// ListIdleSandboxes returns running sandboxes with auto-pause enabled whose
// last_activity_at is older than their auto_pause_after_seconds threshold AND
// whose metered bytes delta (used+ingress - last_metered_bytes) is below the
// idle threshold. Called by the idle-pause sweeper.
func ListIdleSandboxes(ctx context.Context, d *database.Db, idleThresholdBytes int64, region string) ([]Sandbox, error) {
	q, err := query(d, "listIdleSandboxes")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, idleThresholdBytes, region)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sandbox
	for rows.Next() {
		rec, err := scanSandbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

// SnapshotMeteredBytes sets last_metered_bytes = bandwidth_used_bytes +
// bandwidth_ingress_bytes for every running sandbox with auto-pause enabled
// in region.
// Called at the end of each sweep tick so the NEXT tick measures delta over
// exactly one sweep window rather than since the last user API call.
func SnapshotMeteredBytes(ctx context.Context, d *database.Db, region string) error {
	q, err := query(d, "snapshotMeteredBytes")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, region)
	return err
}

// MarkIdlePausing flips status to 'pausing' for sandboxes that passed the
// idle check. Uses a CAS on status='running' so a concurrent user-pause or
// destroy won't be clobbered.
func MarkIdlePausing(ctx context.Context, d *database.Db, ids []string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	lock, err := query(d, "lockIdlePauseCandidates")
	if err != nil {
		return nil, err
	}
	q, err := query(d, "markIdlePausing")
	if err != nil {
		return nil, err
	}
	tx, err := d.Con.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, lock, ids)
	if err != nil {
		return nil, err
	}
	locked, err := scanIDList(rows)
	if err != nil {
		return nil, err
	}
	if len(locked) == 0 {
		return nil, nil
	}
	// Separate statement after acquiring locks: capture reservations committed
	// before the lock must be visible to the idle-pause exclusion check.
	rows, err = tx.Query(ctx, q, locked)
	if err != nil {
		return nil, err
	}
	flipped, err := scanIDList(rows)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return flipped, nil
}

func GetIngressRoute(ctx context.Context, d *database.Db, id string) (IngressRoute, error) {
	q, err := query(d, "getIngressRoute")
	if err != nil {
		return IngressRoute{}, err
	}
	row := d.Con.QueryRow(ctx, q, id)
	var route IngressRoute
	err = row.Scan(&route.ID, &route.HostAddr, &route.Status, &route.IngressEnabled, &route.Region, &route.BandwidthCapped)
	if errors.Is(err, pgx.ErrNoRows) {
		return IngressRoute{}, nil
	}
	if err != nil {
		return IngressRoute{}, err
	}
	return route, nil
}

func UpdateSandboxBandwidthIngress(ctx context.Context, d *database.Db, id string, bytes int64) error {
	q, err := query(d, "updateBandwidthIngress")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, id, bytes)
	return err
}

func MarkPausing(ctx context.Context, d *database.Db, id string, at time.Time) (string, error) {
	return guardedSandboxTransition(ctx, d, id, "markPausing", id, at)
}

// MarkPaused flips pausing→paused and stamps bundle_uploaded_at in the same
// update. Callers invoke it only after the complete bundle is durable in
// shared storage.
func MarkPaused(
	ctx context.Context, d *database.Db, id string, manifest json.RawMessage,
	uri, cachedHostID *string, cachedUntil, pausedAt time.Time,
	emitter BillingEmitter,
) (string, error) {
	q, err := query(d, "markPaused")
	if err != nil {
		return "", err
	}
	manifestArg := []byte(manifest)
	if len(manifestArg) == 0 {
		manifestArg = []byte("{}")
	}
	tx, err := d.Con.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st, err := scanCASStatus(tx.QueryRow(
		ctx, q, id, pausedAt, uri, manifestArg, cachedHostID, cachedUntil,
	))
	if err != nil {
		return "", err
	}
	if st != "" {
		if err := emitInTx(ctx, tx, emitter, id, BillingEventSandboxPaused, string(StatusPausing)); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return st, nil
}

func MarkPauseRolledBack(ctx context.Context, d *database.Db, id string, errMsg *string, at time.Time) (string, error) {
	q, err := query(d, "markPauseRolledBack")
	if err != nil {
		return "", err
	}
	return scanCASStatus(d.Con.QueryRow(ctx, q, id, errMsg, at))
}

func MarkResuming(ctx context.Context, d *database.Db, id string, clearFailedHosts bool, at time.Time) (string, error) {
	queryName := "markResumingFromPaused"
	if clearFailedHosts {
		queryName = "markResumingFromError"
	}
	return guardedSandboxTransition(ctx, d, id, queryName, id, at)
}

func MarkResumed(
	ctx context.Context, d *database.Db, id string, ip, mac, apiSock, containerID, overlayPath *string,
	fcPid int, runningAt time.Time, host string, emitter BillingEmitter,
) (string, error) {
	q, err := query(d, "markResumed")
	if err != nil {
		return "", err
	}
	tx, err := d.Con.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st, err := scanCASStatus(tx.QueryRow(
		ctx, q, id, ip, mac, apiSock, containerID, overlayPath, fcPid, runningAt, host,
	))
	if err != nil {
		return "", err
	}
	if st != "" {
		if err := emitInTx(ctx, tx, emitter, id, BillingEventSandboxRunning, string(StatusResuming)); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return st, nil
}

func MarkResumeFailed(
	ctx context.Context, d *database.Db, id, host string, errMsg *string, at time.Time,
) (string, error) {
	q, err := query(d, "markResumeFailed")
	if err != nil {
		return "", err
	}
	hosts := []string{host}
	return scanCASStatus(d.Con.QueryRow(ctx, q, id, hosts, errMsg, at))
}

func MarkResumeExhausted(ctx context.Context, d *database.Db, id string, errMsg *string) (string, error) {
	q, err := query(d, "markResumeExhausted")
	if err != nil {
		return "", err
	}
	// Rolls resuming → paused, and emits NO billing event on purpose: the
	// sandbox never reached `running` during the failed resume, so there's
	// no usage interval to close. A `sandbox.paused` here would be a
	// spurious, unpaired event in the billing stream (over-counts pauses
	// and can desync a state-machine billing backend). The prior real
	// `sandbox.paused` already stopped billing; a failed resume changes
	// nothing.
	return scanCASStatus(d.Con.QueryRow(ctx, q, id, errMsg))
}

// MarkStuckPauseFailed flips a stuck `pausing` row to `error`. Used by
// control's stale-state watchdog. CAS-guarded: WHERE status='pausing'
// so a concurrent successful pause (pausing → paused) wins the race.
func MarkStuckPauseFailed(ctx context.Context, d *database.Db, id string, errMsg *string, emitter BillingEmitter) (string, error) {
	q, err := query(d, "markStuckPauseFailed")
	if err != nil {
		return "", err
	}
	tx, err := d.Con.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st, err := scanCASStatus(tx.QueryRow(ctx, q, id, errMsg))
	if err != nil {
		return "", err
	}
	if st != "" {
		if err := emitInTx(ctx, tx, emitter, id, BillingEventSandboxFailed, string(StatusPausing)); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return st, nil
}

var ErrForkSourceUnavailable = errors.New("fork source unavailable")

// MarkForking inserts a brand-new row in 'forking' state, validating
// that the source row is paused. Done in a single transaction so the
// source-status check and the new-row INSERT can't race a concurrent
// resume of the source. The committed forking child then protects the source
// bundle through guarded lifecycle transitions until copying finishes.
func MarkForking(ctx context.Context, d *database.Db, srcID string, newRow Sandbox) (*Sandbox, error) {
	tx, err := d.Con.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	lock, err := query(d, "lockForkSource")
	if err != nil {
		return nil, err
	}
	var srcStatus, owner, region string
	var manifest json.RawMessage
	var uploaded *time.Time
	if err := tx.QueryRow(ctx, lock, srcID).Scan(&srcStatus, &manifest, &uploaded, &owner, &region); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrForkSourceUnavailable
		}
		return nil, err
	}
	if srcStatus != string(StatusPaused) || uploaded == nil || len(manifest) == 0 || owner != newRow.CreatedBy || region != newRow.Region {
		return nil, ErrForkSourceUnavailable
	}
	// Capture metadata under the same lock as child creation. The earlier HTTP
	// read may describe a previous pause generation.
	newRow.SnapshotManifest = append(json.RawMessage(nil), manifest...)

	q, err := query(d, "insertForkRow")
	if err != nil {
		return nil, err
	}
	envsRaw, err := marshalEnvs(newRow.Envs)
	if err != nil {
		return nil, fmt.Errorf("fork: marshal envs: %w", err)
	}
	// INSERT ... SELECT clones lineage straight from the source row; we pass
	// only the fields a fork changes. srcID ($1) is also the WHERE key and
	// becomes forked_from.
	ct, err := tx.Exec(ctx, q,
		srcID,                      // $1  source id (= forked_from, WHERE key)
		newRow.ID,                  // $2  new id
		newRow.Egress,              // $3  (request override applied by caller)
		newRow.SSHPubkeys,          // $4  (request override applied by caller)
		newRow.CreatedAt,           // $5
		newRow.BandwidthQuotaBytes, // $6  (control-resolved cluster default)
		newRow.IngressEnabled,      // $7  (request override applied by caller)
		envsRaw,                    // $8  (request override applied by caller)
		newRow.Name,                // $9
	)
	if err != nil {
		return nil, err
	}
	if ct.RowsAffected() == 0 {
		// Source flipped out of 'paused' between the FOR UPDATE check and the
		// insert (shouldn't happen under the row lock, but fail loudly).
		return nil, fmt.Errorf("fork: source sandbox %q not paused at insert time", srcID)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &newRow, nil
}

func MarkForkPaused(
	ctx context.Context, d *database.Db, id string, manifest json.RawMessage,
	uri *string, pausedAt time.Time, emitter BillingEmitter,
) (string, error) {
	q, err := query(d, "markForkPaused")
	if err != nil {
		return "", err
	}
	manifestArg := []byte(manifest)
	if len(manifestArg) == 0 {
		manifestArg = []byte("{}")
	}
	tx, err := d.Con.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st, err := scanCASStatus(tx.QueryRow(ctx, q, id, pausedAt, uri, manifestArg))
	if err != nil {
		return "", err
	}
	if st != "" {
		if err := emitInTx(ctx, tx, emitter, id, BillingEventSandboxPaused, string(StatusForking)); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return st, nil
}

// MarkForkFailed flips a stuck or errored `forking` row to `failed` with
// an explanatory message. Called from:
//   - the fork orchestrator's error branches (R2 copy failed, source
//     bundle never landed, MarkForkPaused races), to surface a clean
//     error to the user instead of leaving the row pinned at 'forking'.
//   - the sweep CronJob's stuck-forking watchdog, for fork goroutines
//     that died with no chance to write back (process restart, panic).
//
// CAS-guarded WHERE status='forking' so a concurrent successful
// MarkForkPaused wins the race.
func MarkForkFailed(ctx context.Context, d *database.Db, id string, errMsg *string, emitter BillingEmitter) (string, error) {
	q, err := query(d, "markForkFailed")
	if err != nil {
		return "", err
	}
	tx, err := d.Con.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st, err := scanCASStatus(tx.QueryRow(ctx, q, id, errMsg))
	if err != nil {
		return "", err
	}
	if st != "" {
		if err := emitInTx(ctx, tx, emitter, id, BillingEventSandboxFailed, string(StatusForking)); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return st, nil
}

func ClearLocalCache(ctx context.Context, d *database.Db, id, host string) error {
	q, err := query(d, "clearLocalCache")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, id, host)
	return err
}

func MarkDestroying(ctx context.Context, d *database.Db, id string) (string, error) {
	return guardedSandboxTransition(ctx, d, id, "markDestroying", id)
}

func ListPausing(ctx context.Context, d *database.Db, host string) ([]string, error) {
	q, err := query(d, "listPausingByHost")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, host)
	if err != nil {
		return nil, err
	}
	return scanIDList(rows)
}

func ListPaused(ctx context.Context, d *database.Db, cachedHost string) ([]string, error) {
	q, err := query(d, "listPausedByCachedHost")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, cachedHost)
	if err != nil {
		return nil, err
	}
	return scanIDList(rows)
}

// StuckOrphanDestroying is one row of listStuckOrphanDestroying — just
// the sandbox id and its snapshot_uri (if any) so the watchdog can
// clean R2 before flipping the row to destroyed.
type StuckOrphanDestroying struct {
	ID          string
	SnapshotURI string
}

// IncDrainPauseAttempts bumps the drain pause-fail counter and returns
// the new value. Sweep uses this to bound retries before falling back
// to destroy.
func IncDrainPauseAttempts(ctx context.Context, d *database.Db, id string) (int, error) {
	q, err := query(d, "incDrainPauseAttempts")
	if err != nil {
		return 0, err
	}
	var n int
	err = d.Con.QueryRow(ctx, q, id).Scan(&n)
	return n, err
}

// ResetDrainPauseAttempts clears the counter — called when pause
// successfully transitions to status='pausing' so subsequent drains
// (e.g. uncordon + recordon) start fresh.
func ResetDrainPauseAttempts(ctx context.Context, d *database.Db, id string) error {
	q, err := query(d, "resetDrainPauseAttempts")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, id)
	return err
}

func ListStuckOrphanDestroying(ctx context.Context, d *database.Db, cutoff time.Time, region string) ([]StuckOrphanDestroying, error) {
	q, err := query(d, "listStuckOrphanDestroying")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, cutoff, region)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StuckOrphanDestroying
	for rows.Next() {
		var r StuckOrphanDestroying
		if err := rows.Scan(&r.ID, &r.SnapshotURI); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func ListStuckPausing(ctx context.Context, d *database.Db, cutoff time.Time, region string) ([]Sandbox, error) {
	q, err := query(d, "listStuckPausing")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, cutoff, region)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sandbox
	for rows.Next() {
		rec, err := scanSandbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

func ListStuckResuming(ctx context.Context, d *database.Db, cutoff time.Time, region string) ([]Sandbox, error) {
	q, err := query(d, "listStuckResuming")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, cutoff, region)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sandbox
	for rows.Next() {
		rec, err := scanSandbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

func ListStuckForking(ctx context.Context, d *database.Db, cutoff time.Time, region string) ([]Sandbox, error) {
	q, err := query(d, "listStuckForking")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, cutoff, region)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sandbox
	for rows.Next() {
		rec, err := scanSandbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

// LocalCacheCandidate is the minimal row needed by a host's paused-snapshot
// cache reaper. Keep this projection deliberately narrow: cache maintenance
// must never expose sandbox credentials or tenant configuration.
type LocalCacheCandidate struct {
	ID          string     `json:"id"`
	CachedUntil *time.Time `json:"cached_until,omitempty"`
}

func LocalCacheCandidates(ctx context.Context, d *database.Db, host string) ([]LocalCacheCandidate, error) {
	q, err := query(d, "localCacheCandidates")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, host)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LocalCacheCandidate
	for rows.Next() {
		var rec LocalCacheCandidate
		if err := rows.Scan(&rec.ID, &rec.CachedUntil); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func ListLiveSandboxes(ctx context.Context, d *database.Db) ([]LiveSandbox, error) {
	q, err := query(d, "listLiveSandboxes")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]LiveSandbox, 0, 256)
	for rows.Next() {
		var ls LiveSandbox
		if err := rows.Scan(&ls.ID, &ls.HostID, &ls.Shape, &ls.MemMib, &ls.VCPU, &ls.DiskMib); err != nil {
			return nil, err
		}
		out = append(out, ls)
	}
	return out, rows.Err()
}

func StatusOfIDs(ctx context.Context, d *database.Db, ids []string) (map[string]string, error) {
	if len(ids) == 0 {
		return map[string]string{}, nil
	}
	q, err := query(d, "statusOfIDs")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string, len(ids))
	for rows.Next() {
		var id, status string
		if err := rows.Scan(&id, &status); err != nil {
			return nil, err
		}
		out[id] = status
	}
	return out, rows.Err()
}

// AgedRunningRow is one row returned by MarkAgedRunningDestroyed —
// enough context for the TTL-evictor CronJob to log structured output.
type AgedRunningRow struct {
	ID        string
	HostID    string
	CreatedAt time.Time
}

// MarkAgedRunningDestroyed flips every 'running' row older than cutoff
// to 'destroyed' with the supplied destroyedAt + note, detaches their
// sandbox_disks, and emits one sandbox.destroyed billing event per
// flipped id — all inside one transaction. userCutoffs overrides the default
// cutoff by durable owner ID, preserving the running_at pause/resume clock.
// Returns the flipped rows.
func MarkAgedRunningDestroyed(ctx context.Context, d *database.Db, cutoff, destroyedAt time.Time, note, region string, userCutoffs map[string]time.Time, emitter BillingEmitter) ([]AgedRunningRow, error) {
	q, err := query(d, "markAgedRunningDestroyed")
	if err != nil {
		return nil, err
	}
	lock, err := query(d, "lockAgedRunningCandidates")
	if err != nil {
		return nil, err
	}
	tx, err := d.Con.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, lock, cutoff, region, userCutoffs)
	if err != nil {
		return nil, err
	}
	locked, err := scanIDList(rows)
	if err != nil {
		return nil, err
	}
	if len(locked) == 0 {
		return nil, tx.Commit(ctx)
	}
	rows, err = tx.Query(ctx, q, cutoff, destroyedAt, note, region, locked, userCutoffs)
	if err != nil {
		return nil, err
	}
	var out []AgedRunningRow
	for rows.Next() {
		var r AgedRunningRow
		if err := rows.Scan(&r.ID, &r.HostID, &r.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, r := range out {
		if err := emitInTx(ctx, tx, emitter, r.ID, BillingEventSandboxDestroyed, string(StatusRunning)); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// FailOrphanCreating flips stuck-creating rows to failed and emits one
// sandbox.failed event per flipped id, all inside one transaction.
func FailOrphanCreating(ctx context.Context, d *database.Db, cutoff time.Time, region string, emitter BillingEmitter) ([]string, error) {
	q, err := query(d, "failOrphanCreating")
	if err != nil {
		return nil, err
	}
	tx, err := d.Con.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, q, cutoff, region)
	if err != nil {
		return nil, err
	}
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, id := range out {
		if err := emitInTx(ctx, tx, emitter, id, BillingEventSandboxFailed, string(StatusCreating)); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

func SumUsageByHost(ctx context.Context, d *database.Db) (map[string]HostUsage, error) {
	q, err := query(d, "sumUsageByHost")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]HostUsage)
	for rows.Next() {
		var (
			hostID  string
			usedMib int64
			vmCount int
		)
		if err := rows.Scan(&hostID, &usedMib, &vmCount); err != nil {
			return nil, err
		}
		if hostID == "" {
			continue
		}
		out[hostID] = HostUsage{UsedMib: int(usedMib), VMCount: vmCount}
	}
	return out, rows.Err()
}

func ListRunningSandboxesOnHost(ctx context.Context, d *database.Db, hostID string) ([]string, error) {
	q, err := query(d, "listRunningSandboxesOnHost")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func CountSandboxesActive(ctx context.Context, d *database.Db, userID string) (int, error) {
	q, err := query(d, "countSandboxesActive")
	if err != nil {
		return 0, err
	}
	var n int
	return n, d.Con.QueryRow(ctx, q, userID).Scan(&n)
}

// CountSandboxesActiveExcept is CountSandboxesActive with one id
// excluded. Used by resume so the row being resumed doesn't count
// itself toward the cap.
func CountSandboxesActiveExcept(ctx context.Context, d *database.Db, userID, excludeID string) (int, error) {
	q, err := query(d, "countSandboxesActiveExcept")
	if err != nil {
		return 0, err
	}
	var n int
	return n, d.Con.QueryRow(ctx, q, userID, excludeID).Scan(&n)
}

func CountSandboxesSince(ctx context.Context, d *database.Db, userID string, since time.Time) (int, error) {
	q, err := query(d, "countSandboxesSince")
	if err != nil {
		return 0, err
	}
	var n int
	return n, d.Con.QueryRow(ctx, q, userID, since).Scan(&n)
}

// ── per-user metrics queries (no new table — derived from sandboxes) ──

// SandboxStatusCount is one row of the live status histogram.
type SandboxStatusCount struct {
	Status string
	Count  int
}

// UserMetricsRow is the raw aggregate row from userMetricsWindow.
type UserMetricsRow struct {
	Spawned        int
	Destroyed      int
	LifetimeMin    float64
	LifetimeP50    float64
	LifetimeP95    float64
	LifetimeAvg    float64
	VcpuSeconds    float64
	MemMibSeconds  float64
	DiskMibSeconds float64
	EgressBytes    int64
	IngressBytes   int64
}

// SandboxShapeRollup is one row of per-shape window aggregates.
type SandboxShapeRollup struct {
	Shape       string
	Count       int
	VcpuSeconds float64
}

// SandboxBucketRow is one row of the bucketed timeseries.
type SandboxBucketRow struct {
	Ts        time.Time
	Spawned   int
	Destroyed int
	Running   int
}

func GetUserMetricsByStatus(ctx context.Context, d *database.Db, userID string) ([]SandboxStatusCount, error) {
	q, err := query(d, "userMetricsByStatus")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SandboxStatusCount
	for rows.Next() {
		var r SandboxStatusCount
		if err := rows.Scan(&r.Status, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func GetUserMetricsWindow(ctx context.Context, d *database.Db, userID string, from, to time.Time) (UserMetricsRow, error) {
	q, err := query(d, "userMetricsWindow")
	if err != nil {
		return UserMetricsRow{}, err
	}
	var w UserMetricsRow
	err = d.Con.QueryRow(ctx, q, userID, from, to).Scan(
		&w.Spawned, &w.Destroyed,
		&w.LifetimeMin, &w.LifetimeP50, &w.LifetimeP95, &w.LifetimeAvg,
		&w.VcpuSeconds, &w.MemMibSeconds, &w.DiskMibSeconds,
		&w.EgressBytes, &w.IngressBytes,
	)
	return w, err
}

func GetUserMetricsByShape(ctx context.Context, d *database.Db, userID string, from, to time.Time) ([]SandboxShapeRollup, error) {
	q, err := query(d, "userMetricsByShape")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, userID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SandboxShapeRollup
	for rows.Next() {
		var r SandboxShapeRollup
		if err := rows.Scan(&r.Shape, &r.Count, &r.VcpuSeconds); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetUserMetricsTimeseries returns one bucket per `bucket` Postgres-
// interval literal ("1 hour" / "1 day").
func GetUserMetricsTimeseries(ctx context.Context, d *database.Db, userID string, from, to time.Time, bucket string) ([]SandboxBucketRow, error) {
	q, err := query(d, "userMetricsTimeseries")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, userID, from, to, bucket)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SandboxBucketRow
	for rows.Next() {
		var b SandboxBucketRow
		if err := rows.Scan(&b.Ts, &b.Spawned, &b.Destroyed, &b.Running); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// SandboxConfigurationPatch carries already-validated fields. Labels is the
// merged map; PreviousLabels is the version used to validate that merge.
type SandboxConfigurationPatch struct {
	IngressEnabled        *bool
	AutoPauseAfterSeconds *int
	DisableAutoPause      bool
	Labels                map[string]string
	PreviousLabels        map[string]string
}

func (r *Repo) PatchSandboxConfiguration(ctx context.Context, id, userID, region string, p SandboxConfigurationPatch) error {
	q, err := query(r.DB, "patchSandboxConfiguration")
	if err != nil {
		return err
	}
	var labels, previous []byte
	if p.Labels != nil {
		labels, err = json.Marshal(p.Labels)
		if err != nil {
			return err
		}
		previous = []byte(`{}`)
		if len(p.PreviousLabels) > 0 {
			previous, err = json.Marshal(p.PreviousLabels)
			if err != nil {
				return err
			}
		}
	}
	tx, ok, err := beginCaptureOperation(ctx, r.DB, id)
	if err != nil {
		return err
	}
	if !ok {
		return ErrSnapshotCaptureConflict
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var updated string
	err = tx.QueryRow(ctx, q, id, userID, region, p.IngressEnabled, p.DisableAutoPause, p.AutoPauseAfterSeconds, labels, previous).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSnapshotCaptureConflict
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
