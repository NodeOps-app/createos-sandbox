package models

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/NodeOps-app/createos-sandbox/database"
	"github.com/jackc/pgx/v5"
)

const SnapshotIDPrefix = "snap_"

type SnapshotType string

const (
	SnapshotTypeDisk SnapshotType = "disk"
	SnapshotTypeFull SnapshotType = "full"
)

type SnapshotStatus string

const (
	SnapshotStatusCreating SnapshotStatus = "creating"
	SnapshotStatusReady    SnapshotStatus = "ready"
	SnapshotStatusFailed   SnapshotStatus = "failed"
	SnapshotStatusDeleting SnapshotStatus = "deleting"
)

// Snapshot is a reusable artifact independent of the source sandbox's lifetime.
// Names are optional display labels, not unique identifiers.
type Snapshot struct {
	CapturedAt *time.Time `json:"captured_at,omitempty" sql:"captured_at"`
	// SandboxID is the capture source, not a dependency on a live sandbox row.
	SandboxID string         `json:"sandbox_id" sql:"sandbox_id"`
	ID        string         `json:"id" sql:"id"`
	UserID    string         `json:"user_id" sql:"user_id"`
	Name      *string        `json:"name,omitempty" sql:"name"`
	Type      SnapshotType   `json:"type" sql:"type"`
	Status    SnapshotStatus `json:"status" sql:"status"`
	// Region owns lifecycle writes; HostID identifies the capture/upload host.
	// Neither field pins subsequent restores to that location.
	Region           string          `json:"region" sql:"region"`
	HostID           *string         `json:"host_id,omitempty" sql:"host_id"`
	Shape            string          `json:"shape" sql:"shape"`
	VCPU             int             `json:"vcpu" sql:"vcpu"`
	MemMib           int             `json:"mem_mib" sql:"mem_mib"`
	DiskMib          int64           `json:"disk_mib" sql:"disk_mib"`
	Rootfs           string          `json:"rootfs" sql:"rootfs"`
	SnapshotURI      *string         `json:"snapshot_uri,omitempty" sql:"snapshot_uri"`
	SnapshotManifest json.RawMessage `json:"snapshot_manifest,omitempty" sql:"snapshot_manifest"`
	SizeBytes        int64           `json:"size_bytes" sql:"size_bytes"`
	ErrorCode        *string         `json:"error_code,omitempty" sql:"error_code"`
	CreatedAt        time.Time       `json:"created_at" sql:"created_at"`
	ReadyAt          *time.Time      `json:"ready_at,omitempty" sql:"ready_at"`
	DeletedAt        *time.Time      `json:"deleted_at,omitempty" sql:"deleted_at"`
}

// InsertSnapshot reserves the source atomically; callers cannot bypass capture
// coordination by using the generic insertion adapter.
func InsertSnapshot(ctx context.Context, d *database.Db, s Snapshot) error {
	_, err := (&Repo{DB: d}).ReserveSnapshotCapture(ctx, s)
	return err
}

func scanSnapshot(row scannable) (*Snapshot, error) {
	var s Snapshot
	var kind, status string
	err := row.Scan(&s.ID, &s.UserID, &s.Name, &kind, &status, &s.Region,
		&s.HostID, &s.Shape, &s.VCPU, &s.MemMib, &s.DiskMib, &s.Rootfs,
		&s.SnapshotURI, &s.SnapshotManifest, &s.SizeBytes, &s.ErrorCode,
		&s.CreatedAt, &s.ReadyAt, &s.DeletedAt, &s.SandboxID, &s.CapturedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s.Type, s.Status = SnapshotType(kind), SnapshotStatus(status)
	return &s, nil
}

func GetSnapshot(ctx context.Context, d *database.Db, id, userID string) (*Snapshot, error) {
	q, err := query(d, "getSnapshot")
	if err != nil {
		return nil, err
	}
	return scanSnapshot(d.Con.QueryRow(ctx, q, id, userID))
}

func ListUserSnapshots(ctx context.Context, d *database.Db, userID string, limit, offset int) ([]Snapshot, error) {
	q, err := query(d, "listUserSnapshots")
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := d.Con.Query(ctx, q, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Snapshot
	for rows.Next() {
		s, err := scanSnapshot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

func CountUserSnapshots(ctx context.Context, d *database.Db, userID string) (int, error) {
	q, err := query(d, "countUserSnapshots")
	if err != nil {
		return 0, err
	}
	var n int
	err = d.Con.QueryRow(ctx, q, userID).Scan(&n)
	return n, err
}

// CountQuotaSnapshots counts retained disk and full snapshots in all regions
// visible locally. Like sandbox quotas, this is a preflight count, not a reservation.
func (r *Repo) CountQuotaSnapshots(ctx context.Context, userID string) (int, error) {
	q, err := query(r.DB, "countQuotaSnapshots")
	if err != nil {
		return 0, err
	}
	var n int
	err = r.DB.Con.QueryRow(ctx, q, userID).Scan(&n)
	return n, err
}

// Lifecycle updates return an empty status on a CAS miss. Callers must not
// interpret a nil error as permission to perform follow-up side effects.
// Region and host must come from trusted control/host identity, not public input.
func MarkSnapshotReady(ctx context.Context, d *database.Db, id, userID, region, hostID, uri string, manifest json.RawMessage, sizeBytes int64) (string, error) {
	q, err := query(d, "markSnapshotReady")
	if err != nil {
		return "", err
	}
	return scanCASStatus(d.Con.QueryRow(ctx, q, id, userID, region, hostID, uri, manifest, sizeBytes))
}

// MarkSnapshotFailed also releases an unfinished capture reservation. Workers
// must recover a frozen source (or confirm it has exited) before calling this;
// a transient probe failure or service restart alone is not a terminal outcome.
func MarkSnapshotFailed(ctx context.Context, d *database.Db, id, userID, region, hostID, errorCode string) (string, error) {
	q, err := query(d, "markSnapshotFailed")
	if err != nil {
		return "", err
	}
	return scanCASStatus(d.Con.QueryRow(ctx, q, id, userID, region, hostID, errorCode))
}

// SoftDeleteSnapshot hides completed captures without deleting their bucket files.
func SoftDeleteSnapshot(ctx context.Context, d *database.Db, id, userID, region string) (string, error) {
	q, err := query(d, "softDeleteSnapshot")
	if err != nil {
		return "", err
	}
	return scanCASStatus(d.Con.QueryRow(ctx, q, id, userID, region))
}

var ErrSnapshotCaptureConflict = errors.New("sandbox state changed or snapshot capture in progress")

// beginCaptureOperation serializes capture with competing lifecycle writes.
// READ COMMITTED and separate statements are intentional: after waiting for the
// sandbox lock, the capture check must see the preceding transaction's insert.
func beginCaptureOperation(ctx context.Context, d *database.Db, id string) (pgx.Tx, bool, error) {
	lock, err := query(d, "lockSandboxForCaptureOperation")
	if err != nil {
		return nil, false, err
	}
	active, err := query(d, "hasActiveSnapshotCapture")
	if err != nil {
		return nil, false, err
	}
	tx, err := d.Con.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, false, err
	}
	var got string
	err = tx.QueryRow(ctx, lock, id).Scan(&got)
	if err != nil {
		_ = tx.Rollback(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var busy bool
	if err = tx.QueryRow(ctx, active, id).Scan(&busy); err != nil || busy {
		_ = tx.Rollback(ctx)
		return nil, false, err
	}
	return tx, true, nil
}

func guardedSandboxTransition(ctx context.Context, d *database.Db, id, queryName string, args ...any) (string, error) {
	q, err := query(d, queryName)
	if err != nil {
		return "", err
	}
	tx, ok, err := beginCaptureOperation(ctx, d, id)
	if err != nil || !ok {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// A paused source's bundle must remain unchanged while a fork copies it.
	activeFork, err := query(d, "hasActiveFork")
	if err != nil {
		return "", err
	}
	var copying bool
	if err = tx.QueryRow(ctx, activeFork, id).Scan(&copying); err != nil || copying {
		return "", err
	}
	status, err := scanCASStatus(tx.QueryRow(ctx, q, args...))
	if err != nil {
		return "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return "", err
	}
	return status, nil
}

// ReserveSnapshotCapture reads source configuration under the same row lock used
// by pause/resume/delete and disk attach. It never changes the sandbox row.
func (r *Repo) ReserveSnapshotCapture(ctx context.Context, s Snapshot) (*Snapshot, error) {
	tx, ok, err := beginCaptureOperation(ctx, r.DB, s.SandboxID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrSnapshotCaptureConflict
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q, err := query(r.DB, "getSandbox")
	if err != nil {
		return nil, err
	}
	src, err := scanSandbox(tx.QueryRow(ctx, q, s.SandboxID))
	if err != nil {
		return nil, err
	}
	if src.CreatedBy != s.UserID || IsPoolOwnerID(src.CreatedBy) || src.Region != s.Region ||
		src.Status != StatusRunning ||
		src.Rootfs == nil || strings.TrimSpace(*src.Rootfs) == "" || src.VCPU <= 0 || src.MemMib <= 0 || src.DiskMib <= 0 {
		return nil, ErrSnapshotCaptureConflict
	}
	if src.HostID == nil || strings.TrimSpace(*src.HostID) == "" {
		return nil, ErrSnapshotCaptureConflict
	}

	q, err = query(r.DB, "snapshotSourceHasDisks")
	if err != nil {
		return nil, err
	}
	var attached bool
	if err = tx.QueryRow(ctx, q, src.ID).Scan(&attached); err != nil {
		return nil, err
	}
	if attached {
		return nil, ErrSnapshotCaptureConflict
	}
	s.HostID = src.HostID

	s.Shape = src.Shape
	s.VCPU = src.VCPU
	s.MemMib = src.MemMib
	s.DiskMib = src.DiskMib
	s.Rootfs = *src.Rootfs
	q, err = query(r.DB, "insertSnapshot")
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, q, s.ID, s.UserID, s.Name, string(s.Type), s.Region, s.HostID, s.Shape, s.VCPU, s.MemMib, s.DiskMib, s.Rootfs, s.SandboxID); err != nil {
		return nil, err
	}
	q, err = query(r.DB, "getSnapshot")
	if err != nil {
		return nil, err
	}
	result, err := scanSnapshot(tx.QueryRow(ctx, q, s.ID, s.UserID))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

// MarkSnapshotCaptured releases the source only after the worker has completed
// local capture/recovery. It does not make an uploading snapshot ready.
func (r *Repo) MarkSnapshotCaptured(ctx context.Context, id, userID, region, hostID string) (string, error) {
	q, err := query(r.DB, "markSnapshotCaptured")
	if err != nil {
		return "", err
	}
	return scanCASStatus(r.DB.Con.QueryRow(ctx, q, id, userID, region, hostID))
}

// HasActiveSnapshotCapture is a preflight check only; lifecycle writers must
// still use beginCaptureOperation to serialize the check and mutation.
func (r *Repo) HasActiveSnapshotCapture(ctx context.Context, id string) (bool, error) {
	q, err := query(r.DB, "hasActiveSnapshotCapture")
	if err != nil {
		return false, err
	}
	var active bool
	err = r.DB.Con.QueryRow(ctx, q, id).Scan(&active)
	return active, err
}

// Host snapshot reads are scoped to the worker identity and owning region,
// independently of source sandbox placement after capture has finished.
func (r *Repo) GetHostSnapshot(ctx context.Context, id, host, region string) (*Snapshot, error) {
	q, err := query(r.DB, "getHostSnapshot")
	if err != nil {
		return nil, err
	}
	return scanSnapshot(r.DB.Con.QueryRow(ctx, q, id, host, region))
}
func (r *Repo) ListHostSnapshotJobs(ctx context.Context, host, region string) ([]Snapshot, error) {
	q, err := query(r.DB, "listHostSnapshotJobs")
	if err != nil {
		return nil, err
	}
	rows, err := r.DB.Con.Query(ctx, q, host, region)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Snapshot{}
	for rows.Next() {
		s, err := scanSnapshot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// SnapshotCaptureSource exposes only the source state needed by an
// assigned worker, never the source's environment, credentials or access token.
type SnapshotCaptureSource struct {
	Status Status `json:"status"`
}

func (r *Repo) SnapshotCaptureSource(ctx context.Context, id, host, region string) (*SnapshotCaptureSource, error) {
	q, err := query(r.DB, "snapshotCaptureSource")
	if err != nil {
		return nil, err
	}
	var src SnapshotCaptureSource
	err = r.DB.Con.QueryRow(ctx, q, id, host, region).Scan(&src.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &src, err
}
