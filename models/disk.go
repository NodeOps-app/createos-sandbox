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

// DiskIDPrefix is the canonical prefix for `disks.id`.
const DiskIDPrefix = "disk_"

// DiskKind values. Future kinds (gcs, nfs, webdav, ...) get their own
// constants here; each kind owns its own config + credentials schema.
const (
	DiskKindS3 = "s3"
)

// SandboxDiskStatus values. The agent reports mounted|failed back; the
// row is reset to pending at pause time and on every fresh attach.
const (
	SandboxDiskStatusPending = "pending"
	SandboxDiskStatusMounted = "mounted"
	SandboxDiskStatusFailed  = "failed"
)

// ErrDiskAttached is returned by DeleteDisk when sandboxes still reference
// the disk via sandbox_disks.
var ErrDiskAttached = fmt.Errorf("disk has active attachments")

// Disk mirrors one row of the disks table. Credentials is stored as a
// JSON envelope (see internal/apiserver/diskcrypto) and is NEVER returned
// in any user-facing projection — keep it out of any handler response.
type Disk struct {
	ID          string          `json:"id" sql:"id"`
	UserID      string          `json:"user_id" sql:"user_id"`
	Name        string          `json:"name" sql:"name"`
	Kind        string          `json:"kind" sql:"kind"`
	Config      json.RawMessage `json:"config" sql:"config"`
	Credentials json.RawMessage `json:"-" sql:"credentials"`
	CreatedAt   time.Time       `json:"created_at" sql:"created_at"`
	DeletedAt   *time.Time      `json:"deleted_at,omitempty" sql:"deleted_at"`
}

// SandboxDisk mirrors one row of the sandbox_disks join table, augmented
// with the disk's display fields for user-facing lists.
type SandboxDisk struct {
	DiskID      string          `json:"disk_id" sql:"disk_id"`
	Name        string          `json:"name" sql:"name"`
	Kind        string          `json:"kind" sql:"kind"`
	Config      json.RawMessage `json:"config" sql:"config"`
	MountPath   string          `json:"mount_path" sql:"mount_path"`
	SubPath     string          `json:"sub_path,omitempty" sql:"sub_path"`
	MountStatus string          `json:"mount_status" sql:"mount_status"`
	MountError  *string         `json:"mount_error,omitempty" sql:"mount_error"`
	CreatedAt   time.Time       `json:"created_at" sql:"created_at"`
}

// ResolvedDisk is the host-bound, decrypted bundle for one attachment.
// Never persisted; lives only inside a single forward-request lifetime.
type ResolvedDisk struct {
	DiskID      string          `json:"disk_id"`
	Kind        string          `json:"kind"`
	Config      json.RawMessage `json:"config"`
	Credentials json.RawMessage `json:"credentials"` // plaintext, AES-GCM decrypted by control
	MountPath   string          `json:"mount_path"`
}

func InsertDisk(ctx context.Context, d *database.Db, rec *Disk) error {
	q, err := query(d, "insertDisk")
	if err != nil {
		return err
	}
	return d.Con.QueryRow(ctx, q, rec.ID, rec.UserID, rec.Name, rec.Kind,
		string(rec.Config), string(rec.Credentials)).Scan(&rec.CreatedAt)
}

// GetDisk resolves by disk_ id or by name (user-scoped). Returns nil
// when not found — callers must 404 their own way.
func GetDisk(ctx context.Context, d *database.Db, userID, idOrName string) (*Disk, error) {
	var q string
	var qerr error
	if strings.HasPrefix(idOrName, DiskIDPrefix) {
		q, qerr = query(d, "getDiskByID")
	} else {
		q, qerr = query(d, "getDiskByName")
	}
	if qerr != nil {
		return nil, qerr
	}
	disk := &Disk{}
	err := d.Con.QueryRow(ctx, q, idOrName, userID).Scan(
		&disk.ID, &disk.UserID, &disk.Name, &disk.Kind,
		&disk.Config, &disk.Credentials, &disk.CreatedAt, &disk.DeletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return disk, nil
}

func ListDisks(ctx context.Context, d *database.Db, userID string, limit, offset int) ([]Disk, error) {
	q, err := query(d, "listDisks")
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := d.Con.Query(ctx, q, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Disk
	for rows.Next() {
		var disk Disk
		if err := rows.Scan(&disk.ID, &disk.UserID, &disk.Name, &disk.Kind,
			&disk.Config, &disk.CreatedAt, &disk.DeletedAt); err != nil {
			return nil, err
		}
		out = append(out, disk)
	}
	return out, rows.Err()
}

// CountUserDisks returns the total number of non-deleted disks the user
// owns. Drives pagination.total on GET /v1/disks.
func CountUserDisks(ctx context.Context, d *database.Db, userID string) (int, error) {
	q, err := query(d, "countUserDisks")
	if err != nil {
		return 0, err
	}
	var n int
	if err := d.Con.QueryRow(ctx, q, userID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// DeleteDisk soft-deletes the row. Returns ErrDiskAttached if any
// non-destroyed sandbox still holds an attachment — caller should 409.
// Lock the disk first, then count attachments using a fresh READ COMMITTED
// statement snapshot. A single locking CTE can miss an attach committed while
// the delete statement waited for the disk lock.
func DeleteDisk(ctx context.Context, d *database.Db, userID, idOrName string) error {
	disk, err := GetDisk(ctx, d, userID, idOrName)
	if err != nil {
		return err
	}
	if disk == nil {
		return pgx.ErrNoRows
	}
	lock, err := query(d, "lockDiskForDelete")
	if err != nil {
		return err
	}
	q, err := query(d, "deleteDiskIfUnattached")
	if err != nil {
		return err
	}
	tx, err := d.Con.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var lockedID string
	if err := tx.QueryRow(ctx, lock, disk.ID, userID).Scan(&lockedID); err != nil {
		return err
	}
	var existsRow, deleted bool
	var attachedCnt int
	if err := tx.QueryRow(ctx, q, disk.ID, userID).Scan(&existsRow, &attachedCnt, &deleted); err != nil {
		return err
	}
	if !existsRow {
		return pgx.ErrNoRows
	}
	if attachedCnt > 0 {
		return ErrDiskAttached
	}
	if !deleted {
		// Lock held but neither attached nor deleted — shouldn't happen.
		return fmt.Errorf("delete-disk: unexpected non-update")
	}
	return tx.Commit(ctx)
}

// UpdateDiskCredentials rewrites the AES-GCM envelope on an existing
// disk. Owner-scoped so a leaked id alone can't rotate someone else's
// disk. Returns pgx.ErrNoRows when no matching row exists.
func UpdateDiskCredentials(ctx context.Context, d *database.Db, diskID, userID string, encrypted json.RawMessage) error {
	q, err := query(d, "updateDiskCredentials")
	if err != nil {
		return err
	}
	var gotID string
	err = d.Con.QueryRow(ctx, q, string(encrypted), diskID, userID).Scan(&gotID)
	if errors.Is(err, pgx.ErrNoRows) {
		return pgx.ErrNoRows
	}
	return err
}

// RunningSandboxAttachment is one attachment of a disk to a running
// sandbox, augmented with the host the sandbox lives on so control can
// fan out an MMDS refresh.
type RunningSandboxAttachment struct {
	SandboxID     string
	MountPath     string
	SubPath       string
	HostID        string
	HostAddr      string
	HostPublicKey []byte
}

// ListRunningSandboxesForDisk returns every (sandbox, host, mount_path)
// tuple for running sandboxes attached to the given disk. Used by the
// credential-rotate endpoint to push fresh creds via MMDS without a
// pause/resume cycle.
func ListRunningSandboxesForDisk(ctx context.Context, d *database.Db, diskID string) ([]RunningSandboxAttachment, error) {
	q, err := query(d, "listRunningSandboxesForDisk")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, diskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunningSandboxAttachment
	for rows.Next() {
		var a RunningSandboxAttachment
		if err := rows.Scan(&a.SandboxID, &a.MountPath, &a.SubPath, &a.HostID, &a.HostAddr, &a.HostPublicKey); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AttachDisk inserts a sandbox_disks row. Caller is responsible for
// having already validated the disk belongs to the sandbox's owner.
// subPath is the optional bucket sub-folder; empty = mount bucket root.
func AttachDisk(ctx context.Context, d *database.Db, sandboxID, diskID, mountPath, subPath string) error {
	q, err := query(d, "attachDisk")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, sandboxID, diskID, mountPath, subPath)
	return err
}

// AttachDiskIfRunning is the TOCTOU-safe live-attach path: locks the
// sandbox row and inserts only if status='running' at lock time.
// Returns (running, inserted): running=false means the sandbox flipped
// out of 'running' (most commonly into 'pausing') between the handler's
// read and this write; the caller should surface 409 rather than
// inserting a dangling row that won't make it into the snapshot bundle.
// inserted=false with running=true means the same (sandbox, disk,
// mount_path) row already exists (idempotent re-attach).
func AttachDiskIfRunning(ctx context.Context, d *database.Db, sandboxID, diskID, mountPath, subPath string) (running, inserted, diskExists bool, err error) {
	q, err := query(d, "attachDiskIfRunning")
	if err != nil {
		return false, false, false, err
	}
	tx, ok, err := beginCaptureOperation(ctx, d, sandboxID)
	if err != nil {
		return false, false, false, err
	}
	if !ok {
		return false, false, false, ErrSnapshotCaptureConflict
	}
	defer func() { _ = tx.Rollback(ctx) }()
	err = tx.QueryRow(ctx, q, sandboxID, diskID, mountPath, subPath).Scan(&running, &inserted, &diskExists)
	if errors.Is(err, pgx.ErrNoRows) {
		// sandboxes row not found.
		return false, false, false, pgx.ErrNoRows
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	return running, inserted, diskExists, err
}

// DetachDisk removes a single sandbox_disks row keyed by mount_path.
// A disk can be attached at multiple paths; this drops the one at
// `mountPath`. Returns pgx.ErrNoRows if no such attachment exists.
func DetachDisk(ctx context.Context, d *database.Db, sandboxID, diskID, mountPath string) error {
	q, err := query(d, "detachDisk")
	if err != nil {
		return err
	}
	tx, ok, err := beginCaptureOperation(ctx, d, sandboxID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrSnapshotCaptureConflict
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var gotID string
	if err = tx.QueryRow(ctx, q, sandboxID, diskID, mountPath).Scan(&gotID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func ListSandboxDisks(ctx context.Context, d *database.Db, sandboxID string) ([]SandboxDisk, error) {
	q, err := query(d, "listSandboxDisks")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, sandboxID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SandboxDisk
	for rows.Next() {
		var sd SandboxDisk
		if err := rows.Scan(&sd.DiskID, &sd.Name, &sd.Kind, &sd.Config,
			&sd.MountPath, &sd.SubPath, &sd.MountStatus, &sd.MountError, &sd.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, sd)
	}
	return out, rows.Err()
}

// ResolveSandboxDisks returns the encrypted-creds bundle for every disk
// attached to a sandbox. Used by control on create-forward and on the
// host-scoped /v1/internal/sandboxes/:id/disks endpoint.
// ResolveSandboxDisks returns the encrypted-creds bundle + per-attachment
// paths (mount + bucket sub-folder) for every disk attached to a sandbox.
func ResolveSandboxDisks(ctx context.Context, d *database.Db, sandboxID string) ([]Disk, []string, []string, error) {
	q, err := query(d, "resolveSandboxDisks")
	if err != nil {
		return nil, nil, nil, err
	}
	rows, err := d.Con.Query(ctx, q, sandboxID)
	if err != nil {
		return nil, nil, nil, err
	}
	defer rows.Close()
	var disks []Disk
	var mountPaths []string
	var subPaths []string
	for rows.Next() {
		var disk Disk
		var mp, sp string
		if err := rows.Scan(&disk.ID, &disk.Kind, &disk.Config, &disk.Credentials, &mp, &sp); err != nil {
			return nil, nil, nil, err
		}
		disks = append(disks, disk)
		mountPaths = append(mountPaths, mp)
		subPaths = append(subPaths, sp)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, err
	}
	return disks, mountPaths, subPaths, nil
}

// SetSandboxDiskStatus updates the per-attachment mount status reported
// by the guest. mountError may be empty when status == 'mounted'.
// mountPath is part of the key so two attachments of the same disk
// (at different paths) get independent status.
func SetSandboxDiskStatus(ctx context.Context, d *database.Db, sandboxID, diskID, mountPath, status, mountError string) error {
	q, err := query(d, "setSandboxDiskStatus")
	if err != nil {
		return err
	}
	var errPtr *string
	if mountError != "" {
		// Truncate to 1 KiB so a deeply broken FUSE error log can't
		// stuff arbitrary bytes into the row.
		if len(mountError) > 1024 {
			mountError = mountError[:1024]
		}
		errPtr = &mountError
	}
	_, err = d.Con.Exec(ctx, q, sandboxID, diskID, status, errPtr, mountPath)
	return err
}

// ResetSandboxDiskStatus flips every attachment of a sandbox back to
// 'pending' — called when the host is about to unmount (pause) so the
// surfaced status doesn't lie.
func ResetSandboxDiskStatus(ctx context.Context, d *database.Db, sandboxID string) error {
	q, err := query(d, "resetSandboxDiskStatus")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, sandboxID)
	return err
}

func CountDisksActive(ctx context.Context, d *database.Db, userID string) (int, error) {
	q, err := query(d, "countDisksActive")
	if err != nil {
		return 0, err
	}
	var n int
	return n, d.Con.QueryRow(ctx, q, userID).Scan(&n)
}

func CountDisksSince(ctx context.Context, d *database.Db, userID string, since time.Time) (int, error) {
	q, err := query(d, "countDisksSince")
	if err != nil {
		return 0, err
	}
	var n int
	return n, d.Con.QueryRow(ctx, q, userID, since).Scan(&n)
}
