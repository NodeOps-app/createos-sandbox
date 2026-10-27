// Package models — issued_certs ledger.
//
// Every TLS leaf cert ever minted by the in-process CA lives here as one
// row, append-only. Rotation inserts a new row and stamps the prior row
// with a revocation tombstone (for hosts, deferred 24h via the sweep so
// in-flight handshakes drain). The CRL endpoint scans this table for
// every non-NULL `revoked_at`.
//
// pgEdge / Spock multi-master compatibility: PK is the 128-bit random
// cert_serial (no collisions across replicas), every column is plain
// timestamptz / text (no SERIAL, no SEQUENCE, no global counter). The
// `replaced_by` column carries the successor serial as plain text — no
// self-referencing FK because Spock's per-table replication doesn't
// cleanly resolve cross-row constraint violations during replay.
package models

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/NodeOps-app/sandbox/database"
)

// CertKind is the actor class a cert was issued for. Used as the
// `subject_kind` column on issued_certs + the SPIFFE URI shape on the
// leaf SAN (`spiffe://createos/<kind>/<id>`).
type CertKind string

const (
	CertKindHost      CertKind = "host"
	CertKindControl   CertKind = "control"
	CertKindIngress   CertKind = "ingress"
	CertKindGateway   CertKind = "gateway"
	CertKindProxy     CertKind = "proxy"
	CertKindScheduler CertKind = "scheduler"
)

// ValidCertKinds is the canonical allowlist used by the CSR handler +
// CLI to reject bogus kinds at the door.
var ValidCertKinds = map[CertKind]struct{}{
	CertKindHost:      {},
	CertKindControl:   {},
	CertKindIngress:   {},
	CertKindGateway:   {},
	CertKindProxy:     {},
	CertKindScheduler: {},
}

// CertStatus is the derived lifecycle state of a cert. Not stored on the
// row — computed at read time from (revoked_at, expires_at, now()). The
// SQL view `cert_status` re-implements this so callers can filter
// directly in their query when convenient.
type CertStatus string

const (
	CertStatusActive  CertStatus = "active"
	CertStatusExpired CertStatus = "expired"
	CertStatusRevoked CertStatus = "revoked"
)

// TTL constants per actor class. Hosts get 90 days because they're the
// most-likely-compromised tier (publicly exposed, broadest privilege)
// and a shorter window caps the blast radius of a leaked key. Everything
// else gets 1 year because those processes run inside the k8s cluster,
// rotate their pods on every deploy, and the leak surface is much
// smaller.
const (
	CertTTLHost      = 90 * 24 * time.Hour
	CertTTLControl   = 365 * 24 * time.Hour
	CertTTLIngress   = 365 * 24 * time.Hour
	CertTTLGateway   = 365 * 24 * time.Hour
	CertTTLProxy     = 365 * 24 * time.Hour
	CertTTLScheduler = 365 * 24 * time.Hour
)

// CertTTL returns the lifetime that should be stamped on a freshly-issued
// leaf cert for the given kind. Unknown kinds fall through to the
// shortest TTL (host's 90 days) as a fail-safe.
func CertTTL(k CertKind) time.Duration {
	switch k {
	case CertKindHost:
		return CertTTLHost
	case CertKindControl:
		return CertTTLControl
	case CertKindIngress:
		return CertTTLIngress
	case CertKindGateway:
		return CertTTLGateway
	case CertKindProxy:
		return CertTTLProxy
	case CertKindScheduler:
		return CertTTLScheduler
	}
	return CertTTLHost
}

// HostRotateRevokeGrace is the delay between issuing a successor host
// cert and tombstoning the predecessor. Hosts run a long-lived
// createos-serve process whose in-memory tls.Config still references
// the old leaf until the systemd restart triggered by the renewer
// completes. The grace lets in-flight handshakes on the predecessor
// drain naturally; the sweep flips `revoked_at` once the grace window
// elapses. Non-host actors don't get a grace — their CSR caller is
// expected to swap-and-restart atomically.
const HostRotateRevokeGrace = 24 * time.Hour

// IssuedCert mirrors one row in the issued_certs ledger. Pointer fields
// are nullable in the schema.
type IssuedCert struct {
	CertSerial        string     `json:"cert_serial"`
	SubjectKind       CertKind   `json:"subject_kind"`
	SubjectID         string     `json:"subject_id"`
	IssuedAt          time.Time  `json:"issued_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	RevokedBy         *string    `json:"revoked_by,omitempty"`
	ReplacedBy        *string    `json:"replaced_by,omitempty"`
	ScheduledRevokeAt *time.Time `json:"scheduled_revoke_at,omitempty"`
}

// Status returns the derived lifecycle state at the given moment.
func (c *IssuedCert) Status(now time.Time) CertStatus {
	if c.RevokedAt != nil && !c.RevokedAt.After(now) {
		return CertStatusRevoked
	}
	if !c.ExpiresAt.After(now) {
		return CertStatusExpired
	}
	return CertStatusActive
}

// ─── Revocation actor strings ─────────────────────────────────────────
// `revoked_by` is freeform but we standardise the values written by the
// system itself; admin revocations get prefixed with the operator id.

const (
	RevokeByRotation    = "rotation"
	RevokeByCompromise  = "compromise"
	RevokeByAdminPrefix = "admin:"
)

// ─── DB operations ────────────────────────────────────────────────────

// InsertIssuedCert appends a freshly-issued leaf to the ledger. cert_serial
// uniqueness is enforced by the table's PK — a duplicate (extremely
// unlikely with 128-bit random serials) bubbles up as a 23505 violation.
func InsertIssuedCert(ctx context.Context, d *database.Db, c IssuedCert) error {
	q, err := query(d, "insertIssuedCert")
	if err != nil {
		return err
	}
	if _, err := d.Con.Exec(ctx, q,
		c.CertSerial, string(c.SubjectKind), c.SubjectID, c.ExpiresAt,
	); err != nil {
		return fmt.Errorf("insertIssuedCert %s: %w", c.CertSerial, err)
	}
	return nil
}

// RotateCertImmediate is the non-host rotation: insert successor + revoke
// every prior active cert for the same subject in one transaction. The
// predecessor is gone from "active" the instant this returns.
func RotateCertImmediate(ctx context.Context, d *database.Db, newCert IssuedCert) error {
	tx, err := d.Con.Begin(ctx)
	if err != nil {
		return fmt.Errorf("rotateCertImmediate begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	insertQ, err := query(d, "insertIssuedCert")
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, insertQ,
		newCert.CertSerial, string(newCert.SubjectKind), newCert.SubjectID, newCert.ExpiresAt,
	); err != nil {
		return fmt.Errorf("rotateCertImmediate insert: %w", err)
	}

	revokeQ, err := query(d, "revokePriorOnRotateImmediate")
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, revokeQ,
		string(newCert.SubjectKind), newCert.SubjectID, newCert.CertSerial,
	); err != nil {
		return fmt.Errorf("rotateCertImmediate revoke prior: %w", err)
	}
	return tx.Commit(ctx)
}

// RotateCertWithGrace is the host rotation: insert successor and stamp
// `scheduled_revoke_at = now() + grace` on every prior active cert for
// the same subject. The sweep flips `revoked_at` once the grace window
// elapses. Returns immediately with the predecessor still considered
// active by the CRL.
func RotateCertWithGrace(ctx context.Context, d *database.Db, newCert IssuedCert, grace time.Duration) error {
	tx, err := d.Con.Begin(ctx)
	if err != nil {
		return fmt.Errorf("rotateCertWithGrace begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	insertQ, err := query(d, "insertIssuedCert")
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, insertQ,
		newCert.CertSerial, string(newCert.SubjectKind), newCert.SubjectID, newCert.ExpiresAt,
	); err != nil {
		return fmt.Errorf("rotateCertWithGrace insert: %w", err)
	}

	scheduleQ, err := query(d, "scheduleRevokePriorOnRotate")
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, scheduleQ,
		string(newCert.SubjectKind), newCert.SubjectID, newCert.CertSerial, grace.String(),
	); err != nil {
		return fmt.Errorf("rotateCertWithGrace schedule: %w", err)
	}
	return tx.Commit(ctx)
}

// RevokeIssuedCert tombstones a single cert by serial. `actor` is the
// freeform reason string (RevokeByCompromise, RevokeByAdminPrefix+uid,
// etc.). No-op if the cert is already revoked.
func RevokeIssuedCert(ctx context.Context, d *database.Db, serial, actor string) error {
	q, err := query(d, "revokeIssuedCert")
	if err != nil {
		return err
	}
	if _, err := d.Con.Exec(ctx, q, serial, actor); err != nil {
		return fmt.Errorf("revokeIssuedCert %s: %w", serial, err)
	}
	return nil
}

// ApplyScheduledRevocations is called by the sweep CronJob. Flips
// `revoked_at = scheduled_revoke_at` on every row where the schedule has
// elapsed and the cert isn't already revoked. Returns the number of rows
// tombstoned.
func ApplyScheduledRevocations(ctx context.Context, d *database.Db, now time.Time) (int, error) {
	q, err := query(d, "applyScheduledRevocations")
	if err != nil {
		return 0, err
	}
	tag, err := d.Con.Exec(ctx, q, now)
	if err != nil {
		return 0, fmt.Errorf("applyScheduledRevocations: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// GetActiveCert returns the most recent active (non-revoked, unexpired)
// cert for the given subject. Returns (nil, nil) when there isn't one.
func GetActiveCert(ctx context.Context, d *database.Db, kind CertKind, subjectID string) (*IssuedCert, error) {
	q, err := query(d, "getActiveCertForSubject")
	if err != nil {
		return nil, err
	}
	row := d.Con.QueryRow(ctx, q, string(kind), subjectID)
	var c IssuedCert
	var subjectKind string
	if err := row.Scan(
		&c.CertSerial, &subjectKind, &c.SubjectID,
		&c.IssuedAt, &c.ExpiresAt,
		&c.RevokedAt, &c.RevokedBy, &c.ReplacedBy, &c.ScheduledRevokeAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("getActiveCert %s/%s: %w", kind, subjectID, err)
	}
	c.SubjectKind = CertKind(subjectKind)
	return &c, nil
}

// ListIssuedCerts returns the full ledger for a single subject ordered
// newest-first. Useful for operator queries + the CLI's `ca list`
// command.
func ListIssuedCerts(ctx context.Context, d *database.Db, kind CertKind, subjectID string) ([]IssuedCert, error) {
	q, err := query(d, "listIssuedCertsForSubject")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, string(kind), subjectID)
	if err != nil {
		return nil, fmt.Errorf("listIssuedCerts: %w", err)
	}
	defer rows.Close()
	out := make([]IssuedCert, 0)
	for rows.Next() {
		var c IssuedCert
		var subjectKind string
		if err := rows.Scan(
			&c.CertSerial, &subjectKind, &c.SubjectID,
			&c.IssuedAt, &c.ExpiresAt,
			&c.RevokedAt, &c.RevokedBy, &c.ReplacedBy, &c.ScheduledRevokeAt,
		); err != nil {
			return nil, fmt.Errorf("listIssuedCerts scan: %w", err)
		}
		c.SubjectKind = CertKind(subjectKind)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListRevokedSerialsLedger feeds the CRL endpoint. Single-table read
// against issued_certs — replaces the legacy two-table UNION.
func ListRevokedSerialsLedger(ctx context.Context, d *database.Db) ([]string, error) {
	q, err := query(d, "listRevokedSerialsLedger")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("listRevokedSerialsLedger: %w", err)
	}
	defer rows.Close()
	out := make([]string, 0)
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("listRevokedSerialsLedger scan: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
