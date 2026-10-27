package models

import (
	"context"
	"encoding/json"
	"time"

	"github.com/NodeOps-app/sandbox/database"

	"github.com/jackc/pgx/v5"
)

const AuditEventIDPrefix = "aud_"

// AuditEvent mirrors one row of the audit_events table. Persisted for
// every audited action regardless of caller. Webhook fan-out skips
// when is_internal=true (see ClaimPendingWebhookDeliveries).
type AuditEvent struct {
	ID            string          `json:"id"             sql:"id"`
	UserID        string          `json:"user_id"        sql:"user_id"`
	Action        string          `json:"action"         sql:"action"`
	OperationType string          `json:"operation_type" sql:"operation_type"`
	Actor         *string         `json:"actor"          sql:"actor"`
	HashedToken   *string         `json:"hashed_token"   sql:"hashed_token"`
	RequestID     *string         `json:"request_id"     sql:"request_id"`
	UserAgent     *string         `json:"user_agent"     sql:"user_agent"`
	IPAddress     *string         `json:"ip_address"     sql:"ip_address"`
	ExpiresAt     *time.Time      `json:"expires_at"     sql:"expires_at"`
	Metadata      json.RawMessage `json:"metadata"       sql:"metadata"`
	SubjectType   *string         `json:"subject_type"   sql:"subject_type"`
	SubjectID     *string         `json:"subject_id"     sql:"subject_id"`
	OccurredAt    time.Time       `json:"occurred_at"    sql:"occurred_at"`
	IsInternal    bool            `json:"is_internal"    sql:"is_internal"`
	// Shipping state (outbox columns). Zero values are fine on insert
	// — table defaults to status='pending', attempts=0, next_attempt_at=now().
	Attempts int `json:"-" sql:"attempts"`
}

func InsertAuditEvent(ctx context.Context, tx pgx.Tx, d *database.Db, e AuditEvent) error {
	q, err := query(d, "insertAuditEvent")
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, q,
		e.ID, e.UserID, e.Action, e.OperationType,
		e.Actor, e.HashedToken, e.RequestID, e.UserAgent, e.IPAddress,
		e.ExpiresAt, string(e.Metadata), e.SubjectType, e.SubjectID,
		e.OccurredAt, e.IsInternal,
	)
	return err
}

// ListAuditEventsForUser returns the user's events newest-first.
// limit/offset are caller-validated.
func ListAuditEventsForUser(ctx context.Context, d *database.Db, userID string, limit, offset int) ([]AuditEvent, error) {
	q, err := query(d, "listAuditEventsForUser")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(
			&e.ID, &e.UserID, &e.Action, &e.OperationType,
			&e.Actor, &e.HashedToken, &e.RequestID, &e.UserAgent, &e.IPAddress,
			&e.ExpiresAt, &e.Metadata, &e.SubjectType, &e.SubjectID,
			&e.OccurredAt, &e.IsInternal,
		); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func CountAuditEventsForUser(ctx context.Context, d *database.Db, userID string) (int, error) {
	q, err := query(d, "countAuditEventsForUser")
	if err != nil {
		return 0, err
	}
	var n int
	return n, d.Con.QueryRow(ctx, q, userID).Scan(&n)
}

// SweepExpiredAuditEvents deletes rows past their ExpiresAt. Run on a
// cron — retention is per-user policy, default 90d.
func SweepExpiredAuditEvents(ctx context.Context, d *database.Db) (int64, error) {
	q, err := query(d, "sweepExpiredAuditEvents")
	if err != nil {
		return 0, err
	}
	tag, err := d.Con.Exec(ctx, q)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// Shipping state — mirrors billing_events.status semantics.
const (
	AuditStatusPending          = "pending"
	AuditStatusShipped          = "shipped"
	AuditStatusPermanentFailure = "permanent_failure"
)

// ClaimPendingAuditEvents reserves up to `limit` events ready for
// backend shipping. FOR UPDATE SKIP LOCKED partitions work across
// replicas. Caller owns the returned tx — must Commit or Rollback.
// Locks release at tx end.
func ClaimPendingAuditEvents(ctx context.Context, d *database.Db, limit int) (pgx.Tx, []AuditEvent, error) {
	q, err := query(d, "claimPendingAuditEvents")
	if err != nil {
		return nil, nil, err
	}
	tx, err := d.Con.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	rows, err := tx.Query(ctx, q, limit)
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, nil, err
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(
			&e.ID, &e.UserID, &e.Action, &e.OperationType,
			&e.Actor, &e.HashedToken, &e.RequestID, &e.UserAgent, &e.IPAddress,
			&e.ExpiresAt, &e.Metadata, &e.SubjectType, &e.SubjectID,
			&e.OccurredAt, &e.IsInternal,
			&e.Attempts,
		); err != nil {
			_ = tx.Rollback(ctx)
			return nil, nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		_ = tx.Rollback(ctx)
		return nil, nil, err
	}
	return tx, out, nil
}

func MarkAuditEventShipped(ctx context.Context, tx pgx.Tx, d *database.Db, id string) error {
	q, err := query(d, "markAuditEventShipped")
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, q, id)
	return err
}

func MarkAuditEventPermanentFailure(ctx context.Context, tx pgx.Tx, d *database.Db, id, msg string) error {
	q, err := query(d, "markAuditEventPermanentFailure")
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, q, id, msg)
	return err
}

// BumpAuditEventShipAttempt increments attempts and schedules retry.
// status stays 'pending'. Caller computes nextAt via exponential backoff.
func BumpAuditEventShipAttempt(ctx context.Context, tx pgx.Tx, d *database.Db, id, errMsg string, nextAt time.Time) error {
	q, err := query(d, "bumpAuditEventShipAttempt")
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, q, id, errMsg, nextAt)
	return err
}
