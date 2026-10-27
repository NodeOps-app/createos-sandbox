package models

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/NodeOps-app/sandbox/database"

	"github.com/jackc/pgx/v5"
)

// BillingEventIDPrefix is the canonical prefix for billing event IDs.
const BillingEventIDPrefix = "evt_"

// Billing event type strings. Wire format mirrors these verbatim in the
// webhook payload's `event_type` field.
const (
	BillingEventSandboxRunning   = "sandbox.running"
	BillingEventSandboxPaused    = "sandbox.paused"
	BillingEventSandboxDestroyed = "sandbox.destroyed"
	BillingEventSandboxFailed    = "sandbox.failed"
)

// Billing event delivery-state values. Matches the CHECK constraint on
// billing_events.status. Only `pending` is non-terminal; everything
// else means the worker will never touch the row again.
const (
	BillingStatusPending          = "pending"           // outbox row waiting for worker
	BillingStatusDelivered        = "delivered"         // worker got 2xx
	BillingStatusSuperseded       = "superseded"        // collapsed by a later event for the same sandbox
	BillingStatusInternalSkip     = "internal_skip"     // creator has is_internal=true → audit only
	BillingStatusPermanentFailure = "permanent_failure" // 4xx (excl. 408/429); operator action needed
)

// BillingEvent mirrors one row of the billing_events outbox. Field
// order + types follow the migration's columns; payload is the exact
// body the worker POSTs to the webhook.
type BillingEvent struct {
	ID            string          `json:"id"`
	SandboxID     string          `json:"sandbox_id"`
	EventType     string          `json:"event_type"`
	Payload       json.RawMessage `json:"payload"`
	OccurredAt    time.Time       `json:"occurred_at"`
	Status        string          `json:"status"`
	DeliveredAt   *time.Time      `json:"delivered_at"`
	Attempts      int             `json:"attempts"`
	LastError     *string         `json:"last_error"`
	NextAttemptAt time.Time       `json:"next_attempt_at"`
}

// SandboxForBilling is the deliberately narrow sandbox projection required to
// build a lifecycle billing event. It excludes runtime configuration and
// secrets so emitters never need to decode envs or access their encryption key.
type SandboxForBilling struct {
	ID                  string
	CreatedBy           string
	Status              Status
	Name                *string
	Shape               string
	VCPU                int
	MemMib              int
	DiskMib             int64
	BandwidthQuotaBytes int64
	BandwidthUsedBytes  int64
	Region              string
	CreatedAt           time.Time
	RunningAt           *time.Time
	PausedAt            *time.Time
	DestroyedAt         *time.Time
	ForkedFrom          *string
}

// GetSandboxForBillingInTx reads only lifecycle/accounting fields inside the
// caller's transaction, so it observes an uncommitted Mark* status mutation
// without loading sensitive runtime columns such as envs or secret_token.
func GetSandboxForBillingInTx(ctx context.Context, tx pgx.Tx, d *database.Db, id string) (*SandboxForBilling, error) {
	q, err := query(d, "getSandboxForBilling")
	if err != nil {
		return nil, err
	}
	var rec SandboxForBilling
	var status string
	err = tx.QueryRow(ctx, q, id).Scan(
		&rec.ID, &rec.CreatedBy, &status, &rec.Name, &rec.Shape,
		&rec.VCPU, &rec.MemMib, &rec.DiskMib,
		&rec.BandwidthQuotaBytes, &rec.BandwidthUsedBytes, &rec.Region,
		&rec.CreatedAt, &rec.RunningAt, &rec.PausedAt, &rec.DestroyedAt,
		&rec.ForkedFrom,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rec.Status = Status(status)
	return &rec, nil
}

// InsertBillingEvent appends a row to the outbox inside the caller-
// provided transaction. Same statement also marks any prior pending
// events for the same sandbox as superseded.
//
// Caller owns the surrounding tx — so the sandbox status UPDATE and
// this insert land atomically (when wrapped together). d is used only
// to resolve the named query string; the write goes through tx.
func InsertBillingEvent(ctx context.Context, tx pgx.Tx, d *database.Db,
	id, sandboxID, eventType string, payload []byte, occurredAt time.Time) error {
	q, err := query(d, "insertBillingEvent")
	if err != nil {
		return err
	}
	var got string
	return tx.QueryRow(ctx, q, id, sandboxID, eventType, string(payload), occurredAt).Scan(&got)
}

// ClaimPendingBillingEvents reads up to `limit` events that are ready
// for delivery (delivered_at IS NULL AND next_attempt_at <= now()),
// holding row locks via FOR UPDATE SKIP LOCKED so concurrent workers
// each get a disjoint slice.
//
// Caller owns the returned tx — must Commit or Rollback. Locks release
// at tx end. Typical worker pattern: claim → deliver each → mark
// delivered or bump attempts → commit.
func ClaimPendingBillingEvents(ctx context.Context, d *database.Db, limit int) (pgx.Tx, []BillingEvent, error) {
	q, err := query(d, "claimPendingBillingEvents")
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
	var out []BillingEvent
	for rows.Next() {
		var ev BillingEvent
		if err := rows.Scan(&ev.ID, &ev.SandboxID, &ev.EventType, &ev.Payload, &ev.OccurredAt, &ev.Attempts); err != nil {
			_ = tx.Rollback(ctx)
			return nil, nil, err
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		_ = tx.Rollback(ctx)
		return nil, nil, err
	}
	return tx, out, nil
}

// MarkBillingEventDelivered transitions status pending → delivered.
// Idempotent on terminal-state rows (the WHERE id=$1 still matches).
func MarkBillingEventDelivered(ctx context.Context, tx pgx.Tx, d *database.Db, id string) error {
	q, err := query(d, "markBillingEventDelivered")
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, q, id)
	return err
}

// MarkBillingEventPermanentFailure transitions status pending →
// permanent_failure. Used for 4xx responses (excl. 408/429) — schema
// mismatch / receiver bug; never going to succeed. Operators alarm on
// status='permanent_failure'.
func MarkBillingEventPermanentFailure(ctx context.Context, tx pgx.Tx, d *database.Db, id, msg string) error {
	q, err := query(d, "markBillingEventPermanentFailure")
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, q, id, msg)
	return err
}

// BumpBillingEventAttempt increments attempts and schedules the next
// retry. status stays 'pending'. Caller computes nextAt via exponential
// backoff.
func BumpBillingEventAttempt(ctx context.Context, tx pgx.Tx, d *database.Db, id, errMsg string, nextAt time.Time) error {
	q, err := query(d, "bumpBillingEventAttempt")
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, q, id, errMsg, nextAt)
	return err
}

// ErrBillingEventInsert is the sentinel a caller can use to discriminate
// outbox-insert failures from sandbox-status update failures inside the
// wrapping transaction. Today we just bubble the underlying error
// upwards — kept here for future log-grouping.
var ErrBillingEventInsert = errors.New("billing outbox insert failed")

// IsInternalUser reports whether the user has at least one active
// (non-revoked) is_internal=true API key. Internal users get billing
// events RECORDED in the outbox (for audit) but the worker is told to
// skip delivery via MarkBillingEventInternalSkip.
func IsInternalUser(ctx context.Context, d *database.Db, userID string) (bool, error) {
	q, err := query(d, "isInternalUser")
	if err != nil {
		return false, err
	}
	var internal bool
	return internal, d.Con.QueryRow(ctx, q, userID).Scan(&internal)
}

// MarkBillingEventInternalSkip transitions a freshly-inserted event to
// status='internal_skip' so the worker never picks it up. Row stays
// for audit. Caller runs this in the SAME tx as InsertBillingEvent.
func MarkBillingEventInternalSkip(ctx context.Context, tx pgx.Tx, d *database.Db, id string) error {
	q, err := query(d, "markBillingEventInternalSkip")
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, q, id)
	return err
}

// MarkBillingEventInternalSkipInTx is the tx-scoped variant of
// MarkBillingEventInternalSkip. Used by BillingEmitter.EmitInTx so the
// status flip lands in the SAME transaction as the original Mark*
// UPDATE + the billing_events INSERT — all three commit or roll back
// together.
func MarkBillingEventInternalSkipInTx(ctx context.Context, tx pgx.Tx, d *database.Db, id string) error {
	return MarkBillingEventInternalSkip(ctx, tx, d, id)
}

// IsInternalUserInTx is the tx-scoped variant of IsInternalUser. Reads
// inside the caller's transaction so the lookup sees a consistent
// snapshot with the just-updated sandbox row.
func IsInternalUserInTx(ctx context.Context, tx pgx.Tx, d *database.Db, userID string) (bool, error) {
	q, err := query(d, "isInternalUser")
	if err != nil {
		return false, err
	}
	var internal bool
	return internal, tx.QueryRow(ctx, q, userID).Scan(&internal)
}

// BillingEmitter records a billing_events row in the caller-provided
// tx. Implementations live outside the models package; the interface
// lets every Mark* function emit without importing higher-level
// packages.
//
// On error, the caller MUST roll back the tx — emit failure means the
// status mutation must NOT commit. This is the atomicity guarantee
// callers rely on.
//
// nil receiver is allowed and is a no-op (the Mark still commits).
type BillingEmitter interface {
	EmitInTx(ctx context.Context, tx pgx.Tx, sandboxID, eventType, prevStatus string) error
}

// emitInTx invokes the emitter if non-nil, otherwise no-op. Internal
// helper for the Mark* functions so each callsite doesn't need to
// repeat the nil-check.
func emitInTx(ctx context.Context, tx pgx.Tx, emitter BillingEmitter, sandboxID, eventType, prevStatus string) error {
	if emitter == nil {
		return nil
	}
	return emitter.EmitInTx(ctx, tx, sandboxID, eventType, prevStatus)
}
