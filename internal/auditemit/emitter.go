// Package auditemit implements audit.Emitter against Postgres. Each
// Emit inserts a row into audit_events; internal/auditshipper drains
// the table and POSTs to the backend audit-log endpoint.
package auditemit

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/database"
	"github.com/NodeOps-app/sandbox/internal/audit"
	"github.com/NodeOps-app/sandbox/models"
)

// Emitter satisfies audit.Emitter. Safe for concurrent use.
type Emitter struct {
	DB        *database.Db
	Retention time.Duration // 0 = no expiry stamp
}

func New(db *database.Db, retention time.Duration) *Emitter {
	return &Emitter{DB: db, Retention: retention}
}

// Emit is fire-and-forget. Opens its own tx, inserts the row,
// commits. Errors logged, never propagated.
func (e *Emitter) Emit(ctx context.Context, ac audit.Context, action audit.Action, op audit.OperationType, md audit.Metadata) {
	if e == nil {
		return
	}
	// Internal users bypass audit persistence — no row is written.
	// Async re-emission for internal history is a follow-up; for now
	// the row simply doesn't exist. Cuts ~30 ms per hot-path claim.
	if ac.IsInternal {
		return
	}
	ev, err := e.build(ac, action, op, md)
	if err != nil {
		log.WithContext(ctx).Warnf("[auditemit] %s %s build: %v", ac.UserID, action, err)
		return
	}
	tx, err := e.DB.Con.Begin(ctx)
	if err != nil {
		log.WithContext(ctx).Warnf("[auditemit] %s %s begin: %v", ac.UserID, action, err)
		return
	}
	if err := models.InsertAuditEvent(ctx, tx, e.DB, ev); err != nil {
		_ = tx.Rollback(ctx)
		log.WithContext(ctx).Warnf("[auditemit] %s %s insert: %v", ac.UserID, action, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		log.WithContext(ctx).Warnf("[auditemit] %s %s commit: %v", ac.UserID, action, err)
	}
}

// EmitInTx writes the audit row inside the caller's tx, so the audit
// row commits/rolls-back together with the caller's business mutation.
func (e *Emitter) EmitInTx(ctx context.Context, tx pgx.Tx, ac audit.Context, action audit.Action, op audit.OperationType, md audit.Metadata) error {
	if e == nil {
		return nil
	}
	// See Emit — internal users bypass audit persistence.
	if ac.IsInternal {
		return nil
	}
	ev, err := e.build(ac, action, op, md)
	if err != nil {
		return err
	}
	return models.InsertAuditEvent(ctx, tx, e.DB, ev)
}

func (e *Emitter) build(ac audit.Context, action audit.Action, op audit.OperationType, md audit.Metadata) (models.AuditEvent, error) {
	now := time.Now().UTC()
	body, err := json.Marshal(md)
	if err != nil {
		return models.AuditEvent{}, fmt.Errorf("marshal metadata: %w", err)
	}
	var expires *time.Time
	if e.Retention > 0 {
		t := now.Add(e.Retention)
		expires = &t
	}
	return models.AuditEvent{
		ID:            newAuditEventID(now),
		UserID:        ac.UserID,
		Action:        string(action),
		OperationType: string(op),
		Actor:         strPtr(ac.Actor),
		HashedToken:   strPtr(ac.HashedToken),
		RequestID:     strPtr(ac.RequestID),
		UserAgent:     strPtr(ac.UserAgent),
		IPAddress:     strPtr(ac.IPAddress),
		ExpiresAt:     expires,
		Metadata:      body,
		SubjectType:   strPtr(ac.SubjectType),
		SubjectID:     strPtr(ac.SubjectID),
		OccurredAt:    now,
		IsInternal:    ac.IsInternal,
	}, nil
}

func newAuditEventID(t time.Time) string {
	id := ulid.MustNew(ulid.Timestamp(t), rand.Reader)
	return models.AuditEventIDPrefix + strings.ToLower(id.String())
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
