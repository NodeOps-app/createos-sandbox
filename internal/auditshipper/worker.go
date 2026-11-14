// Package auditshipper delivers pending audit_events with retry backoff.
// FOR UPDATE SKIP LOCKED coordinates workers sharing one database, not
// separate regional databases. A successful POST followed by a failed commit
// can be delivered again; the receiver must deduplicate by event ID.
package auditshipper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/database"
	"github.com/NodeOps-app/createos-sandbox/internal/hmacsign"
	"github.com/NodeOps-app/createos-sandbox/models"
)

type Worker struct {
	DB         *database.Db
	BackendURL string
	Secret     []byte
	Interval   time.Duration // default 5s
	Batch      int           // default 32
	HTTP       *http.Client
}

func (w *Worker) Run(ctx context.Context) {
	if w.Interval <= 0 {
		w.Interval = 5 * time.Second
	}
	if w.Batch <= 0 {
		w.Batch = 32
	}
	if w.HTTP == nil {
		w.HTTP = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:    16,
				IdleConnTimeout: 30 * time.Second,
			},
		}
	}
	log.WithContext(ctx).Infof("[audit-shipper] starting (interval=%s batch=%d url=%s)", w.Interval, w.Batch, w.BackendURL)

	t := time.NewTicker(w.Interval)
	defer t.Stop()
	w.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

func (w *Worker) tick(ctx context.Context) {
	tx, events, err := models.ClaimPendingAuditEvents(ctx, w.DB, w.Batch)
	if err != nil {
		log.WithContext(ctx).Warnf("[audit-shipper] claim: %v", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if len(events) == 0 {
		_ = tx.Commit(ctx)
		return
	}

	for _, ev := range events {
		evCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := w.ship(evCtx, ev)
		cancel()

		switch {
		case err == nil:
			if err := models.MarkAuditEventShipped(ctx, tx, w.DB, ev.ID); err != nil {
				log.WithContext(ctx).Warnf("[audit-shipper] mark shipped %s: %v", ev.ID, err)
			}
		case isPermanent(err):
			if err := models.MarkAuditEventPermanentFailure(ctx, tx, w.DB, ev.ID, trunc(err.Error())); err != nil {
				log.WithContext(ctx).Warnf("[audit-shipper] mark permanent %s: %v", ev.ID, err)
			}
			log.WithContext(ctx).Warnf("[audit-shipper] permanent failure for %s: %v", ev.ID, err)
		default:
			next := nextAttemptAt(ev.Attempts)
			if err := models.BumpAuditEventShipAttempt(ctx, tx, w.DB, ev.ID, trunc(err.Error()), next); err != nil {
				log.WithContext(ctx).Warnf("[audit-shipper] bump %s: %v", ev.ID, err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		log.WithContext(ctx).Warnf("[audit-shipper] commit: %v", err)
	}
}

func (w *Worker) ship(ctx context.Context, ev models.AuditEvent) error {
	// Require signing even when the worker is constructed outside the CLI.
	if len(w.Secret) == 0 {
		return &RetryableError{Inner: fmt.Errorf("audit webhook signing secret is required")}
	}
	body, err := json.Marshal(toBackendShape(ev))
	if err != nil {
		return &PermanentError{Inner: err}
	}
	now := time.Now().UTC()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.BackendURL, bytes.NewReader(body))
	if err != nil {
		return &RetryableError{Inner: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CreateOS-Event-Id", ev.ID)
	req.Header.Set("X-CreateOS-Timestamp", strconv.FormatInt(now.Unix(), 10))
	req.Header.Set("X-CreateOS-Signature", hmacsign.Sign(w.Secret, body, now))
	resp, err := w.HTTP.Do(req)
	if err != nil {
		return &RetryableError{Inner: err}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusRequestTimeout,
		resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode >= 500:
		return &RetryableError{Inner: fmt.Errorf("%d: %s", resp.StatusCode, trunc(string(respBody)))}
	default:
		return &PermanentError{Inner: fmt.Errorf("%d: %s", resp.StatusCode, trunc(string(respBody)))}
	}
}

// Matches the backend's AuditLog struct field-for-field.
type backendShape struct {
	ID            string          `json:"id"`
	UserID        string          `json:"userId"`
	Action        string          `json:"action"`
	Actor         *string         `json:"actor"`
	HashedToken   *string         `json:"hashedToken"`
	OperationType string          `json:"operationType"`
	SubjectType   *string         `json:"subjectType"`
	SubjectID     *string         `json:"subjectId"`
	RequestID     *string         `json:"requestId"`
	UserAgent     *string         `json:"userAgent"`
	IPAddress     *string         `json:"ipAddress"`
	ExpiresAt     *time.Time      `json:"expiresAt"`
	Metadata      json.RawMessage `json:"metadata"`
	CreatedAt     time.Time       `json:"createdAt"`
}

func toBackendShape(ev models.AuditEvent) backendShape {
	return backendShape{
		ID:            ev.ID,
		UserID:        ev.UserID,
		Action:        ev.Action,
		Actor:         ev.Actor,
		HashedToken:   ev.HashedToken,
		OperationType: ev.OperationType,
		SubjectType:   ev.SubjectType,
		SubjectID:     ev.SubjectID,
		RequestID:     ev.RequestID,
		UserAgent:     ev.UserAgent,
		IPAddress:     ev.IPAddress,
		ExpiresAt:     ev.ExpiresAt,
		Metadata:      ev.Metadata,
		CreatedAt:     ev.OccurredAt,
	}
}

type RetryableError struct{ Inner error }

func (e *RetryableError) Error() string { return e.Inner.Error() }
func (e *RetryableError) Unwrap() error { return e.Inner }

type PermanentError struct{ Inner error }

func (e *PermanentError) Error() string { return e.Inner.Error() }
func (e *PermanentError) Unwrap() error { return e.Inner }

func isPermanent(err error) bool {
	var pe *PermanentError
	return errors.As(err, &pe)
}

// Mirrors billing/worker.go: 1s, 4s, 16s, 1m, 5m, 30m, 1h+.
func nextAttemptAt(prevAttempts int) time.Time {
	now := time.Now().UTC()
	delays := []time.Duration{
		1 * time.Second, 4 * time.Second, 16 * time.Second,
		1 * time.Minute, 5 * time.Minute, 30 * time.Minute,
	}
	if prevAttempts < len(delays) {
		return now.Add(delays[prevAttempts])
	}
	return now.Add(1 * time.Hour)
}

func trunc(s string) string {
	if len(s) > 1024 {
		return s[:1024]
	}
	return s
}
