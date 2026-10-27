package billing

import (
	"context"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/models"
)

// Worker drains the billing_events outbox and delivers each event via
// the Webhook. Multiple control-plane replicas can each run a Worker
// concurrently — the SQL claim uses FOR UPDATE SKIP LOCKED so each row
// goes to exactly one worker. No leader election needed.
type Worker struct {
	Repo     *models.Repo
	Webhook  *Webhook
	Interval time.Duration // default 5s
	Batch    int           // default 32 events per tick
}

// Run blocks until ctx is done. Tick spacing is governed by Interval;
// each tick claims up to Batch pending rows, delivers them, marks
// each delivered or schedules a retry.
func (w *Worker) Run(ctx context.Context) {
	if w == nil || w.Repo == nil || w.Repo.DB == nil {
		log.WithContext(ctx).Error("[billing-worker] invalid configuration: repository is required")
		return
	}
	if w.Webhook == nil || w.Webhook.Client == nil || w.Webhook.URL == "" {
		log.WithContext(ctx).Error("[billing-worker] invalid configuration: webhook URL and client are required")
		return
	}
	if w.Interval <= 0 {
		w.Interval = 5 * time.Second
	}
	if w.Batch <= 0 {
		w.Batch = 32
	}
	log.WithContext(ctx).Infof("[billing-worker] starting (interval=%s batch=%d url=%s)",
		w.Interval, w.Batch, w.Webhook.URL)

	t := time.NewTicker(w.Interval)
	defer t.Stop()
	w.tick(ctx) // sync first pass so a hot backlog drains before the first tick
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
	tx, events, err := models.ClaimPendingBillingEvents(ctx, w.Repo.DB, w.Batch)
	if err != nil {
		log.WithContext(ctx).Warnf("[billing-worker] claim: %v", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if len(events) == 0 {
		_ = tx.Commit(ctx) // release the empty tx promptly
		return
	}

	for _, ev := range events {
		// Per-event context with a 15s budget — the webhook itself has
		// a 10s timeout; this leaves 5s for outbox bookkeeping.
		evCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := w.Webhook.Deliver(evCtx, ev.ID, ev.EventType, ev.Payload)
		cancel()

		switch {
		case err == nil:
			if err := models.MarkBillingEventDelivered(ctx, tx, w.Repo.DB, ev.ID); err != nil {
				log.WithContext(ctx).Warnf("[billing-worker] mark delivered %s: %v", ev.ID, err)
			}
		case isPermanent(err):
			msg := err.Error()
			if len(msg) > 1024 {
				msg = msg[:1024]
			}
			if err := models.MarkBillingEventPermanentFailure(ctx, tx, w.Repo.DB, ev.ID, msg); err != nil {
				log.WithContext(ctx).Warnf("[billing-worker] mark permanent %s: %v", ev.ID, err)
			}
			log.WithContext(ctx).Warnf("[billing-worker] permanent failure for %s: %v", ev.ID, err)
		default:
			next := nextAttemptAt(ev.Attempts)
			msg := err.Error()
			if len(msg) > 1024 {
				msg = msg[:1024]
			}
			if err := models.BumpBillingEventAttempt(ctx, tx, w.Repo.DB, ev.ID, msg, next); err != nil {
				log.WithContext(ctx).Warnf("[billing-worker] bump attempt %s: %v", ev.ID, err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		log.WithContext(ctx).Warnf("[billing-worker] commit: %v", err)
	}
}

func isPermanent(err error) bool {
	var pe *PermanentError
	return errors.As(err, &pe)
}

// nextAttemptAt returns when the worker should retry a failed delivery
// next. Capped at 1h. Sequence: 1s, 4s, 16s, 1m, 5m, 30m, 1h, 1h, …
func nextAttemptAt(prevAttempts int) time.Time {
	now := time.Now().UTC()
	delays := []time.Duration{
		1 * time.Second,
		4 * time.Second,
		16 * time.Second,
		1 * time.Minute,
		5 * time.Minute,
		30 * time.Minute,
	}
	if prevAttempts < len(delays) {
		return now.Add(delays[prevAttempts])
	}
	return now.Add(1 * time.Hour)
}
