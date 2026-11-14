// Package pgqueue is the Postgres-backed buildqueue implementation.
// Wraps the templates table; status field IS the queue state machine.
package pgqueue

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/NodeOps-app/createos-sandbox/internal/buildqueue"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// New returns a buildqueue.Queue backed by the templates table.
// Enqueue/Complete go through *models.Repo so it remains the single
// source of SQL truth.
func New(repo *models.Repo) buildqueue.Queue {
	return &pgQueue{repo: repo}
}

type pgQueue struct {
	repo *models.Repo
}

// Enqueue inserts a 'pending' row. The caller is expected to have
// minted the tpl_id, validated the Dockerfile, and enforced per-user
// concurrency before reaching this point.
func (q *pgQueue) Enqueue(ctx context.Context, j buildqueue.Job) error {
	rec := models.Template{
		ID:         j.TplID,
		UserID:     j.UserID,
		Name:       j.Name,
		Base:       j.Base,
		Dockerfile: j.Dockerfile,
		Status:     models.TemplateStatusPending,
	}
	return q.repo.InsertTemplate(ctx, rec)
}

// Claim runs the atomic UPDATE...FOR UPDATE SKIP LOCKED. Returns
// buildqueue.ErrEmpty when no eligible job is ready (callers must not
// branch on pgx.ErrNoRows directly).
func (q *pgQueue) Claim(ctx context.Context, blockedUsers []string) (*buildqueue.Job, error) {
	t, err := q.repo.ClaimNextBuild(ctx, blockedUsers)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, buildqueue.ErrEmpty
		}
		return nil, err
	}
	return &buildqueue.Job{
		TplID:      t.ID,
		UserID:     t.UserID,
		Name:       t.Name,
		Base:       t.Base,
		Dockerfile: t.Dockerfile,
		EnqueuedAt: t.CreatedAt,
	}, nil
}

// Complete is the dispatcher's idempotent confirmation. The build sandbox
// usually races to PATCH the row first via its narrowly-scoped JWT;
// our CAS on status='building' makes the loser harmless.
func (q *pgQueue) Complete(ctx context.Context, tplID string, o buildqueue.Outcome) error {
	newStatus := models.TemplateStatusReady
	if o.Status == buildqueue.StatusFailed {
		newStatus = models.TemplateStatusFailed
	}
	id, err := q.repo.CompleteTemplateBuild(ctx, tplID, newStatus,
		o.SHA256, o.SizeBytes, o.Ext4SizeBytes)
	if err != nil {
		return err
	}
	if id == "" {
		// CAS missed: the row no longer matched the building-state update.
		// Treat this as an idempotent no-op; it does not prove a successful build.
		return nil
	}
	return nil
}

// Reap marks every `building` row older than maxAge as failed. No
// retries are enqueued by this method.
func (q *pgQueue) Reap(ctx context.Context, maxAge time.Duration) (failed []string, err error) {
	cutoff := time.Now().UTC().Add(-maxAge)
	return q.repo.ReapStuckBuilds(ctx, cutoff)
}

func (q *pgQueue) Terminal(ctx context.Context, tplID string) (bool, error) {
	rec, err := q.repo.GetTemplate(ctx, tplID)
	if err != nil {
		return false, err
	}
	if rec == nil {
		return true, nil
	}
	return rec.DeletedAt != nil || rec.Status == models.TemplateStatusReady || rec.Status == models.TemplateStatusFailed, nil
}
