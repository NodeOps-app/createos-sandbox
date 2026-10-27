// Package buildqueue brokers template build jobs from the user-facing
// API to the builder service.
//
// Pluggable so the v1 Postgres backend can be swapped for Redis / NATS /
// etc. without touching the builder. See DESIGN/templates.md.
package buildqueue

import (
	"context"
	"errors"
	"time"
)

// Job is what the builder needs to actually run a build.
type Job struct {
	TplID      string
	UserID     string
	Name       string
	Base       string
	Dockerfile string
	EnqueuedAt time.Time
}

// Status is the terminal state passed to Complete.
type Status int

const (
	StatusReady  Status = iota + 1 // build succeeded; ext4 in R2
	StatusFailed                   // build failed; diagnostic logs live in ClickHouse
)

// Outcome is the terminal result of a build. Diagnostic logs (the
// thing operators reach for when Status==StatusFailed) live in
// ClickHouse — no error_text mirror here.
type Outcome struct {
	Status        Status
	SHA256        *string
	SizeBytes     int64
	Ext4SizeBytes int64
}

// Sentinel errors. Implementations must return ErrEmpty (and only
// ErrEmpty) when no eligible job is ready.
var (
	ErrEmpty         = errors.New("buildqueue: no ready jobs")
	ErrAlreadyExists = errors.New("buildqueue: job already enqueued")
	ErrNotClaimed    = errors.New("buildqueue: job not currently claimed")
)

// Queue is the broker interface. All methods are safe for concurrent
// use across multiple builder processes; Claim is exclusive (a job is
// delivered to at most one live consumer).
type Queue interface {
	// Enqueue submits a new job. Idempotent on j.TplID.
	Enqueue(ctx context.Context, j Job) error

	// Claim atomically reserves one job whose UserID is NOT in
	// blockedUsers. The blockedUsers filter is how callers enforce
	// per-user concurrency caps without the queue knowing about caps.
	// Returns ErrEmpty if no eligible job is ready.
	Claim(ctx context.Context, blockedUsers []string) (*Job, error)

	// Complete marks a claimed job as terminally done (success or
	// failure). Idempotent on (tplID, status='building'); if the row
	// has already moved on, returns ErrNotClaimed.
	Complete(ctx context.Context, tplID string, o Outcome) error

	// Reap is the janitor sweep. Any row stuck in `building` past
	// maxAge is marked terminal-failed — never retried. Failure means
	// either the dispatcher crashed mid-build or the build sandbox
	// itself failed to PATCH back; both look identical from the DB
	// and re-running on a stale Dockerfile rarely helps. Returns
	// the list of ids that were just failed.
	Reap(ctx context.Context, maxAge time.Duration) (failed []string, err error)

	// Terminal reports whether a template no longer has a live build. Missing
	// or deleted templates are terminal too: no build sandbox should survive
	// after its owning template disappears.
	Terminal(ctx context.Context, tplID string) (bool, error)
}
