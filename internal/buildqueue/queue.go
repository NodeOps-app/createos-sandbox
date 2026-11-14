// Package buildqueue brokers template build jobs from the user-facing
// API to the builder service.
//
// The production backend uses Postgres; memqueue provides a process-local
// implementation for tests.
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
	StatusReady  Status = iota + 1 // build succeeded; ext4 in object storage
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

// Queue is the broker interface. Implementations serialize claims against
// their backing state: Postgres coordinates builder processes, while memqueue
// coordinates only callers sharing the same in-memory queue.
type Queue interface {
	// Enqueue submits a new job. Duplicate-ID error handling is backend-specific.
	Enqueue(ctx context.Context, j Job) error

	// Claim atomically reserves one job whose UserID is NOT in
	// blockedUsers. The blockedUsers filter is how callers enforce
	// per-user concurrency caps without the queue knowing about caps.
	// Returns ErrEmpty if no eligible job is ready.
	Claim(ctx context.Context, blockedUsers []string) (*Job, error)

	// Complete marks a claimed job as terminally done (success or
	// failure). The Postgres backend treats a missed building-state CAS as
	// success; memqueue can return ErrNotClaimed for missing/unclaimed jobs.
	Complete(ctx context.Context, tplID string, o Outcome) error

	// Reap marks claims older than maxAge terminal-failed without re-enqueueing
	// them and returns their IDs. Age alone does not establish whether the
	// worker crashed, stalled, or simply exceeded its allowed duration.
	Reap(ctx context.Context, maxAge time.Duration) (failed []string, err error)

	// Terminal reports whether a template no longer has a live build. Missing
	// or deleted templates are terminal too: no build sandbox should survive
	// after its owning template disappears.
	Terminal(ctx context.Context, tplID string) (bool, error)
}
