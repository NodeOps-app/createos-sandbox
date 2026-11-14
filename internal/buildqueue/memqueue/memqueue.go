// Package memqueue is an in-memory buildqueue implementation for tests.
// Single mutex, FIFO order, no persistence. Not safe for production.
package memqueue

import (
	"context"
	"sync"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/buildqueue"
)

type entry struct {
	job       buildqueue.Job
	claimedAt time.Time // zero = pending
	attempts  int       // incremented on every Claim of this entry
	done      bool
	failed    bool // marked terminal-failed by Reap
}

// Queue is the in-memory implementation.
type Queue struct {
	mu  sync.Mutex
	all []*entry // FIFO; never reordered
}

// New returns an empty in-memory queue.
func New() *Queue { return &Queue{} }

func (q *Queue) Enqueue(_ context.Context, j buildqueue.Job) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, e := range q.all {
		if e.job.TplID == j.TplID {
			return buildqueue.ErrAlreadyExists
		}
	}
	if j.EnqueuedAt.IsZero() {
		j.EnqueuedAt = time.Now()
	}
	q.all = append(q.all, &entry{job: j})
	return nil
}

func (q *Queue) Claim(_ context.Context, blockedUsers []string) (*buildqueue.Job, error) {
	blocked := map[string]struct{}{}
	for _, u := range blockedUsers {
		blocked[u] = struct{}{}
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, e := range q.all {
		if e.done || e.failed || !e.claimedAt.IsZero() {
			continue
		}
		if _, blockedUser := blocked[e.job.UserID]; blockedUser {
			continue
		}
		e.claimedAt = time.Now()
		e.attempts++
		j := e.job
		return &j, nil
	}
	return nil, buildqueue.ErrEmpty
}

func (q *Queue) Complete(_ context.Context, tplID string, _ buildqueue.Outcome) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, e := range q.all {
		if e.job.TplID == tplID {
			if e.claimedAt.IsZero() {
				return buildqueue.ErrNotClaimed
			}
			e.done = true
			return nil
		}
	}
	return buildqueue.ErrNotClaimed
}

// Reap fails every claim older than maxAge — no retries.
func (q *Queue) Reap(_ context.Context, maxAge time.Duration) ([]string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now()
	var failed []string
	for _, e := range q.all {
		if e.done || e.failed || e.claimedAt.IsZero() {
			continue
		}
		if now.Sub(e.claimedAt) <= maxAge {
			continue
		}
		e.failed = true
		e.claimedAt = time.Time{}
		failed = append(failed, e.job.TplID)
	}
	return failed, nil
}

func (q *Queue) Terminal(_ context.Context, tplID string) (bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, e := range q.all {
		if e.job.TplID == tplID {
			return e.done || e.failed, nil
		}
	}
	return true, nil
}
