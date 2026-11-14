package framework

import (
	"context"
	"time"

	"github.com/NodeOps-app/createos-sandbox/models"
)

// Filter rejects hosts that cannot serve the request. All registered Filters
// in the pipeline must return ok=true for a host to survive.
type Filter interface {
	Name() string
	Filter(req *Request, h *models.Host) (ok bool, reason string)
}

// Scorer assigns a 0..100 score per surviving host. The pipeline computes
// `sum(score_i * weight_i)` and picks the maximum (random tie-break).
type Scorer interface {
	Name() string
	Score(req *Request, h *models.Host) int
	Weight() int
}

// Reserver atomically claims capacity on the chosen host. The implementation
// owns the correctness story (in-mem mutex, DB LWT, external service, …).
// On a lost race it must return ErrConflict; the pipeline will re-pick.
//
// The reservation is keyed by sandbox id (a durable identifier from the
// sandboxes table). Release supports explicit removal; the service normally
// reconciles the delta against durable records during hydration.
type Reserver interface {
	Name() string
	Reserve(ctx context.Context, sbID string, req *Request, h *models.Host) error
	Release(ctx context.Context, sbID string) error
	// Reconcile publishes host admission counters and reconciles pending deltas
	// atomically, so an older filtering snapshot cannot undercount usage. It walks the
	// in-mem delta and drops entries that the durable record has caught
	// up with (live), gone terminal on (terminated), or whose grace
	// window expired (orphaned by a control-plane crash). Reservers that
	// have no in-mem state can no-op.
	Reconcile(hosts map[string]models.Host, live, terminated map[string]bool, graceCutoff time.Time)
	// PendingIDs returns the set of sandbox ids currently held in delta.
	// Hydrate uses this to bound the StatusOfIDs lookup it sends to the
	// repo for terminal-state detection.
	PendingIDs() []string
}
