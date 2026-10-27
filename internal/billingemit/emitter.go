// Package billingemit implements the BillingEmitter interface declared
// in models. Lifted out of the handlers package so every Mark* model
// function can record a billing_events row in the SAME transaction as
// the status mutation, without the models package taking a dependency
// on handlers / shapes / clickhouse / etc.
//
// The emitter owns the payload-shaping logic that used to live in
// Handler.emitBillingEvent. Sweep, the host db-proxy paths, and the
// user-facing control handlers all share the same Emitter so a status
// change emits a billing event exactly once per Mark*, regardless of
// which actor triggered it.
package billingemit

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
	"github.com/NodeOps-app/sandbox/internal/proto"
	"github.com/NodeOps-app/sandbox/internal/utils"
	"github.com/NodeOps-app/sandbox/models"
)

// ShapesProvider is the narrow interface needed to bill burstable
// shapes at their CPUQuotaPct rather than vcpu * 1000. Implemented by
// *cache.Shapes (DB-backed, TTL-cached). nil-safe — when nil
// the emitter falls back to vcpu * 1000.
type ShapesProvider interface {
	Shapes(ctx context.Context) []proto.Shape
}

// Emitter records billing_events rows atomically with the caller's
// status-mutation transaction. Always emits when non-nil; internal
// users get an internal_skip stamp inside the same tx so the worker
// skips delivery (audit row remains). Construct one at process start
// and share — methods are safe for concurrent use (no internal state).
type Emitter struct {
	DB     *database.Db
	Shapes ShapesProvider
}

// New constructs an Emitter. Pass nil at call sites (e.g. tests) to
// disable emission entirely — EmitInTx no-ops on a nil receiver.
func New(db *database.Db, shapes ShapesProvider) *Emitter {
	return &Emitter{DB: db, Shapes: shapes}
}

// billingPayload is the wire format the worker POSTs to the webhook.
// Hand-built subset of models.Sandbox fields — intentionally not a
// view shape shared with the user-facing API so adding fields here
// can't leak to users by accident.
type billingPayload struct {
	EventID        string         `json:"event_id"`
	EventType      string         `json:"event_type"`
	OccurredAt     time.Time      `json:"occurred_at"`
	PreviousStatus string         `json:"previous_status,omitempty"`
	CurrentStatus  string         `json:"current_status"`
	Sandbox        billingSandbox `json:"sandbox"`
}

type billingSandbox struct {
	ID                  string     `json:"id"`
	UserID              string     `json:"user_id"`
	Name                string     `json:"name"`
	Shape               string     `json:"shape"`
	CPUMillicores       int        `json:"cpu_millicores"`
	MemMib              int        `json:"mem_mib"`
	DiskMib             int64      `json:"disk_mib"`
	BandwidthQuotaBytes int64      `json:"bandwidth_quota_bytes"`
	BandwidthUsedBytes  int64      `json:"bandwidth_used_bytes"`
	Region              string     `json:"region"`
	CreatedAt           time.Time  `json:"created_at"`
	RunningAt           *time.Time `json:"running_at"`
	PausedAt            *time.Time `json:"paused_at"`
	DestroyedAt         *time.Time `json:"destroyed_at"`
	ForkedFrom          string     `json:"forked_from,omitempty"`
}

// EmitInTx satisfies models.BillingEmitter. Called by the Mark*
// functions inside their own status-mutation transaction so the
// billing_events insert + the status flip share atomicity. Always
// emits when the receiver is non-nil; internal users get an
// internal_skip stamp inside the same tx so the worker skips delivery.
//
// On error, the caller MUST roll back the tx — emit failure means the
// status mutation must not commit. This is the atomicity guarantee.
//
// nil receiver (tests), missing sandbox row → no-op (returns nil).
func (e *Emitter) EmitInTx(ctx context.Context, tx pgx.Tx, sandboxID, eventType, prevStatus string) error {
	if e == nil {
		return nil
	}
	// Internal users (is_internal=true API key) bypass the billing
	// pipeline entirely — no billing_events row, no is_internal DB
	// lookup, no internal-skip UPDATE. The downstream billing service
	// would drop these anyway; skipping in-tx removes ~50 ms per claim
	// under contention. Async re-emission for internal audit history
	// is a follow-up; for now the row simply doesn't exist.
	if utils.IsInternalFromContext(ctx) {
		return nil
	}
	// Read the row inside the tx so the lookup sees the just-completed
	// UPDATE under MVCC isolation — even though the tx hasn't committed
	// yet, reads inside the same tx observe its own writes.
	rec, err := models.GetSandboxForBillingInTx(ctx, tx, e.DB, sandboxID)
	if err != nil {
		return fmt.Errorf("billingemit: load sandbox %s: %w", sandboxID, err)
	}
	if rec == nil {
		// Row gone (concurrent test wipe / race) — skip silently.
		log.WithContext(ctx).Warnf("[billingemit] %s emit %s: sandbox not found (race?)", sandboxID, eventType)
		return nil
	}
	// Pool-owned sandboxes never emit — the tenant hasn't claimed yet, so
	// any billing event under the pool actor is meaningless (and the
	// receiver has no user_id to hang it under). The real emit fires on
	// the tenant's post-claim status transition.
	if models.IsPoolOwnerID(rec.CreatedBy) {
		return nil
	}
	now := time.Now().UTC()
	eventID, err := newBillingEventID(now)
	if err != nil {
		return fmt.Errorf("billingemit: create event id for %s/%s: %w", sandboxID, eventType, err)
	}
	payload := billingPayload{
		EventID:        eventID,
		EventType:      eventType,
		OccurredAt:     now,
		PreviousStatus: prevStatus,
		CurrentStatus:  string(rec.Status),
		Sandbox: billingSandbox{
			ID:                  rec.ID,
			UserID:              rec.CreatedBy,
			Name:                derefStringPtr(rec.Name),
			Shape:               rec.Shape,
			CPUMillicores:       e.shapeMillicores(ctx, rec.Shape, rec.VCPU),
			MemMib:              rec.MemMib,
			DiskMib:             rec.DiskMib,
			BandwidthQuotaBytes: rec.BandwidthQuotaBytes,
			BandwidthUsedBytes:  rec.BandwidthUsedBytes,
			Region:              rec.Region,
			CreatedAt:           rec.CreatedAt,
			RunningAt:           rec.RunningAt,
			PausedAt:            rec.PausedAt,
			DestroyedAt:         rec.DestroyedAt,
			ForkedFrom:          derefStringPtr(rec.ForkedFrom),
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("billingemit: marshal %s/%s: %w", sandboxID, eventType, err)
	}
	if err := models.InsertBillingEvent(ctx, tx, e.DB,
		payload.EventID, sandboxID, eventType, body, now); err != nil {
		return fmt.Errorf("billingemit: insert %s/%s: %w", sandboxID, eventType, err)
	}
	// Internal users: stamp internal_skip so the worker never picks
	// up the row. We still INSERT it for audit. Lookup failures are
	// non-fatal — fail-open lets the worker try to deliver, which is
	// preferable to a missed event for a billable user.
	internal, lookupErr := models.IsInternalUserInTx(ctx, tx, e.DB, rec.CreatedBy)
	if lookupErr != nil {
		log.WithContext(ctx).Warnf("[billingemit] %s emit %s: internal-user check failed: %v (will deliver)",
			sandboxID, eventType, lookupErr)
		return nil
	}
	if internal {
		if err := models.MarkBillingEventInternalSkipInTx(ctx, tx, e.DB, payload.EventID); err != nil {
			return fmt.Errorf("billingemit: mark internal-skip %s: %w", payload.EventID, err)
		}
	}
	return nil
}

// shapeMillicores returns the billable CPU allocation for a shape, in
// millicores. Burstable shapes (CPUQuotaPct > 0) bill the fractional
// quota; dedicated shapes bill VCPU * 1000. Falls back to VCPU * 1000
// for unknown shape strings (or when the shapes provider hasn't been
// wired) so we never emit zero.
func (e *Emitter) shapeMillicores(ctx context.Context, shape string, vcpu int) int {
	if e.Shapes != nil {
		for _, s := range e.Shapes.Shapes(ctx) {
			if s.ID == shape {
				if s.CPUQuotaPct > 0 {
					return s.CPUQuotaPct * 10
				}
				return s.VCPU * 1000
			}
		}
	}
	return vcpu * 1000
}

// newBillingEventID mints `evt_<26-char crockford base32 ulid>` —
// monotonic w.r.t. the supplied timestamp so receivers can sort.
func newBillingEventID(t time.Time) (string, error) {
	id, err := ulid.New(ulid.Timestamp(t), rand.Reader)
	if err != nil {
		return "", err
	}
	return models.BillingEventIDPrefix + strings.ToLower(id.String()), nil
}

func derefStringPtr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
