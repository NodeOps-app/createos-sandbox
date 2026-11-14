// Package billingemit records lifecycle billing events in the transaction
// supplied by model status updates. Atomicity and duplicate prevention depend
// on the caller's guarded state transition; delivery is handled separately.
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

	"github.com/NodeOps-app/createos-sandbox/database"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/internal/utils"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// ShapesProvider is the narrow interface needed to bill burstable
// shapes at their CPUQuotaPct rather than vcpu * 1000. Implemented by
// *cache.Shapes (DB-backed, TTL-cached). nil-safe — when nil
// the emitter falls back to vcpu * 1000.
type ShapesProvider interface {
	Shapes(ctx context.Context) []proto.Shape
}

// Emitter records billing events in the caller's transaction. Internal request
// contexts and pool rows are skipped. For other contexts, a database check can
// mark the inserted event internal_skip so delivery is suppressed. Construct
// once and share without mutating DB or Shapes.
type Emitter struct {
	DB     *database.Db
	Shapes ShapesProvider
}

// New constructs an Emitter. A nil Shapes provider uses vCPU-based billing.
// To disable emission, pass a nil *Emitter to model callers instead.
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

// EmitInTx inserts an event in the caller's status-mutation transaction.
// Callers must roll back on error. Nil receivers, internal request contexts,
// missing sandbox rows, and unclaimed pool rows are no-ops. Database-identified
// internal users retain an event stamped internal_skip.
func (e *Emitter) EmitInTx(ctx context.Context, tx pgx.Tx, sandboxID, eventType, prevStatus string) error {
	if e == nil {
		return nil
	}
	// Internal request contexts bypass both the row lookup and event insert.
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
// wired); the fallback is zero if the supplied vcpu is zero.
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
// time-sortable by the supplied millisecond timestamp. Random suffixes do not
// preserve generation order within the same millisecond.
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
