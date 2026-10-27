package handlers

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/utils"
)

// shapeMillicores returns the billable CPU allocation for a shape, in
// millicores. Burstable shapes (CPUQuotaPct > 0) bill the fractional
// quota; dedicated shapes bill VCPU * 1000. Falls back to VCPU * 1000
// for unknown shape strings (or when the shapes provider hasn't been
// wired) so we never emit zero. Used by the reconcile-view endpoint;
// the atomic emit path uses the equivalent helper in billingemit.
func (h *Handler) shapeMillicores(ctx context.Context, shape string, vcpu int) int {
	if h.shapes != nil {
		for _, s := range h.shapes.Shapes(ctx) {
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

// derefStringPtr returns the pointee or "" for nil — local helper used
// by the billing reconcile-view handler.
func derefStringPtr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// emitBillingEvent records a lifecycle billing event in its OWN
// transaction. This wrapper is now used by only one path that has no
// Mark* equivalent: DbInsertSandbox's initial creating → running
// upsert. Every other status mutation flows through a Mark* function
// in models/sandbox.go, which begins its own tx and calls
// billingEmitter.EmitInTx so the status flip + event INSERT commit
// atomically.
//
// nil emitter / billing-disabled = no-op. Best-effort: emit failures
// are logged and swallowed (this path is non-atomic by definition —
// the row INSERT has already committed before we reach here).
func (h *Handler) emitBillingEvent(ctx context.Context, sandboxID, eventType, prevStatus string) {
	if h.billingEmitter == nil {
		return
	}
	// Fast-path skip for internal users — mirrors billingemit.EmitInTx.
	// Doing the check here avoids the tx Begin/Commit round-trips that
	// otherwise cost ~20-60 ms per event under burst even though the
	// inner EmitInTx would just return nil.
	if utils.IsInternalFromContext(ctx) {
		return
	}
	tx, err := h.repo.DB.Con.Begin(ctx)
	if err != nil {
		log.WithContext(ctx).Errorf("[billing] emit %s for %s: begin tx: %v", eventType, sandboxID, err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.billingEmitter.EmitInTx(ctx, tx, sandboxID, eventType, prevStatus); err != nil {
		log.WithContext(ctx).Errorf("[billing] emit %s for %s: %v", eventType, sandboxID, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		log.WithContext(ctx).Errorf("[billing] emit %s for %s: commit: %v", eventType, sandboxID, err)
	}
}
