package handlers

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/createos"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// maybeAutoTopup checks whether the sandbox's remaining egress quota
// has crossed under the configured threshold and, if so, asks createos
// for the user's current credit balance. If credit > 0, it debits
// `autoTopupGiB` worth of bandwidth and bumps the local quota.
//
// Best-effort + asynchronous: failures are logged, never bubbled. The
// caller (DbSetBandwidthUsed) returns to the host immediately; the
// recharge happens in a goroutine so the meter PATCH stays sub-ms.
//
// Cooldown: one top-up per user_id per autoTopupCooldown. Without it,
// the meter's 5s PATCH cadence would re-trigger before the quota bump
// has propagated and we'd debit the user multiple times.
func (h *Handler) maybeAutoTopup(sandboxID string, newUsedBytes int64) {
	if h.createos == nil || h.createos.BaseURL == "" || h.autoTopupThresholdBytes <= 0 || h.autoTopupGiB <= 0 {
		return
	}
	rec, err := h.repo.Get(context.Background(), sandboxID)
	if err != nil || rec == nil {
		return
	}
	// Only top up while the sandbox is actively running. Paused VMs
	// don't consume egress, and creating/pausing/resuming/destroying
	// are transient — debiting credits there would be wasteful or
	// race the lifecycle.
	if rec.Status != models.StatusRunning {
		return
	}
	if rec.BandwidthQuotaBytes <= 0 {
		return // unmetered (-1) or zero quota — nothing to top up
	}
	remaining := rec.BandwidthQuotaBytes - newUsedBytes
	if remaining >= h.autoTopupThresholdBytes {
		return
	}
	// Internal users (is_internal=true) bypass billing entirely — same
	// rule the webhook outbox uses to mark events `internal_skip`.
	// IsInternalUser hits the api_keys table; if it errors we fall open
	// so a transient DB blip doesn't strand a real user without credit.
	if internal, err := h.repo.IsInternalUser(context.Background(), rec.CreatedBy); err != nil {
		log.Warnf("[auto-topup] internal check for user=%s sandbox=%s failed: %v (will attempt)",
			rec.CreatedBy, sandboxID, err)
	} else if internal {
		return
	}
	// Cooldown check.
	if v, ok := h.autoTopupLast.Load(rec.CreatedBy); ok {
		if last, ok := v.(time.Time); ok && time.Since(last) < h.autoTopupCooldown {
			return
		}
	}
	h.autoTopupLast.Store(rec.CreatedBy, time.Now())

	go h.runAutoTopup(rec.ID, rec.CreatedBy, h.autoTopupGiB)
}

// runAutoTopup performs the credit check + recharge + local quota bump.
// All steps gated on success of the previous; partial failures log and
// stop. The cooldown is set before this goroutine fires so a repeated
// PATCH within the window can't race a parallel attempt.
func (h *Handler) runAutoTopup(sandboxID, userID string, gib float64) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	plan, err := h.createos.GetCurrentPlan(ctx, userID)
	if err != nil {
		if err != createos.ErrDisabled {
			log.Warnf("[auto-topup] current-plan for user=%s sandbox=%s: %v", userID, sandboxID, err)
		}
		return
	}
	if plan.Amount <= 0 {
		log.Infof("[auto-topup] user=%s sandbox=%s has no credit (amount=%.4f) — skipping recharge",
			userID, sandboxID, plan.Amount)
		return
	}

	rch, err := h.createos.RechargeEgressBandwidth(ctx, userID, sandboxID, gib)
	if err != nil {
		log.Warnf("[auto-topup] recharge for user=%s sandbox=%s gib=%.2f: %v", userID, sandboxID, gib, err)
		return
	}
	// Translate the granted GiB into bytes and add it to the local
	// sandbox's bandwidth_quota_bytes. The host's meter loop will
	// notice the higher quota on its next tick and lift any cap.
	addBytes := int64(gib * 1024 * 1024 * 1024)
	if err := models.RechargeSandboxBandwidth(ctx, h.repo.DB, sandboxID, addBytes); err != nil {
		log.Errorf("[auto-topup] local recharge for sandbox=%s after createos debit of %.4f credits: %v — credit was debited but local quota NOT bumped",
			sandboxID, rch.Amount, err)
		return
	}
	log.Infof("[auto-topup] user=%s sandbox=%s recharged %.2f GiB (debited %.4f credits)",
		userID, sandboxID, gib, rch.Amount)
}
