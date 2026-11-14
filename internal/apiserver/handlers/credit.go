package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/middlewares"
)

// checkCredit gates user-initiated cost-incurring actions (create
// sandbox/network/disk/template, resume, bandwidth recharge) on a
// positive credit balance.
//
// Returns (status, errorMessage, false) when the gate should block; ok=true
// when the caller may proceed. Internal API keys always pass through.
//
// API-key resolution fails closed: if the authenticated key cannot be
// resolved again for billing, the chargeable action is rejected rather than
// bypassing the credit gate. The LimitsProvider separately defines the policy
// for an unavailable external billing service.
func (h *Handler) checkCredit(c *fiber.Ctx) (int, string, bool) {
	authType, token, hasAuth := middlewares.ExtractAuthToken(c)
	if !hasAuth {
		// Auth middleware already runs before us — reaching here without
		// auth means a misrouted unauth'd handler. Block, not silently
		// allow.
		return http.StatusUnauthorized, "missing auth", false
	}
	keyRec, err := h.repo.LookupAPIKeyByHash(c.UserContext(), authType, h.apiKeyHasher.Hash(token))
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[credit] api-key lookup: %v", err)
		return http.StatusServiceUnavailable, "unable to verify credit; please retry", false
	}
	if keyRec == nil {
		return http.StatusUnauthorized, "unauthorized", false
	}
	if keyRec.IsInternal {
		// Internal keys (operator-issued) always bypass.
		return 0, "", true
	}
	L := h.limits.Get(c.UserContext(), keyRec.UserID, keyRec.IsInternal)
	if L.HasCredit() {
		return 0, "", true
	}
	return http.StatusPaymentRequired, "insufficient credit; please top up to continue", false
}

// checkSandboxConcurrencyQuotaFor enforces the per-user concurrent +
// per-day sandbox caps against an already-resolved Limits snapshot.
// Counts every non-terminal sandbox (running, paused, pausing, resuming,
// ...) toward the concurrent cap so a user can't slip past it by pausing
// and re-creating, or by forking a paused source.
//
// Caller is expected to have already looked up the api-key and checked
// IsInternal — this helper assumes the user is non-internal. Returns
// (status, message, ok); on ok=false the caller returns httpx.Fail
// (or httpx.Error for 5xx) using the returned status.
func (h *Handler) checkSandboxConcurrencyQuotaFor(c *fiber.Ctx, userID string, L Limits) (int, string, bool) {
	if cap := L.MaxSandboxes; cap >= 0 {
		n, cerr := h.repo.CountSandboxesActive(c.UserContext(), userID)
		if cerr != nil {
			log.WithContext(c.UserContext()).Errorf("[quota] sandbox concurrent count: %v", cerr)
			return fiber.StatusServiceUnavailable, "internal error", false
		}
		if n >= cap {
			return fiber.StatusTooManyRequests, fmt.Sprintf(
				"sandbox concurrent quota reached (%d / %d). Destroy or pause one before creating another.",
				n, cap), false
		}
	}
	if cap := L.MaxSandboxesPerDay; cap >= 0 {
		n, cerr := h.repo.CountSandboxesSince(c.UserContext(), userID, time.Now().Add(-24*time.Hour))
		if cerr != nil {
			log.WithContext(c.UserContext()).Errorf("[quota] sandbox per-day count: %v", cerr)
			return fiber.StatusServiceUnavailable, "internal error", false
		}
		if n >= cap {
			return fiber.StatusTooManyRequests, fmt.Sprintf(
				"sandbox per-day quota reached (%d / %d). Try again in 24h or contact an operator.",
				n, cap), false
		}
	}
	return 0, "", true
}

// checkSandboxConcurrencyQuotaExcept is the resume-flavour. Counts active
// sandboxes EXCLUDING `excludeID` (the row being resumed) so a free-tier
// user with one paused VM can resume it — the paused row would otherwise
// count toward the cap and block its own resume.
//
// Per-day cap behaviour is unchanged: resume is not a creation event
// and per-day counts creation timestamps; the same call still runs.
func (h *Handler) checkSandboxConcurrencyQuotaExceptFor(c *fiber.Ctx, userID, excludeID string, L Limits) (int, string, bool) {
	if cap := L.MaxSandboxes; cap >= 0 {
		n, cerr := h.repo.CountSandboxesActiveExcept(c.UserContext(), userID, excludeID)
		if cerr != nil {
			log.WithContext(c.UserContext()).Errorf("[quota] sandbox concurrent count (except): %v", cerr)
			return fiber.StatusServiceUnavailable, "internal error", false
		}
		if n >= cap {
			return fiber.StatusTooManyRequests, fmt.Sprintf(
				"sandbox concurrent quota reached (%d / %d). Destroy or pause one before resuming another.",
				n, cap), false
		}
	}
	if cap := L.MaxSandboxesPerDay; cap >= 0 {
		n, cerr := h.repo.CountSandboxesSince(c.UserContext(), userID, time.Now().Add(-24*time.Hour))
		if cerr != nil {
			log.WithContext(c.UserContext()).Errorf("[quota] sandbox per-day count: %v", cerr)
			return fiber.StatusServiceUnavailable, "internal error", false
		}
		if n >= cap {
			return fiber.StatusTooManyRequests, fmt.Sprintf(
				"sandbox per-day quota reached (%d / %d). Try again in 24h or contact an operator.",
				n, cap), false
		}
	}
	return 0, "", true
}

// checkSandboxConcurrencyQuota is the no-context-yet variant used by
// callers (like fork) that don't already have keyRec/Limits in hand.
// Performs the api-key lookup, bypasses internal keys, then delegates
// to checkSandboxConcurrencyQuotaFor.
func (h *Handler) checkSandboxConcurrencyQuota(c *fiber.Ctx) (int, string, bool) {
	authType, token, hasAuth := middlewares.ExtractAuthToken(c)
	if !hasAuth {
		return fiber.StatusUnauthorized, "missing auth", false
	}
	keyRec, err := h.repo.LookupAPIKeyByHash(c.UserContext(), authType, h.apiKeyHasher.Hash(token))
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[quota] api-key lookup: %v", err)
		return fiber.StatusServiceUnavailable, "internal error", false
	}
	if keyRec == nil {
		return fiber.StatusUnauthorized, "unauthorized", false
	}
	if keyRec.IsInternal {
		return 0, "", true
	}
	L := h.limits.Get(c.UserContext(), keyRec.UserID, keyRec.IsInternal)
	return h.checkSandboxConcurrencyQuotaFor(c, keyRec.UserID, L)
}
