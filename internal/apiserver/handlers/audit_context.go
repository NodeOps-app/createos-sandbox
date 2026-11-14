package handlers

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/middlewares"
	"github.com/NodeOps-app/createos-sandbox/internal/audit"
	"github.com/NodeOps-app/createos-sandbox/internal/utils"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// clientIP returns the real end-user IP, preferring Cloudflare's
// trusted header over the immediate TCP peer. c.IP() alone gives the
// in-cluster pod address (10.42.x.y) when control sits behind
// Cloudflare → nginx → service — not useful for audit forensics.
//
// Trust model: Cf-Connecting-Ip is set by Cloudflare at the edge and
// is overwritten on every hop, so callers can't spoof it AS LONG AS
// the listener isn't reachable from anything other than Cloudflare /
// our own ingress. That's the existing deployment posture documented
// in internal/ingress/main.go's sanitizeRequest.
func clientIP(c *fiber.Ctx) string {
	if v := strings.TrimSpace(c.Get("Cf-Connecting-Ip")); v != "" {
		return v
	}
	// X-Forwarded-For may be present from nginx-ingress when CF isn't
	// fronting. Take the leftmost entry (originating client).
	if v := strings.TrimSpace(c.Get("X-Forwarded-For")); v != "" {
		if i := strings.IndexByte(v, ','); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		if v != "" {
			return v
		}
	}
	return c.IP()
}

// auditCtx builds an audit.Context from the current request. Resolves
// the caller's api_key row once so the audit envelope carries the
// real actor name and is_internal flag — without this the shipper
// can't distinguish internal-user traffic (which is recorded but not
// shipped) from external-user traffic (which ships to the backend).
//
// API-key lookup failure is non-fatal: returns a populated Context
// with is_internal=false (fail-shipped) plus a warning log.
func (h *Handler) auditCtx(c *fiber.Ctx) audit.Context {
	uid := utils.UserIDFromContext(c.UserContext())
	authType, token, ok := middlewares.ExtractAuthToken(c)
	ac := audit.Context{
		UserID:    uid,
		RequestID: c.Get("X-Request-Id"),
		UserAgent: c.Get("User-Agent"),
		IPAddress: clientIP(c),
	}
	if !ok || token == "" {
		return ac
	}
	ac.HashedToken = audit.HashToken(token)
	if hint := utils.SandboxTokenHintFromContext(c.UserContext()); hint != "" {
		ac.Actor = "sandbox_access_token:" + hint
		return ac
	}
	// Internal-user fast path: middleware already resolved is_internal
	// during Resolve(); skip the LookupAPIKeyByHash DB call entirely.
	// The emitter drops internal-user events, so the actor name isn't
	// needed downstream. Under burst this lookup is the audit-stage
	// cost we're trying to shed (see pool-claim-slow logs).
	if utils.IsInternalFromContext(c.UserContext()) {
		ac.IsInternal = true
		return ac
	}
	rec, err := h.repo.LookupAPIKeyByHash(c.UserContext(), authType, h.apiKeyHasher.Hash(token))
	if err != nil {
		log.WithContext(c.UserContext()).Warnf("[audit] api-key lookup for %s: %v (treating as external)", uid, err)
		return ac
	}
	if rec != nil {
		if rec.Name != nil {
			ac.Actor = *rec.Name
		}
		ac.IsInternal = rec.IsInternal
	}
	return ac
}

// auditCtxForSandboxLifecycle preserves the sandbox owner's durable user ID
// while recording that a delegated sandbox credential initiated the action.
// This affects audit attribution only; it never promotes the request into a
// user principal or changes billing ownership.
func (h *Handler) auditCtxForSandboxLifecycle(c *fiber.Ctx, rec *models.Sandbox) audit.Context {
	ac := h.auditCtxWithSubject(c, "sandbox", rec.ID)
	if isSandboxPrincipal(c) {
		ac.UserID = rec.CreatedBy
		isInternal, err := h.repo.IsInternalUser(c.UserContext(), rec.CreatedBy)
		if err != nil {
			log.WithContext(c.UserContext()).Warnf("[audit] internal-owner lookup for sandbox %s: %v (treating as external)", rec.ID, err)
		} else {
			ac.IsInternal = isInternal
		}
	}
	return ac
}

// auditCtxWithSubject builds an audit.Context with subject info.
func (h *Handler) auditCtxWithSubject(
	c *fiber.Ctx, subjectType, subjectID string,
) audit.Context {
	ac := h.auditCtx(c)
	ac.SubjectType = subjectType
	ac.SubjectID = subjectID
	return ac
}
