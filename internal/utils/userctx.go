// Package utils holds tiny cross-cutting helpers with no domain
// dependencies. Currently: the authenticated-user_id context plumbing
// shared between the HTTP middleware layer and the service layer.
package utils

import (
	"context"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

// HeaderUserID is the wire header used to propagate the end-user id on
// internal RPCs that don't carry a JWT uid claim (mTLS-only path). The
// receiving handler reads it via GetUserIDHeader. Never trust this header
// from an externally-reachable interface — it must be stripped at the
// edge proxy / ingress.
const HeaderUserID = "X-CreateOS-User-Id"

// SetUserIDHeader stamps the user id onto an outgoing internal request.
// No-op when userID is empty so callers don't have to branch.
func SetUserIDHeader(req *http.Request, userID string) {
	if userID == "" {
		return
	}
	req.Header.Set(HeaderUserID, userID)
}

// GetUserIDHeader returns the X-CreateOS-User-Id header from an inbound
// Fiber request as supplied by Fiber, without additional trimming. Empty when absent.
func GetUserIDHeader(c *fiber.Ctx) string {
	return c.Get(HeaderUserID)
}

// UserIDLocalsKey is the c.Locals key under which the authentication
// middleware stamps the resolved user_id.
const UserIDLocalsKey = "user_id"

// ctxKey is the type used for our context.WithValue keys.
type ctxKey struct{ name string }

var userIDCtxKey = ctxKey{"user_id"}

var (
	sandboxPrincipalIDCtxKey = ctxKey{"sandbox_principal_id"}
	sandboxTokenHintCtxKey   = ctxKey{"sandbox_token_hint"}
)

// UserIDFromContext reads the authenticated user_id from a context.
// Returns "" if absent (auth disabled or open route).
func UserIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(userIDCtxKey).(string)
	return v
}

// WithUserID returns a derived context carrying user_id. Exposed mainly
// so the control plane can stamp a forwarded request before invoking
// handlers.
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDCtxKey, userID)
}

// WithSandboxPrincipal uses the existing authenticated-request context to
// carry a delegated sandbox identity without fabricating an owning user ID.
func WithSandboxPrincipal(ctx context.Context, sandboxID, tokenHint string) context.Context {
	ctx = context.WithValue(ctx, sandboxPrincipalIDCtxKey, sandboxID)
	return context.WithValue(ctx, sandboxTokenHintCtxKey, tokenHint)
}

func SandboxPrincipalIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(sandboxPrincipalIDCtxKey).(string)
	return v
}

func SandboxTokenHintFromContext(ctx context.Context) string {
	v, _ := ctx.Value(sandboxTokenHintCtxKey).(string)
	return v
}

// UserID returns the authenticated user_id stamped into c.Locals by the
// auth middleware, or "" if auth is disabled / the route was open.
func UserID(c *fiber.Ctx) string {
	s, _ := c.Locals(UserIDLocalsKey).(string)
	return s
}

var isInternalCtxKey = ctxKey{"is_internal"}

// WithIsInternal stamps the api-key's is_internal bit onto ctx. Set by
// the auth middleware once per request so downstream (models, emitters)
// can branch without re-reading api_keys. Mirrors WithUserID.
func WithIsInternal(ctx context.Context, isInternal bool) context.Context {
	return context.WithValue(ctx, isInternalCtxKey, isInternal)
}

// IsInternalFromContext reads the is_internal bit. Returns false when
// absent (open route / unauth caller) — the safe default (never skip
// billing/audit for unknown callers).
func IsInternalFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(isInternalCtxKey).(bool)
	return v
}
