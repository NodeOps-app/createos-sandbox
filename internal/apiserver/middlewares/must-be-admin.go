package middlewares

import (
	"crypto/subtle"

	"github.com/gofiber/fiber/v2"

	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx/types"
)

// MustBeAdmin gates the deliberately narrow host-operations and pprof surface
// behind a shared token compared in constant time. An empty configured token
// keeps the endpoints disabled.
func (m *Middleware) MustBeAdmin() fiber.Handler {
	want := []byte(m.AdminToken)
	return func(c *fiber.Ctx) error {
		if m.AdminToken == "" {
			return httpx.Error(c, fiber.StatusServiceUnavailable,
				"admin operations disabled (no admin_token configured)")
		}
		got := c.Get(HeaderAdminToken)
		if got == "" || subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			return httpx.Fail(c, fiber.StatusUnauthorized,
				types.AuthError{Auth: "invalid token"})
		}
		return c.Next()
	}
}

// MustReadMetrics accepts only the separate read-only credential. Never fall back
// to the operator token: browsers must not need host-management privileges.
func (m *Middleware) MustReadMetrics() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if m.MetricsToken == "" || m.MetricsToken == m.AdminToken {
			return httpx.Error(c, fiber.StatusServiceUnavailable, "dashboard access disabled")
		}
		got := c.Get(HeaderAdminToken)
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(m.MetricsToken)) != 1 {
			return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid token"})
		}
		return c.Next()
	}
}
