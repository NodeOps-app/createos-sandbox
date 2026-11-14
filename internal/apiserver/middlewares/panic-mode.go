package middlewares

import (
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
)

// PanicMode is an emergency public-API kill switch. It deliberately leaves
// health probes and operator/service routes reachable so the control plane can
// be diagnosed and recovered without reopening the user-facing API.
func PanicMode(enabled bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !enabled || panicModeExemptPath(c.Path()) {
			return c.Next()
		}
		return httpx.Fail(c, fiber.StatusServiceUnavailable,
			"service under maintenance")
	}
}

func panicModeExemptPath(path string) bool {
	if path == "/healthz" || path == "/readyz" {
		return true
	}
	return strings.HasPrefix(path, "/v1/internal/") ||
		strings.HasPrefix(path, "/v1/admin/")
}
