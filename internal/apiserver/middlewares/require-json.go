package middlewares

import (
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx/types"
)

// RequireJSON enforces that any user-facing request with a body uses
// `Content-Type: application/json`. Fiber's BodyParser dispatches on
// Content-Type and will happily parse XML / form-encoded payloads if
// the client sets the matching header — coercion rules differ from
// JSON's, so the same handler can see different field values depending
// on which parser ran (CWE-20). Pinning to JSON makes input parsing
// behaviour identical regardless of what the client claims.
//
// Pass-through rules:
//   - Methods that don't carry a body (GET / DELETE / HEAD / OPTIONS).
//   - Empty body (Content-Length == 0).
//   - Empty Content-Type — matches Fiber's default-to-JSON behaviour and
//     keeps existing clients that omit the header working.
//   - Routes that take raw bytes rather than JSON (file uploads).
//   - The /v1/internal/* separately authenticated tree (may carry NDJSON log streams,
//     raw tunnel upgrades, etc).
//   - Health / catalog probes.
//
// Anything else with a non-JSON Content-Type gets a 415.
func (m *Middleware) RequireJSON() fiber.Handler {
	return func(c *fiber.Ctx) error {
		method := c.Method()
		if method != fiber.MethodPost && method != fiber.MethodPut && method != fiber.MethodPatch {
			return c.Next()
		}
		if skipJSONEnforcement(c.Path()) {
			return c.Next()
		}
		if len(c.Body()) == 0 {
			return c.Next()
		}
		ct := strings.TrimSpace(c.Get(fiber.HeaderContentType))
		if ct == "" {
			return c.Next()
		}
		if !strings.HasPrefix(ct, "application/json") {
			return httpx.Fail(c, fiber.StatusUnsupportedMediaType,
				types.FieldError{"content_type": "expected application/json"})
		}
		return c.Next()
	}
}

// skipJSONEnforcement reports routes exempt from the JSON-only gate:
// file upload (raw bytes), the separately authenticated internal tree (NDJSON / tunnel
// upgrades / etc), and health/catalog probes.
func skipJSONEnforcement(p string) bool {
	switch {
	case p == "/healthz", p == "/readyz", p == "/metrics", p == "/v1/shapes", p == "/v1/rootfs":
		return true
	case strings.HasPrefix(p, "/v1/internal/"):
		return true
	case strings.HasPrefix(p, "/v1/sandboxes/") && strings.HasSuffix(p, "/files"):
		// PUT /v1/sandboxes/:id/files — body is the file bytes.
		return true
	}
	return false
}
