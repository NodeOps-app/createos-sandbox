package middlewares

import (
	"github.com/gofiber/fiber/v2"

	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx/types"
)

const (
	// maxJSONBodyBytes caps user-facing JSON request bodies at 256 KiB.
	// Real user requests on /v1/sandboxes, /v1/disks, /v1/templates,
	// /v1/networks are well under 10 KiB even with full envs + egress
	// lists + 16 SSH pubkeys (~4 KiB) + a Dockerfile (~32 KiB cap).
	// 256 KiB leaves ample headroom while still ruling out
	// resource-exhaustion attacks that wrap themselves in valid JSON.
	maxJSONBodyBytes = 256 * 1024
	// maxJSONDepth bounds nested object/array brackets before decoding.
	// It is deliberately much lower than encoding/json's nesting limit.
	// 32 is well above anything our schemas need (deepest legitimate
	// JSON is ~4 levels: sandboxes -> disks[] -> {config:{...}}).
	maxJSONDepth = 32
)

// JSONGuard enforces an early body-size + JSON-depth cap on user-facing
// JSON endpoints. The default Fiber BodyLimit is sized for the 500 MB
// file-upload path; without this, /v1/sandboxes (and every other JSON
// handler) inherits that limit and parses unbounded payloads.
//
// Skips the same routes RequireJSON skips: file uploads (raw bytes),
// the separately authenticated internal tree, health/catalog probes.
func (m *Middleware) JSONGuard() fiber.Handler {
	return func(c *fiber.Ctx) error {
		method := c.Method()
		if method != fiber.MethodPost && method != fiber.MethodPut && method != fiber.MethodPatch {
			return c.Next()
		}
		if skipJSONEnforcement(c.Path()) {
			return c.Next()
		}
		body := c.Body()
		if len(body) == 0 {
			return c.Next()
		}
		if len(body) > maxJSONBodyBytes {
			return httpx.Fail(c, fiber.StatusRequestEntityTooLarge,
				types.FieldError{"body": "request body too large"})
		}
		if exceedsJSONDepth(body, maxJSONDepth) {
			return httpx.Fail(c, fiber.StatusBadRequest,
				types.FieldError{"body": "JSON nesting too deep"})
		}
		return c.Next()
	}
}

// exceedsJSONDepth scans `b` and returns true as soon as a single
// nested-bracket chain (objects + arrays combined) exceeds `max`. We
// don't parse — we just count `{` / `[` outside of strings, stopping
// the moment the limit is breached so a hostile 256 KiB blob doesn't
// even get walked end-to-end. Escape sequences inside strings are
// skipped so an opener inside a quoted value (e.g. `"{{{{"`) is not
// mistakenly counted.
func exceedsJSONDepth(b []byte, max int) bool {
	depth, peak := 0, 0
	inStr := false
	for i := 0; i < len(b); i++ {
		ch := b[i]
		if inStr {
			if ch == '\\' && i+1 < len(b) {
				i++ // skip escaped char
				continue
			}
			if ch == '"' {
				inStr = false
			}
			continue
		}
		switch ch {
		case '"':
			inStr = true
		case '{', '[':
			depth++
			if depth > peak {
				peak = depth
				if peak > max {
					return true
				}
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return false
}
