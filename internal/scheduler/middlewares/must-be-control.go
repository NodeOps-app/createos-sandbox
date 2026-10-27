package middlewares

import (
	"github.com/gofiber/fiber/v2"

	"github.com/NodeOps-app/sandbox/internal/httpx"
	"github.com/NodeOps-app/sandbox/internal/httpx/types"
)

// schedulerAudience is the JWT audience the scheduler accepts. Only the
// control plane calls the scheduler, and it signs its JWTs aud=scheduler.
const schedulerAudience = "scheduler"

// MustBeControl requires the request to come from the control plane,
// proven by an Ed25519-signed JWT with aud=scheduler. The scheduler
// service exposes no user-facing routes — control is its only client.
// On success the JWT's iss and claims are stamped into c.Locals. A nil
// verifier disables the gated endpoints (503).
func (m *Middleware) MustBeControl() fiber.Handler {
	if m.JWTVerifier == nil {
		return func(c *fiber.Ctx) error {
			return httpx.Error(c, fiber.StatusServiceUnavailable,
				"scheduler endpoints disabled (no JWT verifier)")
		}
	}
	return func(c *fiber.Ctx) error {
		token, ok := bearerToken(c.Get(HeaderAuthorization))
		if !ok {
			return httpx.Fail(c, fiber.StatusUnauthorized,
				types.AuthError{Auth: "missing or malformed Authorization header"})
		}
		claims, err := m.JWTVerifier.VerifyExpect(token, schedulerAudience)
		if err != nil {
			return httpx.Fail(c, fiber.StatusUnauthorized,
				types.AuthError{Auth: "invalid JWT: " + err.Error()})
		}
		c.Locals(IssLocalsKey, claims.Iss)
		c.Locals(ClaimsLocalsKey, claims)
		return c.Next()
	}
}
