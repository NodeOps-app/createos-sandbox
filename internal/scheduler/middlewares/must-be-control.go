package middlewares

import (
	"github.com/gofiber/fiber/v2"

	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx/types"
)

// schedulerAudience is the audience expected by the optional JWT middleware.
// The current scheduler HTTP server does not install this middleware.
const schedulerAudience = "scheduler"

// MustBeControl verifies a JWT with aud=scheduler when installed on a route.
// It stores verified issuer/claims in c.Locals and rejects requests with 503
// when no verifier is configured. The current server uses listener mTLS
// instead of this application-level middleware.
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
