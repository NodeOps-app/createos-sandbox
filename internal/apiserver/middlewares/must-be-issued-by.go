package middlewares

import (
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx/types"
	authjwt "github.com/NodeOps-app/createos-sandbox/internal/jwt"
	"github.com/NodeOps-app/createos-sandbox/internal/utils"
)

// Identity kinds — the canonical name for "which kind of internal actor
// sent this token", derived from the verified JWT's iss/Role.
const (
	KindHost      = "host"
	KindHostProxy = "host-proxy"
	KindGateway   = "gateway"
	KindIngress   = "ingress"
	KindBuilder   = "builder"
	KindControl   = "control"
	KindBilling   = "billing"
)

// IdentityKind derives the caller's identity kind from a verified
// *jwt.Claims. The kind is the role prefix before ':' in the iss
// ("<role>:<id>"), with one special case: a host iss whose Role is
// "proxy" is the distinct kind "host-proxy" (a host-minted proxy
// token, signed with the host's key but acting as the proxy).
// Returns "" for an unrecognised / empty iss.
func IdentityKind(c *authjwt.Claims) string {
	if c == nil || c.Iss == "" {
		return ""
	}
	role := c.Iss
	if i := strings.IndexByte(role, ':'); i >= 0 {
		role = role[:i]
	}
	switch role {
	case "host":
		if c.Role == "proxy" {
			return KindHostProxy
		}
		return KindHost
	case "gateway":
		return KindGateway
	case "ingress":
		return KindIngress
	case "builder":
		return KindBuilder
	case "billing":
		return KindBilling
	case "control":
		return KindControl
	default:
		return ""
	}
}

// MustBeIssuedBy verifies an Ed25519-signed JWT in the Authorization
// header, requires aud=control, and asserts the caller's identity kind
// is one of the permitted kinds. It is self-contained — it does the
// verification itself and replaces MustBeInternalService.
//
// On success it stamps the JWT's iss and full claims into c.Locals so
// downstream gates (MustBeOwningHost) can authorise per-resource.
//
// A nil verifier disables the gated endpoints (503).
func (m *Middleware) MustBeIssuedBy(kinds ...string) fiber.Handler {
	if m.JWTVerifier == nil {
		return func(c *fiber.Ctx) error {
			return httpx.Error(c, fiber.StatusServiceUnavailable,
				"internal endpoints disabled (no JWT verifier)")
		}
	}
	allowed := make(map[string]struct{}, len(kinds))
	for _, k := range kinds {
		allowed[k] = struct{}{}
	}
	return func(c *fiber.Ctx) error {
		token, ok := bearerToken(c.Get(HeaderAuthorization))
		if !ok {
			return httpx.Fail(c, fiber.StatusUnauthorized,
				types.AuthError{Auth: "missing or malformed Authorization header"})
		}
		claims, err := m.JWTVerifier.VerifyExpect(token, "control")
		if err != nil {
			return httpx.Fail(c, fiber.StatusUnauthorized,
				types.AuthError{Auth: "invalid JWT: " + err.Error()})
		}
		kind := IdentityKind(claims)
		if _, ok := allowed[kind]; kind == "" || !ok {
			shown := kind
			if shown == "" {
				shown = "unknown"
			}
			return httpx.Fail(c, fiber.StatusForbidden,
				types.AuthError{Auth: "caller kind " + shown + " not permitted here"})
		}
		c.Locals(IssLocalsKey, claims.Iss)
		c.Locals(ClaimsLocalsKey, claims)
		// Preserve the verified originating user for downstream request context.
		// Host forwarding uses mTLS, not a newly signed host JWT.
		if claims.UserID != "" {
			c.SetUserContext(utils.WithUserID(c.UserContext(), claims.UserID))
		}
		return c.Next()
	}
}
