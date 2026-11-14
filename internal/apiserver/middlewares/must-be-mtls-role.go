package middlewares

import (
	"github.com/gofiber/fiber/v2"

	"github.com/NodeOps-app/createos-sandbox/internal/ca"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx/types"
)

// Locals keys read by downstream handlers (MustBeOwningHost, logging).
const (
	MTLSRoleLocalsKey     = "internal_mtls_role"
	MTLSIdentityLocalsKey = "internal_mtls_identity"
)

// MustBePeerRoleMTLS gates a route on a verified mTLS peer-cert SPIFFE URI.
// Internal routes are mounted on the mTLS-only :8443 listener, which requires
// a client cert at handshake time — so by the time this gate runs the cert is
// already cryptographically verified by the TLS stack. This middleware only
// enforces the *role* policy: extract the leaf's URI SAN, parse via
// ca.ParseSpiffeURI, and 403 if the resolved role is not in `roles`. On allow
// it stamps Locals (auth method, role, identity).
func (m *Middleware) MustBePeerRoleMTLS(roles ...string) fiber.Handler {
	allowed := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		allowed[r] = struct{}{}
	}
	return func(c *fiber.Ctx) error {
		// fasthttp wraps the conn for keepalive — c.Context().Conn() may
		// return a wrapper that doesn't type-assert to *tls.Conn. Use
		// TLSConnectionState() which fasthttp resolves correctly even
		// behind the wrapper. Fail-closed if any of the expected fields
		// is absent — that means the route was mounted on a non-mTLS
		// listener (misconfiguration) and we must refuse rather than
		// silently let unauthenticated traffic through.
		state := c.Context().TLSConnectionState()
		if state == nil || len(state.PeerCertificates) == 0 {
			return httpx.Fail(c, fiber.StatusUnauthorized,
				types.AuthError{Auth: "mTLS required"})
		}
		leaf := state.PeerCertificates[0]
		if len(leaf.URIs) == 0 {
			return httpx.Fail(c, fiber.StatusForbidden,
				types.AuthError{Auth: "peer cert missing SPIFFE URI SAN"})
		}
		ident, ok := ca.ParseSpiffeURI(leaf.URIs[0].String())
		if !ok {
			return httpx.Fail(c, fiber.StatusForbidden,
				types.AuthError{Auth: "unrecognised SPIFFE URI"})
		}
		role := ident.Role
		if ident.HostID != "" {
			role = ca.RoleHost
		}
		if _, ok := allowed[role]; !ok {
			return httpx.Fail(c, fiber.StatusForbidden,
				types.AuthError{Auth: "role not allowed"})
		}
		c.Locals(MTLSRoleLocalsKey, role)
		c.Locals(MTLSIdentityLocalsKey, ca.FormatSpiffeURI(ident))
		// Deliberately NO trust of X-CreateOS-User-Id on control's inbound
		// mTLS routes. None of them ("host" heartbeat, db proxy, tunnel-open
		// for ingress/gateway) carries a legitimate "vouches for end-user"
		// semantic — every one of them either acts as the role itself or
		// resolves user id from the DB by sandbox lookup. Trusting the
		// header here would let any cert-holder (e.g. a compromised host)
		// pivot into user-context routes by header injection.
		return c.Next()
	}
}
