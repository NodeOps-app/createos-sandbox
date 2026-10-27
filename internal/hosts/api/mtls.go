package api

import (
	"github.com/gofiber/fiber/v2"
	"strconv"
	"time"

	"github.com/NodeOps-app/sandbox/internal/ca"
	"github.com/NodeOps-app/sandbox/internal/hosts/metrics"
	"github.com/NodeOps-app/sandbox/internal/httpx"
	"github.com/NodeOps-app/sandbox/internal/httpx/types"
	"github.com/NodeOps-app/sandbox/internal/requestctx"
	"github.com/NodeOps-app/sandbox/internal/utils"
)

// InstrumentInternalRPC labels metrics with registered route templates, never
// attacker-controlled URLs or resource IDs. Resolve the route after Next so
// matched endpoints replace the group middleware's prefix.
func InstrumentInternalRPC(service string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		started := time.Now()
		err := c.Next()
		path := c.Route().Path
		metrics.InternalRPC.WithLabelValues(service, path).Inc()
		metrics.InternalRPCSeconds.WithLabelValues(service, path, hostStatusClass(c.Response().StatusCode())).Observe(time.Since(started).Seconds())
		return err
	}
}

func hostStatusClass(status int) string {
	if status < 100 {
		return "other"
	}
	return strconv.Itoa(status/100) + "xx"
}

// Locals keys read by downstream handlers / logging.
const (
	MTLSRoleLocalsKey     = "internal_mtls_role"
	MTLSIdentityLocalsKey = "internal_mtls_identity"
)

// HostMustBePeerRoleMTLS gates a host-side route on a verified mTLS peer-cert
// SPIFFE URI. The host listener is mTLS-only, so by the time this gate runs
// the cert is already cryptographically verified by the TLS stack — this
// middleware only enforces the *role* policy. Missing TLS state / peer cert /
// SAN means the route was mounted on a plain listener (misconfig); fail-closed
// rather than silently passing the request through.
func (s *Server) HostMustBePeerRoleMTLS(roles ...string) fiber.Handler {
	allowed := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		allowed[r] = struct{}{}
	}
	return func(c *fiber.Ctx) error {
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
		if id := c.Params("id"); id != "" {
			c.Locals("sandbox_id", id)
			c.SetUserContext(requestctx.WithSandboxID(c.UserContext(), id))
		}
		// Under mTLS the end-user id rides as a plain X-CreateOS-User-Id
		// header. Only control mints these forwards (it's the only role
		// that resolves an API key to a user). Gate the header trust on
		// role==control so a compromised ingress/gateway cert can't
		// inject a victim's user id into a tunnel-open request.
		if role == ca.RoleControl {
			if uid := utils.GetUserIDHeader(c); uid != "" {
				c.Locals(utils.UserIDLocalsKey, uid)
				c.SetUserContext(utils.WithUserID(c.UserContext(), uid))
			}
		}
		return c.Next()
	}
}
