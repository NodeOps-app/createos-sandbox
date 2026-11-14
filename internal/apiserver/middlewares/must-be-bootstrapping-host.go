package middlewares

import (
	"crypto/subtle"

	"github.com/gofiber/fiber/v2"

	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx/types"
	"github.com/NodeOps-app/createos-sandbox/internal/utils"
)

// BootstrapTokenKind is what the bootstrap-token middleware writes to
// c.Locals after a successful match. Handlers read it via
// BootstrapKindFromCtx to enforce role-token binding (e.g., reject a
// register req with Role="relay" if the request authenticated with the
// compute-host bootstrap token).
type BootstrapTokenKind string

const (
	BootstrapKindCompute BootstrapTokenKind = "compute"
	BootstrapKindRelay   BootstrapTokenKind = "relay"
)

const bootstrapKindLocalsKey = "bootstrap_kind"

// BootstrapKindFromCtx returns the kind set by MustBeBootstrappingHost,
// or "" if the request didn't go through it.
func BootstrapKindFromCtx(c *fiber.Ctx) BootstrapTokenKind {
	v, _ := c.Locals(bootstrapKindLocalsKey).(BootstrapTokenKind)
	return v
}

// MustBeBootstrappingHost gates POST /v1/internal/hosts/register — the
// one-time call a host makes before it has a signing key registered.
//
// Accepts either of TWO shared secrets:
//   - BootstrapToken      → tagged BootstrapKindCompute
//   - RelayBootstrapToken → tagged BootstrapKindRelay
//
// The handler reads the tag from c.Locals and enforces that
// req.Role matches: relay-token can ONLY mint role="relay" hosts and
// vice versa. This narrows blast radius: a leaked compute token can't
// stand up a rogue relay (and vice versa).
//
// Either being unconfigured silently disables that kind — fail-closed.
func (m *Middleware) MustBeBootstrappingHost() fiber.Handler {
	computeWant := []byte(m.BootstrapToken)
	relayWant := []byte(m.RelayBootstrapToken)
	return func(c *fiber.Ctx) error {
		if m.BootstrapToken == "" && m.RelayBootstrapToken == "" {
			return httpx.Error(c, fiber.StatusServiceUnavailable,
				"host registration disabled (no bootstrap_token configured)")
		}
		got := []byte(c.Get(HeaderBootstrapToken))
		if len(got) == 0 {
			return httpx.Fail(c, fiber.StatusUnauthorized,
				types.AuthError{Auth: "invalid bootstrap token"})
		}
		var kind BootstrapTokenKind
		// Always run BOTH comparisons (constant-time) before branching,
		// so a timing attacker can't distinguish "wrong compute token"
		// from "wrong relay token".
		computeMatch := len(computeWant) > 0 && subtle.ConstantTimeCompare(got, computeWant) == 1
		relayMatch := len(relayWant) > 0 && subtle.ConstantTimeCompare(got, relayWant) == 1
		switch {
		case computeMatch:
			kind = BootstrapKindCompute
		case relayMatch:
			kind = BootstrapKindRelay
		default:
			return httpx.Fail(c, fiber.StatusUnauthorized,
				types.AuthError{Auth: "invalid bootstrap token"})
		}
		c.Locals(bootstrapKindLocalsKey, kind)
		return c.Next()
	}
}

// guard against unused-import on utils for downstream package layout
var _ = utils.UserIDFromContext
