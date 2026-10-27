package middlewares

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/apiserver/sandboxaccess"
	"github.com/NodeOps-app/sandbox/internal/apiserver/userapikey"
	"github.com/NodeOps-app/sandbox/internal/httpx"
	"github.com/NodeOps-app/sandbox/internal/httpx/types"
	"github.com/NodeOps-app/sandbox/internal/utils"
)

const invalidSandboxAccessTokenMessage = "invalid or disabled sandbox access token; use the sandbox owner's API key to create or rotate it"

// MustBeAuthenticated requires the request to carry a valid user token
// under one of four headers (X-Auth-Token, X-Access-Token, X-Api-Key, X-Agent-Token).
// A `?token=` query-string fallback is also honoured, but ONLY for the
// browser WebSocket route (`/shell-ws`) where headers can't be set —
// accepting `?token=` on every route would leak the bearer into upstream
// access logs. On success the matched user_id is stamped into c.Locals
// and the request context. Open paths (health probes, /v1/shapes,
// /v1/rootfs and /v1/internal/*) pass through. A nil Resolver
// fails closed on every protected path.
func (m *Middleware) MustBeAuthenticated() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if isOpenPath(c.Path()) {
			return c.Next()
		}
		if m.Resolver == nil {
			log.Error("[auth] user-key resolver is unavailable")
			return httpx.Error(c, fiber.StatusServiceUnavailable, "authentication unavailable")
		}
		authType, token, ok := ExtractAuthToken(c)
		var userID string
		var isInternal bool
		if ok {
			// Sandbox credentials are valid only under X-Api-Key. Never send
			// them to the normal resolver or its external-validator fallback.
			if authType == userapikey.AuthTypeAPIKey && strings.HasPrefix(token, sandboxaccess.Prefix) {
				if m.SandboxTokens == nil {
					return httpx.Fail(c, fiber.StatusUnauthorized,
						types.AuthError{Auth: invalidSandboxAccessTokenMessage})
				}
				resolved, found, err := m.SandboxTokens.Resolve(c.UserContext(), token)
				if err != nil {
					log.Errorf("[sandbox-access-token] resolve: %v", err)
					return httpx.Fail(c, fiber.StatusUnauthorized,
						types.AuthError{Auth: invalidSandboxAccessTokenMessage})
				}
				if !found {
					return httpx.Fail(c, fiber.StatusUnauthorized,
						types.AuthError{Auth: invalidSandboxAccessTokenMessage})
				}
				c.SetUserContext(utils.WithSandboxPrincipal(
					c.UserContext(), resolved.SandboxID, resolved.TokenHint,
				))
				return c.Next()
			}
			var extra map[string]string
			if authType == userapikey.AuthTypeMPPAgent {
				// Require X-Agent-Shared-Key alongside X-Agent-Token.
				// Without it, a leaked agent JWT alone could
				// authenticate — the backend's /v1/users/me validates
				// the JWT without checking the shared key.
				sk := strings.TrimSpace(c.Get(HeaderXAgentSharedKey))
				if sk == "" {
					return httpx.Fail(c, fiber.StatusUnauthorized,
						types.AuthError{Auth: "missing " + HeaderXAgentSharedKey + " header"})
				}
				extra = map[string]string{HeaderXAgentSharedKey: strings.Clone(sk)}
			}
			userID, isInternal, ok = m.Resolver.Resolve(authType, token, extra)
		} else if allowQueryTokenForPath(c.Path()) {
			if qt := strings.TrimSpace(c.Query("token")); qt != "" {
				qt = strings.Clone(qt)
				// Long-lived sandbox credentials are never accepted in URLs.
				if strings.HasPrefix(qt, sandboxaccess.Prefix) {
					return httpx.Fail(c, fiber.StatusUnauthorized,
						types.AuthError{Auth: "invalid api key"})
				}
				// Browser WebSocket APIs can't set headers — accept
				// ?token=… as a fallback ONLY on the WS path. The
				// query-string surface doesn't tell us which auth
				// type the token belongs to, so try all of them;
				// the resolver's per-type hash space keeps them
				// disjoint.
				// mpp_agent excluded — requires two headers
				// (X-Agent-Token + X-Agent-Shared-Key), can't
				// work from a single query param.
				for _, at := range []string{
					userapikey.AuthTypeAPIKey,
					userapikey.AuthTypeAccessToken,
					userapikey.AuthTypeAuthToken,
				} {
					if uid, ii, hit := m.Resolver.Resolve(at, qt, nil); hit {
						userID, isInternal, ok = uid, ii, true
						break
					}
				}
			}
		}
		if !ok {
			return httpx.Fail(c, fiber.StatusUnauthorized,
				types.AuthError{Auth: "invalid api key"})
		}
		c.Locals(utils.UserIDLocalsKey, userID)
		ctx := utils.WithUserID(c.UserContext(), userID)
		ctx = utils.WithIsInternal(ctx, isInternal)
		c.SetUserContext(ctx)
		return c.Next()
	}
}
