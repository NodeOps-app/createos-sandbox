// Package middlewares holds the control plane's HTTP middleware — one
// fiber gate per file, each a method on Middleware with its logic
// declared inline. It references the API-key Resolver and JWT Verifier
// for shared types and owns its own locals-key constants; the gate
// logic itself lives here.
package middlewares

import (
	"context"
	"strings"

	"github.com/NodeOps-app/sandbox/internal/apiserver/sandboxaccess"
	"github.com/NodeOps-app/sandbox/internal/apiserver/userapikey"
	authjwt "github.com/NodeOps-app/sandbox/internal/jwt"
	"github.com/NodeOps-app/sandbox/internal/proto"

	"github.com/gofiber/fiber/v2"
)

// Request headers the control plane's gates inspect.
const (
	// HeaderAuthorization carries internal-service JWTs as
	// `Bearer <jwt>` between control, hosts, gateway, ingress,
	// scheduler, builder. NOT used for user-facing auth — those go
	// through the X-Api-Key / X-Auth-Token / X-Access-Token headers.
	HeaderAuthorization   = "Authorization"
	BearerPrefix          = "Bearer "
	HeaderAdminToken      = "X-Admin-Token"
	HeaderBootstrapToken  = proto.HeaderBootstrapToken
	HeaderXAuthToken      = "X-Auth-Token"
	HeaderXAccessToken    = "X-Access-Token"
	HeaderXAPIKey         = proto.HeaderAPIKey
	HeaderXAgentToken     = "X-Agent-Token"
	HeaderXAgentSharedKey = "X-Agent-Shared-Key"
)

// IssLocalsKey is the c.Locals key under which MustBeIssuedBy
// stamps the JWT's iss claim ("<role>:<id>"). Downstream gates
// (MustBeOwningHost) read it to authorise.
const IssLocalsKey = "internal_iss"

// ClaimsLocalsKey is the c.Locals key under which the full *jwt.Claims
// is stamped. Used by handlers/middleware needing more than iss.
const ClaimsLocalsKey = "internal_jwt_claims"

// SandboxOwnerLookup returns the active host assignment for a sandbox.
// found distinguishes a missing row from an existing row with host_id=NULL;
// neither case grants a machine access.
type SandboxOwnerLookup func(ctx context.Context, sandboxID string) (hostID string, found bool, err error)

// SandboxTokenResolver authenticates the delegated skp_sb_ credential without
// turning it into a user identity. The concrete implementation performs a
// durable lookup on every request so hard-delete revocation is immediate.
type SandboxTokenResolver interface {
	Resolve(ctx context.Context, token string) (sandboxaccess.ResolvedToken, bool, error)
}

// Middleware carries the control plane's auth dependencies. Construct it
// once in server wiring with NewMiddleware, then mount its MustBe* gates
// on routes.
type Middleware struct {
	Resolver      userapikey.Resolver
	SandboxTokens SandboxTokenResolver
	JWTVerifier   *authjwt.Verifier
	AdminToken    string
	// BootstrapToken gates registration of role="compute" hosts (and
	// legacy unset-role hosts). Distinct from RelayBootstrapToken so a
	// leaked compute-onboarding secret can't be used to stand up a rogue
	// relay (and vice versa) — narrows blast radius of either leak.
	BootstrapToken      string
	RelayBootstrapToken string
	SandboxOwnerLookup  SandboxOwnerLookup
}

func (m *Middleware) SetSandboxTokenResolver(resolver SandboxTokenResolver) {
	m.SandboxTokens = resolver
}

// NewMiddleware wires the control plane's middleware dependencies.
func NewMiddleware(resolver userapikey.Resolver, verifier *authjwt.Verifier, adminToken, bootstrapToken, relayBootstrapToken string, sandboxOwner SandboxOwnerLookup) *Middleware {
	return &Middleware{
		Resolver:            resolver,
		JWTVerifier:         verifier,
		AdminToken:          adminToken,
		BootstrapToken:      bootstrapToken,
		RelayBootstrapToken: relayBootstrapToken,
		SandboxOwnerLookup:  sandboxOwner,
	}
}

// JWTSub returns the JWT's `sub` claim from the request locals, or the
// empty string if no JWT was verified. Used by handlers that authorise
// based on per-resource scoping (e.g. builder JWTs whose sub == tpl_id).
func JWTSub(c *fiber.Ctx) string {
	cl, ok := c.Locals(ClaimsLocalsKey).(*authjwt.Claims)
	if !ok || cl == nil {
		return ""
	}
	return cl.Sub
}

// bearerToken extracts a JWT from an `Authorization: Bearer <token>`
// header. Used by internal-service gates only — user-facing auth
// flows through ExtractAuthToken below.
func bearerToken(header string) (string, bool) {
	if len(header) < len(BearerPrefix) ||
		!strings.EqualFold(header[:len(BearerPrefix)], BearerPrefix) {
		return "", false
	}
	tok := strings.TrimSpace(header[len(BearerPrefix):])
	return tok, tok != ""
}

// ExtractAuthToken inspects an inbound request for one of the four
// supported auth headers, in priority order. Returns the (auth_type,
// token) pair or ("", "", false) if none was set / all empty.
//
// Priority:
//
//  1. X-Auth-Token   → auth_token
//  2. X-Access-Token → access_token
//  3. X-Api-Key      → api_key
//  4. X-Agent-Token  → mpp_agent
//
// Multiple headers set: first one wins, the rest are ignored. This
// avoids ambiguity in the cache key — a single request maps to a single
// (type, hash) pair regardless of how clumsily the client populated
// headers.
// allowQueryTokenForPath reports whether the path is one of the few
// routes where `?token=…` is an acceptable auth fallback. Restricted
// to the browser WebSocket endpoints — accepting it on every route
// would leak bearer tokens into Cloudflare / nginx / fiber access logs.
func allowQueryTokenForPath(p string) bool {
	return strings.HasSuffix(p, "/shell-ws")
}

func ExtractAuthToken(c *fiber.Ctx) (authType, token string, ok bool) {
	if v := strings.TrimSpace(c.Get(HeaderXAuthToken)); v != "" {
		return userapikey.AuthTypeAuthToken, strings.Clone(v), true
	}
	if v := strings.TrimSpace(c.Get(HeaderXAccessToken)); v != "" {
		return userapikey.AuthTypeAccessToken, strings.Clone(v), true
	}
	if v := strings.TrimSpace(c.Get(HeaderXAPIKey)); v != "" {
		return userapikey.AuthTypeAPIKey, strings.Clone(v), true
	}
	if v := strings.TrimSpace(c.Get(HeaderXAgentToken)); v != "" {
		return userapikey.AuthTypeMPPAgent, strings.Clone(v), true
	}
	return "", "", false
}

// isOpenPath reports paths that skip user API-key auth: health probes,
// public catalog reads, and the separately-gated internal/admin route trees.
func isOpenPath(p string) bool {
	switch {
	case p == "/healthz", p == "/readyz", p == "/v1/shapes", p == "/v1/rootfs":
		return true
	case p == "/swagger.json":
		return true
	case strings.HasPrefix(p, "/v1/internal"), strings.HasPrefix(p, "/v1/admin"):
		return true
	}
	return false
}
