// Package middlewares holds the scheduler service's HTTP middleware —
// one fiber gate per file, each a method on Middleware with its logic
// declared inline. internal/auth is referenced only for shared types
// and locals-key constants; the gate logic itself lives here.
package middlewares

import (
	"strings"

	authjwt "github.com/NodeOps-app/sandbox/internal/jwt"
)

const (
	HeaderAuthorization = "Authorization"
	BearerPrefix        = "Bearer "
)

// IssLocalsKey / ClaimsLocalsKey are the c.Locals keys under which
// MustBeControl stamps the verified JWT's iss and full claims.
const (
	IssLocalsKey    = "internal_iss"
	ClaimsLocalsKey = "internal_jwt_claims"
)

// Middleware carries the scheduler's auth dependencies. Construct it once
// in server wiring with NewMiddleware, then mount its MustBe* gates.
type Middleware struct {
	JWTVerifier *authjwt.Verifier
}

// NewMiddleware wires the scheduler's middleware dependencies.
func NewMiddleware(verifier *authjwt.Verifier) *Middleware {
	return &Middleware{JWTVerifier: verifier}
}

// bearerToken extracts the token from an "Authorization: Bearer <token>"
// header. Returns ("", false) when the header is absent or malformed.
func bearerToken(header string) (string, bool) {
	if len(header) < len(BearerPrefix) ||
		!strings.EqualFold(header[:len(BearerPrefix)], BearerPrefix) {
		return "", false
	}
	tok := strings.TrimSpace(header[len(BearerPrefix):])
	return tok, tok != ""
}
