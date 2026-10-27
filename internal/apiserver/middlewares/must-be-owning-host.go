package middlewares

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/gofiber/fiber/v2"

	"github.com/NodeOps-app/sandbox/internal/ca"
	"github.com/NodeOps-app/sandbox/internal/httpx"
	"github.com/NodeOps-app/sandbox/internal/httpx/types"
	authjwt "github.com/NodeOps-app/sandbox/internal/jwt"
)

// hostScopedRole reports whether the caller's role must be scoped to
// its own sandboxes when reading the DB-proxy. Only the `host` role
// carries a host id in its SPIFFE URI; gateway/ingress/control are
// cluster-wide routers that legitimately need to read any sandbox.
// host-proxy reuses the host's cert (role=host with host_id), so it's
// covered by this same check.
func hostScopedRole(role string) bool {
	return role == ca.RoleHost
}

// resolveCallerHost extracts the caller's host id from the request
// identity. Tries the mTLS SPIFFE URI first (set by MustBePeerRoleMTLS),
// then falls back to the JWT `iss` claim (set by MustBeIssuedBy).
// The boolean is false after this helper has written a rejection response.
// Callers must return without invoking the next handler in that case.
func resolveCallerHost(c *fiber.Ctx) (host string, ok bool) {
	if iden, _ := c.Locals(MTLSIdentityLocalsKey).(string); iden != "" {
		// SPIFFE URI form: spiffe://createos/host/<host-id>
		if i := strings.Index(iden, "/host/"); i >= 0 {
			return iden[i+len("/host/"):], true
		}
	}
	cl, _ := c.Locals(ClaimsLocalsKey).(*authjwt.Claims)
	if cl == nil || cl.Iss == "" {
		_ = httpx.Fail(c, fiber.StatusUnauthorized,
			types.AuthError{Auth: "no caller identity"})
		return "", false
	}
	if !strings.HasPrefix(cl.Iss, "host:") {
		_ = httpx.Fail(c, fiber.StatusForbidden,
			types.AuthError{Auth: "only hosts may mutate sandbox rows"})
		return "", false
	}
	if cl.Role == "proxy" {
		_ = httpx.Fail(c, fiber.StatusForbidden,
			types.AuthError{Auth: "proxy tokens may not mutate sandbox rows"})
		return "", false
	}
	return strings.TrimPrefix(cl.Iss, "host:"), true
}

// gateOwningHost verifies the caller is the host that owns sandboxID.
// Returns true on success. On failure it writes the response and returns false;
// missing and currently-unassigned rows both fail closed.
func (m *Middleware) gateOwningHost(c *fiber.Ctx, sandboxID, callerHost string) bool {
	if m.SandboxOwnerLookup == nil {
		// Should only ever be nil in tests; never run production
		// without a lookup wired in.
		log.WithContext(c.UserContext()).Error("[owner-lookup] not wired — failing closed")
		_ = httpx.Error(c, fiber.StatusInternalServerError, "internal error")
		return false
	}
	ownerHost, found, err := m.SandboxOwnerLookup(c.UserContext(), sandboxID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[owner-lookup] internal error: %v", err)
		_ = httpx.Error(c, fiber.StatusInternalServerError, "internal error")
		return false
	}
	if !found {
		_ = httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		return false
	}
	if ownerHost == "" {
		_ = httpx.Fail(c, fiber.StatusForbidden,
			types.AuthError{Auth: "sandbox has no assigned host"})
		return false
	}
	if ownerHost != callerHost {
		_ = httpx.Fail(c, fiber.StatusForbidden,
			types.AuthError{Auth: "sandbox not owned by caller"})
		return false
	}
	return true
}

// MustBeOwningHost authorises a write to /v1/internal/db/sandboxes/:id/*
// only when the caller is the host that owns that sandbox. Mounted AFTER
// MustBeIssuedBy / MustBePeerRoleMTLS so the caller identity is populated.
//
// A host-minted proxy token also has iss="host:<id>" (the host signs it
// with its own key) but carries Role="proxy" — it is rejected here, since
// a proxy never mutates sandbox rows.
//
// Returns 403 on non-host caller, proxy token, unassigned row, or host
// mismatch; returns 404 when the sandbox row is missing.
func (m *Middleware) MustBeOwningHost() fiber.Handler {
	return func(c *fiber.Ctx) error {
		sandboxID := c.Params(ParamSandboxID)
		if sandboxID == "" {
			return c.Next() // route doesn't have an :id — let the handler decide
		}
		callerHost, ok := resolveCallerHost(c)
		if !ok {
			return nil
		}
		if !m.gateOwningHost(c, sandboxID, callerHost) {
			return nil
		}
		return c.Next()
	}
}

// MustBeOwningHostFromBody is the body-shaped analogue of
// MustBeOwningHost — for internal DB-proxy routes that carry the
// sandbox id inside the JSON body rather than the URL path
// (mark-pausing, mark-paused, mark-bundle-uploaded, mark-rolled-back,
// mark-destroying, mark-fork-paused). `field` is the JSON key
// (typically "id"). Without this gate any peer-host mTLS cert can
// transition any other host's sandbox row through the pause/destroy
// state machine, corrupting that tenant's VM lifecycle.
//
// Fiber buffers the request body, so re-parsing in the handler
// afterwards is a no-op — same bytes, same outcome.
func (m *Middleware) MustBeOwningHostFromBody(field string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		callerHost, ok := resolveCallerHost(c)
		if !ok {
			return nil
		}
		sandboxID, err := extractBodyStringField(c.Body(), field)
		if err != nil {
			return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
		}
		if sandboxID == "" {
			return httpx.Fail(c, fiber.StatusBadRequest,
				types.AuthError{Auth: "missing sandbox id in body"})
		}
		if !m.gateOwningHost(c, sandboxID, callerHost) {
			return nil
		}
		return c.Next()
	}
}

// MustBeSelfHostFromBody fails the request unless the caller's host id
// equals the host id stored in the JSON body under `field`. Use this on
// internal routes where the body carries a host identifier the caller is
// claiming to act AS (e.g. mark-resumed `host`, mark-resume-failed
// `host`, clear-local-cache `host`). Without this gate, host-A can
// falsely claim mark-resumed on host-B's behalf, or clear host-B's
// locality cache row.
func (m *Middleware) MustBeSelfHostFromBody(field string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		callerHost, ok := resolveCallerHost(c)
		if !ok {
			return nil
		}
		claimedHost, err := extractBodyStringField(c.Body(), field)
		if err != nil {
			return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
		}
		if claimedHost == "" {
			return httpx.Fail(c, fiber.StatusBadRequest,
				types.AuthError{Auth: "missing host in body"})
		}
		if claimedHost != callerHost {
			return httpx.Fail(c, fiber.StatusForbidden,
				types.AuthError{Auth: "may not act as a different host"})
		}
		return c.Next()
	}
}

// MustBeSelfHostFromParam fails the request unless the caller's host id
// equals the URL param `param`. Use this on routes where the path :id is
// a HOST id (heartbeat, host detail mutate). Without this gate, host-A
// can heartbeat host-B's row, suppressing the stale-host eviction that
// the scheduler relies on to drop a dead peer from placement.
func (m *Middleware) MustBeSelfHostFromParam(param string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		callerHost, ok := resolveCallerHost(c)
		if !ok {
			return nil
		}
		claimedHost := c.Params(param)
		if claimedHost == "" {
			return httpx.Fail(c, fiber.StatusBadRequest,
				types.AuthError{Auth: "missing host in path"})
		}
		if claimedHost != callerHost {
			return httpx.Fail(c, fiber.StatusForbidden,
				types.AuthError{Auth: "may not act as a different host"})
		}
		return c.Next()
	}
}

// MustBeSelfHostFromQuery fails the request unless the caller's host id
// equals the host id in query parameter `param`. Use this for host polling
// endpoints whose response and cache key are scoped by a caller-supplied host
// id. Without the binding, one host certificate could read another host's
// state or manufacture unbounded cache keys.
func (m *Middleware) MustBeSelfHostFromQuery(param string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		callerHost, ok := resolveCallerHost(c)
		if !ok {
			return nil
		}
		claimedHost := c.Query(param, "")
		if claimedHost == "" {
			return httpx.Fail(c, fiber.StatusBadRequest,
				types.AuthError{Auth: "missing host in query"})
		}
		if claimedHost != callerHost {
			return httpx.Fail(c, fiber.StatusForbidden,
				types.AuthError{Auth: "may not query a different host"})
		}
		return c.Next()
	}
}

// extractBodyStringField pulls a single, exact-case top-level string field out
// of a JSON object. It rejects duplicates and case variants of that field so
// this authorization check cannot see a different value from encoding/json's
// later case-insensitive struct decode in the handler.
func extractBodyStringField(body []byte, field string) (string, error) {
	if len(body) == 0 {
		return "", nil
	}
	if !json.Valid(body) {
		return "", fmt.Errorf("invalid JSON")
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	start, err := dec.Token()
	if err != nil {
		return "", err
	}
	if delim, ok := start.(json.Delim); !ok || delim != '{' {
		return "", fmt.Errorf("JSON body must be an object")
	}

	var value string
	found := false
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return "", err
		}
		key, ok := token.(string)
		if !ok {
			return "", fmt.Errorf("invalid JSON object key")
		}

		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return "", err
		}
		if !strings.EqualFold(key, field) {
			continue
		}
		if key != field {
			return "", fmt.Errorf("JSON field %q must use exact casing %q", key, field)
		}
		if found {
			return "", fmt.Errorf("duplicate JSON field %q", field)
		}
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", err
		}
		found = true
	}
	if _, err := dec.Token(); err != nil {
		return "", err
	}
	if err := ensureJSONEOF(dec); err != nil {
		return "", err
	}
	return value, nil
}

func ensureJSONEOF(dec *json.Decoder) error {
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

// MustOwnSandboxIfHostRole gates a DB-proxy READ on the sandbox at
// :sandbox_id belonging to the caller — but only when the caller's role
// is `host`. gateway, ingress, and control are pass-through because
// they're cluster-wide routers/services that legitimately need to look
// up any sandbox to do their job. host-proxy uses the host's cert
// (role=host) so it's covered by this gate too.
//
// Without this, any host with a valid mTLS leaf could read any other
// host's sandbox rows via GET /v1/internal/db/sandboxes/:id — fleet-wide
// metadata enumeration. With it, a host can only read its own.
func (m *Middleware) MustOwnSandboxIfHostRole() fiber.Handler {
	return func(c *fiber.Ctx) error {
		role, _ := c.Locals(MTLSRoleLocalsKey).(string)
		if !hostScopedRole(role) {
			return c.Next()
		}
		sandboxID := c.Params(ParamSandboxID)
		if sandboxID == "" {
			return c.Next()
		}
		callerHost, ok := resolveCallerHost(c)
		if !ok {
			return nil
		}
		if !m.gateOwningHost(c, sandboxID, callerHost) {
			return nil
		}
		return c.Next()
	}
}

// MustOwnHostQueryIfHostRole gates a listing read on the `?host=` query
// param matching the caller's SPIFFE host id — only when the caller's
// role is `host`. Forces `host` callers to scope listings to their own
// host; cluster-wide routers (gateway/ingress/control) pass through
// unchanged.
//
// Used on /v1/internal/db/sandboxes(?host=X), /sandboxes/running-ids,
// /sandboxes/live-ids — endpoints whose default (no host param) returns
// the entire fleet's sandboxes. Without this gate any host could call
// `?host=victim-host-id` (or omit the param) and read every sandbox.
//
// `param` is the query string key to inspect (typically "host").
func (m *Middleware) MustOwnHostQueryIfHostRole(param string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		role, _ := c.Locals(MTLSRoleLocalsKey).(string)
		if !hostScopedRole(role) {
			return c.Next()
		}
		callerHost, ok := resolveCallerHost(c)
		if !ok {
			return nil
		}
		// Empty param means "the whole fleet" — for a host role this
		// is a leak. Force it to equal the caller's host id.
		want := c.Query(param, "")
		if want == "" {
			return httpx.Fail(c, fiber.StatusBadRequest,
				types.AuthError{Auth: "host query param required for host-role callers"})
		}
		if want != callerHost {
			return httpx.Fail(c, fiber.StatusForbidden,
				types.AuthError{Auth: "may not query a different host's listing"})
		}
		return c.Next()
	}
}

// CallerHostIfHostRole returns the caller's SPIFFE host id if the role
// is `host`, else "". For handlers that need to apply per-host scoping
// at the handler layer (e.g. by-ip lookup, where the host id can only
// be determined AFTER the DB read returns the row).
func CallerHostIfHostRole(c *fiber.Ctx) string {
	role, _ := c.Locals(MTLSRoleLocalsKey).(string)
	if !hostScopedRole(role) {
		return ""
	}
	iden, _ := c.Locals(MTLSIdentityLocalsKey).(string)
	if iden == "" {
		return ""
	}
	if i := strings.Index(iden, "/host/"); i >= 0 {
		return iden[i+len("/host/"):]
	}
	return ""
}
