package jwt

// Claims is the createos internal-RPC JWT payload — minimal: identity +
// audience + freshness. Operation binding (op/sandbox_id/port) was tried
// in an earlier iteration but added wire weight without meaningful
// security benefit over today's bearer model. The route handler enforces
// per-resource authorization (e.g. RequireSandboxOwner reads :id from
// the URL and compares to sandboxes.host_id against the JWT's iss).
//
// Wire keys follow RFC 7519: iss, sub, aud, iat, nbf, exp, jti.
type Claims struct {
	Iss string `json:"iss"`           // "<role>:<id>" — e.g. "host:fc-vm-1"
	Sub string `json:"sub,omitempty"` // optional request target
	Aud string `json:"aud"`           // intended recipient role: host|control|scheduler
	Iat int64  `json:"iat"`           // unix seconds
	Nbf int64  `json:"nbf"`           // unix seconds — typically iat - 5s for clock skew
	Exp int64  `json:"exp"`           // unix seconds — typically iat + 60s
	Jti string `json:"jti"`           // 128-bit random hex; not tracked, present for future use

	UserID string `json:"uid,omitempty"`  // end-user id, set on control→host forwarded user requests
	Role   string `json:"role,omitempty"` // "proxy" on a host-minted proxy token; empty for a host's own token
}

// Recognised audiences and roles. Stringly-typed by design.
const (
	AudHost      = "host"
	AudControl   = "control"
	AudScheduler = "scheduler"

	RoleHost    = "host"
	RoleControl = "control"
	RoleIngress = "ingress"
	RoleGateway = "gateway"
)
