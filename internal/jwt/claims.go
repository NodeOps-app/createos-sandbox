package jwt

// Claims is the internal JWT payload: issuer, audience, validity timestamps,
// and optional subject, user, and role fields. Signature verification alone
// does not authorize a resource operation; callers enforce route permissions.
// Wire keys use RFC 7519 names plus the uid and role extensions.
type Claims struct {
	Iss string `json:"iss"`           // "<role>:<id>" — e.g. "host:fc-vm-1"
	Sub string `json:"sub,omitempty"` // optional request target
	Aud string `json:"aud"`           // intended recipient role: host|control|scheduler
	Iat int64  `json:"iat"`           // unix seconds
	Nbf int64  `json:"nbf"`           // unix seconds — typically iat - 5s for clock skew
	Exp int64  `json:"exp"`           // unix seconds — typically iat + 60s
	Jti string `json:"jti"`           // 128-bit random hex; not tracked, present for future use

	UserID string `json:"uid,omitempty"`  // optional end-user identity carried by SignFor
	Role   string `json:"role,omitempty"` // "proxy" when minted by SignProxy
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
