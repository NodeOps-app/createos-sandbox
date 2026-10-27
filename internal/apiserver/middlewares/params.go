package middlewares

// Route parameter names — the `:name` tokens in route paths. Handlers and
// middleware read them via c.Params(...); declaring them here keeps the
// route definitions and every reader in agreement (a renamed token only
// changes one place).
const (
	ParamSandboxID = "id"
	ParamIP        = "ip"
	ParamHost      = "host"
	ParamPort      = "port"
	ParamNetwork   = "net"
	ParamTemplate  = "tpl"
	ParamAPIKey    = "key"
	ParamDiskID    = "disk"
	ParamDeviceID  = "id"
	ParamNetworkID = "nid"
	ParamSessionID = "sid"
	ParamProcessID = "process"
)

// Shared query-string keys for paginated list endpoints. Same rationale
// as the route params above — one place to rename if we ever want to
// match a stricter API convention.
const (
	QueryLimit  = "limit"
	QueryOffset = "offset"
	// QueryHostID is the host_id selector used by internal endpoints
	// that fan reconcile state per-host (host-state for compute hosts,
	// relay-state for relays). Caller is verified against the SPIFFE
	// URI on the leaf cert inside the handler — same source of truth
	// for both endpoints.
	QueryHostID = "host_id"
)
