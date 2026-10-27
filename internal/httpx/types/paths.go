package types

// Control-plane internal API paths. One source of truth so callers (the
// host registration + heartbeat loop, plus any future client) can never
// drift from the routes mounted in internal/apiserver/routes.
const (
	PathHostRegister  = "/v1/internal/hosts/register"
	PathHostHeartbeat = "/v1/internal/hosts/heartbeat"
)
