// Package ca implements the small in-process certificate authority that
// issues short-lived leaf certs to createos actors (control, ingress,
// gateway, proxy, scheduler) and hosts. Every leaf carries a SPIFFE
// URI SAN identifying its bearer; the verifier uses that URI as the
// sole authoritative identity claim — CommonName is informational only.
package ca

import (
	"fmt"
	"strings"
)

// Canonical role names used inside SPIFFE URIs and middleware role
// gates. Always reference these constants rather than string literals
// so role renames are a single grep+replace.
const (
	RoleControl   = "control"
	RoleHost      = "host"
	RoleIngress   = "ingress"
	RoleGateway   = "gateway"
	RoleProxy     = "proxy"
	RoleScheduler = "scheduler"
	RoleBuilder   = "builder"
	RoleBilling   = "billing"
)

// URIIdentity describes the bearer of a leaf cert. Exactly one of Role
// or HostID is meaningful per identity:
//
//   - non-host actors (control, ingress, gateway, proxy, scheduler):
//     Role is set, HostID empty → spiffe://createos/role/<role>
//   - hosts:
//     HostID is set, Role empty → spiffe://createos/host/<host-id>
type URIIdentity struct {
	Role   string
	HostID string
}

// FormatSpiffeURI renders the SPIFFE URI for an identity. Hosts win
// when both fields are set (so callers can't accidentally issue a
// role-shaped URI for a host).
func FormatSpiffeURI(id URIIdentity) string {
	if id.HostID != "" {
		return fmt.Sprintf("spiffe://createos/host/%s", id.HostID)
	}
	return fmt.Sprintf("spiffe://createos/role/%s", id.Role)
}

// ParseSpiffeURI splits a SPIFFE URI back into a URIIdentity. Returns
// false when the URI doesn't match the createos trust domain or the
// expected /role/<x> or /host/<x> shape.
func ParseSpiffeURI(uri string) (URIIdentity, bool) {
	const prefix = "spiffe://createos/"
	if !strings.HasPrefix(uri, prefix) {
		return URIIdentity{}, false
	}
	rest := uri[len(prefix):]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 || slash == len(rest)-1 {
		return URIIdentity{}, false
	}
	kind, value := rest[:slash], rest[slash+1:]
	if value == "" || strings.ContainsRune(value, '/') {
		return URIIdentity{}, false
	}
	switch kind {
	case "role":
		return URIIdentity{Role: value}, true
	case "host":
		return URIIdentity{HostID: value}, true
	default:
		return URIIdentity{}, false
	}
}
