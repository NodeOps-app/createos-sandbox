package audit

// Admin action names distinguish operator operations. Delivery routing is
// owned by the emitter/shipper, not these metadata definitions.
const (
	ActionAdminHostCordon      Action = "admin.host.cordon"
	ActionAdminHostUncordon    Action = "admin.host.uncordon"
	ActionAdminHostDrain       Action = "admin.host.drain"
	ActionAdminHostCertRevoke  Action = "admin.host.cert.revoke"
	ActionAdminActorCertRevoke Action = "admin.actor.cert.revoke"
)

type AdminHostCordon struct {
	HostID string `json:"host_id"`
	Reason string `json:"reason,omitempty"`
}

func (AdminHostCordon) isAuditMetadata() {}

type AdminHostUncordon struct {
	HostID string `json:"host_id"`
}

func (AdminHostUncordon) isAuditMetadata() {}

type AdminHostDrain struct {
	HostID            string `json:"host_id"`
	SandboxesAffected int    `json:"sandboxes_affected,omitempty"`
}

func (AdminHostDrain) isAuditMetadata() {}

type AdminHostCertRevoke struct {
	HostID string `json:"host_id"`
	Serial string `json:"serial,omitempty"`
	Reason string `json:"reason,omitempty"`
}

func (AdminHostCertRevoke) isAuditMetadata() {}

type AdminActorCertRevoke struct {
	Role    string `json:"role"`
	ActorID string `json:"actor_id"`
	Serial  string `json:"serial,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func (AdminActorCertRevoke) isAuditMetadata() {}
