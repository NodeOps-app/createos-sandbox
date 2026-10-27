package audit

const (
	ActionNetworkCreate Action = "network.create"
	ActionNetworkDelete Action = "network.delete"
	ActionNetworkAttach Action = "network.attach"
	ActionNetworkDetach Action = "network.detach"
)

type NetworkCreate struct {
	NetworkID string `json:"network_id"`
	Name      string `json:"name"`
	VNI       int    `json:"vni"`
	Region    string `json:"region"`
}

func (NetworkCreate) isAuditMetadata() {}

type NetworkDelete struct {
	NetworkID string `json:"network_id"`
	Name      string `json:"name,omitempty"`
}

func (NetworkDelete) isAuditMetadata() {}

type NetworkAttach struct {
	NetworkID string `json:"network_id"`
	SandboxID string `json:"sandbox_id"`
	Alias     string `json:"alias,omitempty"`
}

func (NetworkAttach) isAuditMetadata() {}

type NetworkDetach struct {
	NetworkID string `json:"network_id"`
	SandboxID string `json:"sandbox_id"`
}

func (NetworkDetach) isAuditMetadata() {}
