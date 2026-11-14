package audit

const (
	ActionDeviceRegister      Action = "device.register"
	ActionDeviceUnregister    Action = "device.unregister"
	ActionDeviceNetworkAttach Action = "device.network.attach"
	ActionDeviceNetworkDetach Action = "device.network.detach"
	ActionDeviceSessionCreate Action = "device.session.create"
	ActionDeviceSessionDelete Action = "device.session.delete"
)

// DeviceRegister captures a new device registration. Pubkey is logged
// (it's public by construction) so operators can correlate audit
// entries with later WG handshakes. Private key never leaves the
// client. Device names and host details still require normal audit access controls.
type DeviceRegister struct {
	DeviceID string `json:"device_id"`
	Name     string `json:"name"`
	ClientIP string `json:"client_ip"`
	Pubkey   string `json:"pubkey"` // base64
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
}

func (DeviceRegister) isAuditMetadata() {}

type DeviceUnregister struct {
	DeviceID string `json:"device_id"`
	Name     string `json:"name,omitempty"`
}

func (DeviceUnregister) isAuditMetadata() {}

type DeviceNetworkAttach struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name,omitempty"`
	NetworkID  string `json:"network_id"`
}

func (DeviceNetworkAttach) isAuditMetadata() {}

type DeviceNetworkDetach struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name,omitempty"`
	NetworkID  string `json:"network_id"`
}

func (DeviceNetworkDetach) isAuditMetadata() {}

type DeviceSessionCreate struct {
	SessionID   string `json:"session_id"`
	DeviceID    string `json:"device_id"`
	DeviceName  string `json:"device_name,omitempty"`
	RelayHostID string `json:"relay_host_id"`
}

func (DeviceSessionCreate) isAuditMetadata() {}

type DeviceSessionDelete struct {
	SessionID  string `json:"session_id"`
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name,omitempty"`
}

func (DeviceSessionDelete) isAuditMetadata() {}
