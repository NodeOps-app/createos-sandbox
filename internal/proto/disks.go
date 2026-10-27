package proto

import "encoding/json"

// MMDSDisk is the per-attachment shape pushed via Firecracker MMDS at
// boot + on every restore. The agent reads it from the `disks` array
// in the root MMDS document and mounts each entry inside the guest.
//
// Fields are intentionally JSON-tagged with snake_case to match how the
// rest of the MMDS doc is shaped. Credentials are plaintext (control
// decrypted them before forwarding); the agent writes them under
// /run/createos/disks/<id>/passwd-s3fs (tmpfs, mode 0600) and never to a
// persistent path.
type MMDSDisk struct {
	ID          string           `json:"id"`          // disk_<ulid>
	Kind        string           `json:"kind"`        // "s3" today
	Config      MMDSDiskS3Config `json:"config"`      // kind-specific config
	Credentials MMDSDiskS3Creds  `json:"credentials"` // plaintext, kind-specific
	MountPath   string           `json:"mount_path"`  // absolute path in the guest
	// SubPath is an optional sub-folder inside the bucket. Empty = mount
	// the bucket root. When non-empty, the agent passes `bucket:/sub_path`
	// to s3fs so the guest sees only files under that prefix.
	SubPath string `json:"sub_path,omitempty"`
}

// MMDSDiskS3Config mirrors the control handler's disk config. It lives in
// proto so the stdlib-only agent can decode the MMDS wire shape directly.
type MMDSDiskS3Config struct {
	Bucket       string `json:"bucket"`
	Endpoint     string `json:"endpoint"`
	Region       string `json:"region,omitempty"`
	UsePathStyle bool   `json:"use_path_style,omitempty"`
}

// MMDSDiskS3Creds carries the bucket access pair plaintext (decrypted
// by control, in-flight only). Never persisted by the agent.
type MMDSDiskS3Creds struct {
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

// DiskStatusReport is what the agent POSTs back to the host's
// per-sandbox status endpoint after every mount attempt. Host then
// PATCHes sandbox_disks rows via control's internal DB proxy.
type DiskStatusReport struct {
	DiskID string `json:"disk_id"`
	Status string `json:"status"`          // "mounted" | "failed"
	Error  string `json:"error,omitempty"` // truncated to ~1 KiB upstream
}

// FromRawConfig parses a raw JSON config blob into the S3-shaped
// MMDSDiskS3Config. Helper for host-side code that holds the disk
// config as json.RawMessage (control's resolve path) and needs the
// strongly-typed form to put into the MMDS payload.
func DecodeS3Config(raw json.RawMessage, out *MMDSDiskS3Config) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// DecodeS3Creds is the credentials counterpart of DecodeS3Config.
func DecodeS3Creds(raw json.RawMessage, out *MMDSDiskS3Creds) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}
