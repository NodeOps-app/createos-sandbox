package proto

import "encoding/json"

// MMDSDisk is the per-attachment shape pushed via Firecracker MMDS at
// boot + on every restore. The agent reads it from the `disks` array
// in the root MMDS document and mounts each entry inside the guest.
//
// Fields are intentionally JSON-tagged with snake_case to match how the
// rest of the MMDS doc is shaped. Credentials are plaintext (control
// decrypted them before forwarding); the agent writes them under
// /run/createos/disks/<id>--<mount-path-hash>/passwd-s3fs (mode 0600).
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

// MMDSDiskS3Creds carries the bucket access pair in plaintext after control
// decryption. The agent writes an s3fs credential file in its runtime directory.
type MMDSDiskS3Creds struct {
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

// DiskStatusReport describes an individual disk mount result. The current
// status path polls the guest's disk-status endpoint; this type does not imply
// that the agent initiates a callback to the host.
type DiskStatusReport struct {
	DiskID string `json:"disk_id"`
	Status string `json:"status"`          // "mounted" | "failed"
	Error  string `json:"error,omitempty"` // truncated to ~1 KiB upstream
}

// DecodeS3Config parses a raw JSON config blob into the S3-shaped
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
