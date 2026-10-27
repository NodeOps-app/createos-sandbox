package audit

const (
	ActionDiskCreate Action = "disk.create"
	ActionDiskDelete Action = "disk.delete"
	ActionDiskAttach Action = "disk.attach"
	ActionDiskDetach Action = "disk.detach"
)

type DiskCreate struct {
	DiskID    string `json:"disk_id"`
	Name      string `json:"name"`
	Bucket    string `json:"bucket"`
	Endpoint  string `json:"endpoint"`
	Region    string `json:"region,omitempty"`
	PathStyle bool   `json:"path_style,omitempty"`
	// NEVER include: access_key_id, secret_access_key, encrypted credential blob.
}

func (DiskCreate) isAuditMetadata() {}

type DiskDelete struct {
	DiskID string `json:"disk_id"`
	Name   string `json:"name,omitempty"`
}

func (DiskDelete) isAuditMetadata() {}

type DiskAttach struct {
	DiskID    string `json:"disk_id"`
	SandboxID string `json:"sandbox_id"`
	MountPath string `json:"mount_path"`
	SubPath   string `json:"sub_path,omitempty"`
}

func (DiskAttach) isAuditMetadata() {}

type DiskDetach struct {
	DiskID    string `json:"disk_id"`
	SandboxID string `json:"sandbox_id"`
	MountPath string `json:"mount_path,omitempty"`
}

func (DiskDetach) isAuditMetadata() {}
