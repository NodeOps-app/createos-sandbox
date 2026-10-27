package audit

const (
	ActionSandboxCreate          Action = "sandbox.create"
	ActionSandboxDestroy         Action = "sandbox.destroy"
	ActionSandboxPause           Action = "sandbox.pause"
	ActionSandboxResume          Action = "sandbox.resume"
	ActionSandboxFork            Action = "sandbox.fork"
	ActionSandboxPatch           Action = "sandbox.patch"
	ActionSandboxResize          Action = "sandbox.resize"
	ActionSandboxEgressSet       Action = "sandbox.egress.set"
	ActionSandboxSSHPubkeyUpdate Action = "sandbox.ssh_pubkey.update"
	ActionSandboxBandwidthUpdate Action = "sandbox.bandwidth.update"
)

// Intentionally NOT audited: sandbox.exec, sandbox.file.*,
// sandbox.tunnel.open, sandbox.shell.open. Attach/detach live on the
// owned resource only — see disk.attach/disk.detach and
// network.attach/network.detach.

type SandboxCreate struct {
	SandboxID          string   `json:"sandbox_id"`
	Name               string   `json:"name"`
	Shape              string   `json:"shape"`
	Rootfs             string   `json:"rootfs,omitempty"`
	VCPU               int      `json:"vcpu"`
	MemMiB             int      `json:"mem_mib"`
	DiskMiB            int64    `json:"disk_mib"`
	HostID             string   `json:"host_id"`
	Region             string   `json:"region"`
	IngressEnabled     bool     `json:"ingress_enabled"`
	EgressAllowlist    []string `json:"egress_allowlist,omitempty"`
	SSHPubkeyFprints   []string `json:"ssh_pubkey_fingerprints,omitempty"`
	BandwidthQuotaByte int64    `json:"bandwidth_quota_bytes,omitempty"`
	SpawnMS            float64  `json:"spawn_ms,omitempty"`
	// NEVER include: env-var values, full ssh pubkey bytes, secret_token.
}

func (SandboxCreate) isAuditMetadata() {}

type SandboxDestroy struct {
	SandboxID string `json:"sandbox_id"`
	Name      string `json:"name,omitempty"`
	// "user" (DELETE), "ttl", "quota", "host_dead". Empty = user.
	Cause  string `json:"cause,omitempty"`
	Status string `json:"status"`
}

func (SandboxDestroy) isAuditMetadata() {}

type SandboxPause struct {
	SandboxID string `json:"sandbox_id"`
	Name      string `json:"name,omitempty"`
}

func (SandboxPause) isAuditMetadata() {}

// Resume may land on a different host than pause.
type SandboxResume struct {
	SandboxID string `json:"sandbox_id"`
	Name      string `json:"name,omitempty"`
	HostID    string `json:"host_id"`
	Region    string `json:"region"`
}

func (SandboxResume) isAuditMetadata() {}

type SandboxFork struct {
	SandboxID       string `json:"sandbox_id"`
	Name            string `json:"name,omitempty"`
	SourceSandboxID string `json:"source_sandbox_id"`
	StartPaused     bool   `json:"start_paused"`
}

func (SandboxFork) isAuditMetadata() {}

type SandboxPatch struct {
	SandboxID      string `json:"sandbox_id"`
	Name           string `json:"name,omitempty"`
	IngressEnabled *bool  `json:"ingress_enabled,omitempty"`
}

func (SandboxPatch) isAuditMetadata() {}

type SandboxResize struct {
	SandboxID  string `json:"sandbox_id"`
	Name       string `json:"name,omitempty"`
	OldDiskMiB int64  `json:"old_disk_mib"`
	NewDiskMiB int64  `json:"new_disk_mib"`
}

func (SandboxResize) isAuditMetadata() {}

type SandboxEgressSet struct {
	SandboxID string   `json:"sandbox_id"`
	Name      string   `json:"name,omitempty"`
	OldRules  []string `json:"old_rules,omitempty"`
	NewRules  []string `json:"new_rules"`
}

func (SandboxEgressSet) isAuditMetadata() {}

// Fingerprint, not raw key bytes — pubkeys are public but storing
// raw bytes makes the payload large and noisy.
type SandboxSSHPubkeyUpdate struct {
	SandboxID   string `json:"sandbox_id"`
	Name        string `json:"name,omitempty"`
	Fingerprint string `json:"fingerprint"` // SHA256:base64
	KeyType     string `json:"key_type"`
	Comment     string `json:"comment,omitempty"`
}

func (SandboxSSHPubkeyUpdate) isAuditMetadata() {}

type SandboxBandwidthUpdate struct {
	SandboxID   string `json:"sandbox_id"`
	Name        string `json:"name,omitempty"`
	AddBytes    int64  `json:"add_bytes"`
	NewQuota    int64  `json:"new_quota_bytes"`
	CreditAfter int64  `json:"credit_after_micros,omitempty"`
}

func (SandboxBandwidthUpdate) isAuditMetadata() {}
