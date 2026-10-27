// Build* helpers project models.* into audit metadata structs.
//
// The audit struct is the security boundary: every field that lands
// here was explicitly chosen to be safe to retain in audit_events and
// ship to the backend. New models fields do NOT leak through
// automatically — adding one here is an opt-in review point.
//
// Helpers take pointers so the handler can pass the same *models.X it
// already holds; nil-safe defaults keep the call site one line.
package audit

import (
	"encoding/base64"

	"github.com/NodeOps-app/sandbox/models"
)

func base64Std(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// sandboxName safely dereferences sb.Name. The sandboxes.name column is
// always set on create (server-mints Docker-style names) but the field
// is *string in the model — guard before deref.
func sandboxName(sb *models.Sandbox) string {
	if sb == nil || sb.Name == nil {
		return ""
	}
	return *sb.Name
}

func BuildSandboxCreate(sb *models.Sandbox) SandboxCreate {
	if sb == nil {
		return SandboxCreate{}
	}
	out := SandboxCreate{
		SandboxID:          sb.ID,
		Shape:              sb.Shape,
		VCPU:               sb.VCPU,
		MemMiB:             sb.MemMib,
		DiskMiB:            sb.DiskMib,
		Region:             sb.Region,
		IngressEnabled:     sb.IngressEnabled,
		EgressAllowlist:    sb.Egress,
		BandwidthQuotaByte: sb.BandwidthQuotaBytes,
		SpawnMS:            sb.SpawnMs,
	}
	if sb.Name != nil {
		out.Name = *sb.Name
	}
	if sb.Rootfs != nil {
		out.Rootfs = *sb.Rootfs
	}
	if sb.HostID != nil {
		out.HostID = *sb.HostID
	}
	for _, k := range sb.SSHPubkeys {
		if fp := FingerprintSSH(k); fp != "" {
			out.SSHPubkeyFprints = append(out.SSHPubkeyFprints, fp)
		}
	}
	return out
}

func BuildSandboxDestroy(sb *models.Sandbox, cause string, status models.Status) SandboxDestroy {
	if sb == nil {
		return SandboxDestroy{Cause: cause, Status: string(status)}
	}
	return SandboxDestroy{
		SandboxID: sb.ID,
		Name:      sandboxName(sb),
		Cause:     cause,
		Status:    string(status),
	}
}

func BuildSandboxPause(sb *models.Sandbox) SandboxPause {
	if sb == nil {
		return SandboxPause{}
	}
	return SandboxPause{SandboxID: sb.ID, Name: sandboxName(sb)}
}

func BuildSandboxResume(sb *models.Sandbox) SandboxResume {
	if sb == nil {
		return SandboxResume{}
	}
	out := SandboxResume{SandboxID: sb.ID, Name: sandboxName(sb), Region: sb.Region}
	if sb.HostID != nil {
		out.HostID = *sb.HostID
	}
	return out
}

func BuildSandboxFork(newSb *models.Sandbox, sourceID string, startPaused bool) SandboxFork {
	out := SandboxFork{SourceSandboxID: sourceID, StartPaused: startPaused}
	if newSb != nil {
		out.SandboxID = newSb.ID
		out.Name = sandboxName(newSb)
	}
	return out
}

func BuildSandboxPatch(sb *models.Sandbox, ingressEnabled *bool) SandboxPatch {
	out := SandboxPatch{IngressEnabled: ingressEnabled}
	if sb != nil {
		out.SandboxID = sb.ID
		out.Name = sandboxName(sb)
	}
	return out
}

func BuildSandboxResize(sb *models.Sandbox, oldDiskMiB int64) SandboxResize {
	if sb == nil {
		return SandboxResize{OldDiskMiB: oldDiskMiB}
	}
	return SandboxResize{
		SandboxID:  sb.ID,
		Name:       sandboxName(sb),
		OldDiskMiB: oldDiskMiB,
		NewDiskMiB: sb.DiskMib,
	}
}

func BuildSandboxEgressSet(sb *models.Sandbox, oldRules, newRules []string) SandboxEgressSet {
	out := SandboxEgressSet{OldRules: oldRules, NewRules: newRules}
	if sb != nil {
		out.SandboxID = sb.ID
		out.Name = sandboxName(sb)
	}
	return out
}

func BuildSandboxSSHPubkeyUpdate(sb *models.Sandbox, pubkey string) SandboxSSHPubkeyUpdate {
	out := SandboxSSHPubkeyUpdate{
		Fingerprint: FingerprintSSH(pubkey),
		KeyType:     SSHKeyType(pubkey),
		Comment:     SSHKeyComment(pubkey),
	}
	if sb != nil {
		out.SandboxID = sb.ID
		out.Name = sandboxName(sb)
	}
	return out
}

func BuildSandboxBandwidthUpdate(sb *models.Sandbox, addBytes int64) SandboxBandwidthUpdate {
	out := SandboxBandwidthUpdate{AddBytes: addBytes}
	if sb != nil {
		out.SandboxID = sb.ID
		out.Name = sandboxName(sb)
		out.NewQuota = sb.BandwidthQuotaBytes
	}
	return out
}

func BuildNetworkCreate(n *models.Network) NetworkCreate {
	if n == nil {
		return NetworkCreate{}
	}
	return NetworkCreate{
		NetworkID: n.ID,
		Name:      n.Name,
		VNI:       n.VNI,
	}
}

func BuildNetworkDelete(n *models.Network) NetworkDelete {
	if n == nil {
		return NetworkDelete{}
	}
	return NetworkDelete{NetworkID: n.ID, Name: n.Name}
}

func BuildNetworkAttach(n *models.Network, sandboxID, alias string) NetworkAttach {
	out := NetworkAttach{SandboxID: sandboxID, Alias: alias}
	if n != nil {
		out.NetworkID = n.ID
	}
	return out
}

func BuildNetworkDetach(n *models.Network, sandboxID string) NetworkDetach {
	out := NetworkDetach{SandboxID: sandboxID}
	if n != nil {
		out.NetworkID = n.ID
	}
	return out
}

// BuildDiskCreate takes the disk + the user-supplied S3 connection
// values. Bucket/endpoint/region/path_style are NOT pulled from
// d.Config here because that JSON blob is opaque at this layer;
// handlers extract typed values from the request and pass them in.
func BuildDiskCreate(d *models.Disk, bucket, endpoint, region string, pathStyle bool) DiskCreate {
	out := DiskCreate{
		Bucket:    bucket,
		Endpoint:  endpoint,
		Region:    region,
		PathStyle: pathStyle,
	}
	if d != nil {
		out.DiskID = d.ID
		out.Name = d.Name
	}
	return out
}

func BuildDiskDelete(d *models.Disk) DiskDelete {
	if d == nil {
		return DiskDelete{}
	}
	return DiskDelete{DiskID: d.ID, Name: d.Name}
}

func BuildDiskAttach(d *models.Disk, sandboxID, mountPath, subPath string) DiskAttach {
	out := DiskAttach{
		SandboxID: sandboxID,
		MountPath: mountPath,
		SubPath:   subPath,
	}
	if d != nil {
		out.DiskID = d.ID
	}
	return out
}

func BuildDiskDetach(d *models.Disk, sandboxID, mountPath string) DiskDetach {
	out := DiskDetach{SandboxID: sandboxID, MountPath: mountPath}
	if d != nil {
		out.DiskID = d.ID
	}
	return out
}

// Template Dockerfile is intentionally summarised as a byte length, not
// shipped — the body can carry secret ARGs and reference auth tokens.
func BuildTemplateSubmit(t *models.Template) TemplateSubmit {
	if t == nil {
		return TemplateSubmit{}
	}
	return TemplateSubmit{
		TemplateID:      t.ID,
		Name:            t.Name,
		BaseImage:       t.Base,
		DockerfileBytes: int64(len(t.Dockerfile)),
	}
}

func BuildTemplateDelete(t *models.Template) TemplateDelete {
	if t == nil {
		return TemplateDelete{}
	}
	return TemplateDelete{TemplateID: t.ID, Name: t.Name}
}

func BuildTemplateBuildStart(t *models.Template, builderID string) TemplateBuildStart {
	if t == nil {
		return TemplateBuildStart{BuilderID: builderID}
	}
	return TemplateBuildStart{
		TemplateID: t.ID,
		Name:       t.Name,
		Attempt:    t.Attempts,
		BuilderID:  builderID,
	}
}

func BuildTemplateBuildComplete(t *models.Template, status string, durationS float64, errMsg string) TemplateBuildComplete {
	out := TemplateBuildComplete{
		Status:     status,
		DurationS:  durationS,
		ErrorClass: TruncateError(errMsg),
	}
	if t != nil {
		out.TemplateID = t.ID
		out.Name = t.Name
		out.Attempt = t.Attempts
	}
	return out
}

// ── device VPN ────────────────────────────────────────────────────────

func BuildDeviceRegister(d *models.Device) DeviceRegister {
	if d == nil {
		return DeviceRegister{}
	}
	out := DeviceRegister{
		DeviceID: d.ID,
		Name:     d.Name,
		ClientIP: d.ClientIP,
		Pubkey:   base64Std(d.Pubkey),
	}
	if d.Hostname != nil {
		out.Hostname = *d.Hostname
	}
	if d.OS != nil {
		out.OS = *d.OS
	}
	return out
}

func BuildDeviceUnregister(d *models.Device) DeviceUnregister {
	if d == nil {
		return DeviceUnregister{}
	}
	return DeviceUnregister{DeviceID: d.ID, Name: d.Name}
}

func BuildDeviceNetworkAttach(d *models.Device, networkID string) DeviceNetworkAttach {
	out := DeviceNetworkAttach{NetworkID: networkID}
	if d != nil {
		out.DeviceID = d.ID
		out.DeviceName = d.Name
	}
	return out
}

func BuildDeviceNetworkDetach(d *models.Device, networkID string) DeviceNetworkDetach {
	out := DeviceNetworkDetach{NetworkID: networkID}
	if d != nil {
		out.DeviceID = d.ID
		out.DeviceName = d.Name
	}
	return out
}

func BuildDeviceSessionCreate(s *models.DeviceSession, d *models.Device) DeviceSessionCreate {
	out := DeviceSessionCreate{}
	if s != nil {
		out.SessionID = s.ID
		out.DeviceID = s.DeviceID
		out.RelayHostID = s.RelayHostID
	}
	if d != nil {
		out.DeviceName = d.Name
	}
	return out
}

func BuildDeviceSessionDelete(sessionID string, d *models.Device) DeviceSessionDelete {
	out := DeviceSessionDelete{SessionID: sessionID}
	if d != nil {
		out.DeviceID = d.ID
		out.DeviceName = d.Name
	}
	return out
}
