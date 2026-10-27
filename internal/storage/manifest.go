package storage

import (
	"encoding/json"
	"fmt"
)

// ManifestVersion is bumped when the on-wire/on-disk shape of
// Manifest changes. Resume code branches on it; the row's
// snapshot_manifest is the canonical source of truth.
const ManifestVersion = 1

// ManifestArtifactNames are the well-known keys inside Manifest.Artifacts.
// They double as the relative paths under <sandbox_id>/ in storage.
const (
	ArtifactMemfile = "memfile.zst"
	ArtifactVMState = "vmstate"
	ArtifactOverlay = "overlay.ext4.zst"

	// Bucket-side filename for the canonical manifest object. The
	// row's snapshot_manifest column holds the same JSON.
	ArtifactManifest = "manifest.json"
)

// BundlePrefix returns the canonical bucket prefix for a sandbox's
// snapshot bundle: "snapshots/<id>/". Use this everywhere we read,
// write, copy, or delete bundle objects so the layout stays in one
// place.
func BundlePrefix(id string) string {
	return "snapshots/" + id + "/"
}

// Manifest is a pure integrity descriptor. No fields that duplicate
// the sandbox row (sandbox_id, shape, rootfs, region, paused_at all
// live on the row), with one exception: OriginalOverlayPath. Firecracker
// bakes the overlay drive's host path into vmstate at CreateSnapshot
// time. On resume the host needs to know that path to ensure the
// decompressed overlay lives where firecracker expects to find it
// (typically via a symlink). It's not row metadata; it's per-bundle
// runtime detail that travels with the bytes.
type Manifest struct {
	Version             int                           `json:"version"`
	Encryption          EncryptionMeta                `json:"encryption"`
	Artifacts           map[string]ArtifactDescriptor `json:"artifacts"`
	OriginalOverlayPath string                        `json:"original_overlay_path,omitempty"`
	// OriginalRootfsPath is the read-only rootfs drive path baked into
	// vmstate at pause time (resolved from the source host's rootfs
	// catalog, possibly relative to that host's cwd). On resume on a
	// different host the orchestrator must surface a file at this exact
	// path — usually a symlink to the resuming host's catalog entry —
	// or firecracker's snapshot-load fails opening the backing file.
	OriginalRootfsPath string `json:"original_rootfs_path,omitempty"`
}

// EncryptionMeta is reserved for v1.1 (AES-GCM with envelope-wrapped
// DEK). v1 always sets Mode="none" and resume code skips decryption.
// Adding the field now means future v1.1 bundles get a non-NULL Mode
// and we don't need a one-way migration of existing plaintext bundles.
type EncryptionMeta struct {
	Mode string `json:"mode"` // "none" | "aes-gcm-v1" (future)
}

// ArtifactDescriptor records integrity + size for one file in the
// bundle. Size is informational (matches Content-Length); SHA256 is
// the authoritative integrity check.
type ArtifactDescriptor struct {
	SHA256 string `json:"sha256"` // lowercase hex
	Size   int64  `json:"size"`
}

// NewManifest builds a v1, encryption=none manifest from per-artifact
// hashes/sizes plus the original overlay path baked into vmstate.
// Returns the manifest and its own JSON encoding ready to upload as
// <prefix>manifest.json.
func NewManifest(memfile, vmstate, overlay ArtifactDescriptor, originalOverlayPath, originalRootfsPath string) (*Manifest, []byte, error) {
	m := &Manifest{
		Version:             ManifestVersion,
		Encryption:          EncryptionMeta{Mode: "none"},
		OriginalOverlayPath: originalOverlayPath,
		OriginalRootfsPath:  originalRootfsPath,
		Artifacts: map[string]ArtifactDescriptor{
			ArtifactMemfile: memfile,
			ArtifactVMState: vmstate,
			ArtifactOverlay: overlay,
		},
	}
	body, err := json.Marshal(m)
	if err != nil {
		return nil, nil, fmt.Errorf("manifest marshal: %w", err)
	}
	return m, body, nil
}

// ParseManifest decodes a JSON manifest, returning a typed value.
// Used both for the bucket-side manifest.json read on debug paths
// and for unmarshalling the row's snapshot_manifest JSONB.
func ParseManifest(data []byte) (*Manifest, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("manifest empty")
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifest decode: %w", err)
	}
	if m.Version != ManifestVersion {
		return nil, fmt.Errorf("manifest version %d unsupported (want %d)", m.Version, ManifestVersion)
	}
	if m.Artifacts == nil {
		return nil, fmt.Errorf("manifest missing artifacts")
	}
	for _, key := range []string{ArtifactMemfile, ArtifactVMState, ArtifactOverlay} {
		a, ok := m.Artifacts[key]
		if !ok {
			return nil, fmt.Errorf("manifest missing artifact %q", key)
		}
		if a.SHA256 == "" {
			return nil, fmt.Errorf("manifest %q sha256 empty", key)
		}
	}
	return &m, nil
}

// VerifyArtifact returns nil if the given (path, sha256, size)
// matches the manifest's record for the named artifact, else a
// descriptive error. Used by resume to validate on-disk locality
// cache files against the row's manifest.
func (m *Manifest) VerifyArtifact(name, gotSHA256 string, gotSize int64) error {
	want, ok := m.Artifacts[name]
	if !ok {
		return fmt.Errorf("manifest has no artifact %q", name)
	}
	if want.SHA256 != gotSHA256 {
		return fmt.Errorf("artifact %q sha256 mismatch: want %s got %s",
			name, want.SHA256, gotSHA256)
	}
	if gotSize != want.Size {
		return fmt.Errorf("artifact %q size mismatch: want %d got %d",
			name, want.Size, gotSize)
	}
	return nil
}
