package vm

import (
	"encoding/json"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
)

// baseExt4Meta is the integrity sidecar for a prewarmed base.ext4. We
// don't need cryptographic strength — the threat is an RCE'd
// per-slot-uid firecracker scribbling on the shared file via its brief
// O_RDWR fd at snapshot-load. Any write bumps mtime; reverting mtime to
// the recorded value requires CAP_FOWNER (or file ownership), which the
// slot uid has neither. So (mtime_ns, size) is a complete tamper signal.
type baseExt4Meta struct {
	MTimeNs int64 `json:"mtime_ns"`
	Size    int64 `json:"size"`
}

// baseExt4MetaPath returns the path of the integrity sidecar that lives
// alongside base.ext4 in the snapshot directory.
func baseExt4MetaPath(baseOverlay string) string {
	return baseOverlay + ".meta"
}

// writeBaseExt4Meta records the current (mtime, size) of base.ext4 to
// the sidecar file. Called at the end of prewarm, after the file has
// been chmod'd. The sidecar is root:root 0600 so the kvm-group write
// permission on base.ext4 itself does not grant edit access here —
// only root can rewrite the meta.
func writeBaseExt4Meta(baseOverlay string) error {
	fi, err := os.Stat(baseOverlay)
	if err != nil {
		return fmt.Errorf("stat base.ext4: %w", err)
	}
	meta := baseExt4Meta{
		MTimeNs: fi.ModTime().UnixNano(),
		Size:    fi.Size(),
	}
	body, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	path := baseExt4MetaPath(baseOverlay)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return err
	}
	if err := os.Chown(path, 0, 0); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// verifyBaseExt4 stats base.ext4 and compares (mtime, size) against the
// sidecar. Returns nil iff the file is byte-identical to the prewarm
// output (no untracked write has occurred since).
//
// Missing sidecar is a tamper signal, NOT an exemption. If a host has
// a base.ext4 but no .meta next to it, we can't confirm provenance —
// the file might be a legitimate legacy snapshot OR an attacker-staged
// drop-in. Either way the safest move is to refuse the snapshot and
// force a re-prewarm: the caller (`firecracker.go:278-290`) catches the
// error, marks the snapshot Ready=false, schedules `createBaseSnapshot`
// in the background, and returns a transient "shape unavailable" error
// to the user. The next request after the re-prewarm completes
// resolves normally.
//
// Historical context: an earlier version of this function fail-OPEN on
// missing sidecar with the rationale "don't break existing hosts."
// That defeats the whole point of the sidecar — an attacker with the
// kvm-group write fd on base.ext4 (today's RCE'd-firecracker scenario)
// could also delete the .meta file and get a free pass. Treating
// missing-meta as tampered closes that loophole.
//
// We intentionally don't auto-create the sidecar at restore time: that
// would let an attacker write base.ext4 + the sidecar in one go.
func verifyBaseExt4(baseOverlay string) error {
	metaPath := baseExt4MetaPath(baseOverlay)
	body, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Fail closed. Caller triggers a re-prewarm which writes the
			// sidecar on success; the next call returns nil.
			log.Warnf("[integrity] %s: sidecar missing — refusing snapshot, forcing re-prewarm", baseOverlay)
			return fmt.Errorf("base.ext4 sidecar missing at %s", metaPath)
		}
		return fmt.Errorf("read meta: %w", err)
	}
	var want baseExt4Meta
	if err := json.Unmarshal(body, &want); err != nil {
		return fmt.Errorf("parse meta: %w", err)
	}
	fi, err := os.Stat(baseOverlay)
	if err != nil {
		return fmt.Errorf("stat base.ext4: %w", err)
	}
	gotMtime := fi.ModTime().UnixNano()
	gotSize := fi.Size()
	if gotMtime != want.MTimeNs || gotSize != want.Size {
		return fmt.Errorf("base.ext4 tampered: mtime_was=%d mtime_now=%d size_was=%d size_now=%d",
			want.MTimeNs, gotMtime, want.Size, gotSize)
	}
	return nil
}
