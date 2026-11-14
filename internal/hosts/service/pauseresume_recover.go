package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/hosts/vm/sparse"
	"github.com/NodeOps-app/createos-sandbox/internal/storage"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// RecoverStuckPauses scans pausing rows owned by this host and either
// completes verified bundles, fails incomplete ones, or retains bundles when
// an operational error prevents recovery.
//
// Called once at serve startup, after reconcile() has had a chance to
// reap leftover firecracker procs. By that point, in-flight pause
// goroutines from the prior process are gone, the fc-process for any
// pausing VM has been killed by reconcile, and the only state left is
// the files in /var/lib/createos/paused/<id>/ plus the row in DB.
//
// Three outcomes:
//
//  1. **Complete**: a manifest and all three matching artifacts exist locally.
//     Verify the completed bundle, upload to object storage, then MarkPaused.
//     The user's `pausing` request becomes invisibly successful.
//
//  2. **Fail**: snapshot files incomplete (crash before /snapshot/create
//     finished, or files lost). Mark the row `failed`, remove the
//     staging dir. User's recovery path is DELETE + recreate.
//
//  3. **Defer**: storage or control is unavailable. Preserve the bundle for
//     another recovery attempt at the next service startup.
//
// Only handles this host's rows. A different host taking over a pausing
// row would be wrong — the bytes only exist on the original host.
func (s *Service) RecoverStuckPauses(ctx context.Context) {
	if s.PauseCfg.HostID == "" {
		log.WithContext(ctx).Warnf("[recover-pause] HostID empty; skipping")
		return
	}
	ids, err := s.Repo.ListPausing(ctx, s.PauseCfg.HostID)
	if err != nil {
		log.WithContext(ctx).Warnf("[recover-pause] ListPausing failed: %v", err)
		return
	}
	if len(ids) == 0 {
		return
	}
	log.WithContext(ctx).Infof("[recover-pause] found %d stuck pausing row(s)", len(ids))
	completed := 0
	failed := 0
	for _, id := range ids {
		row, err := s.Repo.Get(ctx, id)
		if err != nil || row == nil {
			log.WithContext(ctx).Warnf("[recover-pause] %s Get failed: %v", id, err)
			continue
		}
		if row.Status != models.StatusPausing {
			// Concurrent state change (rare) — skip.
			continue
		}
		complete, err := s.completeStuckPause(ctx, *row)
		if err != nil {
			log.WithContext(ctx).Warnf("[recover-pause] %s recovery deferred: %v; retaining bundle", id, err)
			continue
		}
		if complete {
			completed++
		} else {
			s.failStuckPause(ctx, *row)
			failed++
		}
	}
	log.WithContext(ctx).Infof("[recover-pause] completed=%d failed=%d", completed, failed)
}

// completeStuckPause recovers only a fully published bundle. A missing or
// mismatched manifest means the previous writer did not complete this attempt.
// Operational failures keep the verified bundle and pausing row for retry.
func (s *Service) completeStuckPause(ctx context.Context, row models.Sandbox) (bool, error) {
	id := row.ID
	dir := filepath.Join(s.PauseCfg.PausedDir, id)
	manifestBody, err := os.ReadFile(filepath.Join(dir, storage.ArtifactManifest))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	manifest, err := storage.ParseManifest(manifestBody)
	if err != nil {
		return false, nil
	}
	for _, name := range []string{storage.ArtifactMemfile, storage.ArtifactVMState, storage.ArtifactOverlay} {
		desc, err := hashFile(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if err := manifest.VerifyArtifact(name, desc.SHA256, desc.Size); err != nil {
			log.WithContext(ctx).Warnf("[recover-pause] %s incomplete bundle: %v", id, err)
			return false, nil
		}
	}
	memZstPath := filepath.Join(dir, storage.ArtifactMemfile)
	vmStatePath := filepath.Join(dir, storage.ArtifactVMState)
	overlayPath := filepath.Join(dir, storage.ArtifactOverlay)
	if err := sparse.ValidateArchive(overlayPath); err != nil {
		log.WithContext(ctx).Warnf("[recover-pause] %s invalid overlay: %v", id, err)
		return false, nil
	}
	if err := securePausedDir(dir); err != nil {
		return false, err
	}
	keyPrefix := storage.BundlePrefix(id)
	if err := s.uploadBundle(ctx, keyPrefix, memZstPath, vmStatePath, overlayPath, manifestBody,
		manifest.Artifacts[storage.ArtifactMemfile], manifest.Artifacts[storage.ArtifactVMState],
		manifest.Artifacts[storage.ArtifactOverlay]); err != nil {
		return false, err
	}
	now := time.Now().UTC()
	cachedUntil := now.Add(s.PauseCfg.LocalRetain)
	uri := "s3://" + keyPrefix
	cachedHostID := s.PauseCfg.HostID
	st, err := s.Repo.MarkPaused(ctx, id, manifestBody, &uri, &cachedHostID, cachedUntil, now)
	if err != nil {
		return false, err
	}
	if st == "" {
		return false, fmt.Errorf("row no longer pausing; retaining local bundle")
	}
	log.WithContext(ctx).Infof("[recover-pause] %s recovered verified bundle; row now paused", id)
	return true, nil
}

// RecoverStuckResumes scans `resuming` rows owned by this host and
// retries the resume from where the prior process left off. Much
// simpler than pause recovery: Object storage holds the canonical bundle, so any
// crash before MarkResumed is recoverable by just re-running the
// resume goroutine — the existing locality cache + sha256 verify
// inside runResume make it idempotent (skips fetch/decompress when
// local files match the manifest, refetches if they don't).
//
// Note we filter to host_id == me. Rows where another host owns the
// resume aren't ours to retry — that host's own startup recovery will
// pick them up. Rows that already moved to `running` (post-MarkResumed)
// are not in this list; reconcile()'s rehydrate path handles them.
func (s *Service) RecoverStuckResumes(ctx context.Context) {
	if s.PauseCfg.HostID == "" {
		return
	}
	rows, err := s.Repo.ListStuckResuming(ctx, time.Now().UTC(), s.Region)
	if err != nil {
		log.WithContext(ctx).Warnf("[recover-resume] ListStuckResuming failed: %v", err)
		return
	}
	mine := 0
	for _, row := range rows {
		rowHostID := ""
		if row.HostID != nil {
			rowHostID = *row.HostID
		}
		if rowHostID != s.PauseCfg.HostID {
			continue
		}
		mine++
		log.WithContext(ctx).Infof("[recover-resume] %s retrying (host_id=%s)", row.ID, rowHostID)
		// Resume() spawns a goroutine; we don't block startup.
		// The row's snapshot_manifest + snapshot_uri are still set
		// from its prior paused state, so runResume has everything
		// it needs to fetch + restore.
		s.runResumeAsync(context.Background(), row)
	}
	if mine > 0 {
		log.WithContext(ctx).Infof("[recover-resume] kicked off %d stuck resume(s)", mine)
	}
}

// failStuckPause marks the row failed with a recovery hint and removes
// the local staging dir so disk doesn't leak.
func (s *Service) failStuckPause(ctx context.Context, row models.Sandbox) {
	id := row.ID
	dir := filepath.Join(s.PauseCfg.PausedDir, id)
	msg := fmt.Sprintf("serve restarted mid-pause; local files insufficient for recovery (dir=%s)", dir)
	if err := s.Repo.MarkFailed(ctx, id, &msg, time.Now().UTC()); err != nil {
		log.WithContext(ctx).Warnf("[recover-pause] %s MarkFailed: %v", id, err)
	}
	if err := os.RemoveAll(dir); err != nil {
		log.WithContext(ctx).Warnf("[recover-pause] %s remove staging dir: %v", id, err)
	}
	log.WithContext(ctx).Warnf("[recover-pause] %s failed: %s", id, msg)
}
