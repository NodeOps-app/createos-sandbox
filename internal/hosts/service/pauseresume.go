package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/hosts/vm"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/vm/sparse"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/internal/storage"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// PauseConfig is the per-host configuration for the pause/resume
// machinery. Constructed once at host startup and stored on Service.PauseCfg.
type PauseConfig struct {
	HostID            string        // this host's id (matches DB host_id)
	PausedDir         string        // /var/lib/createos/paused
	LocalRetain       time.Duration // 6h
	LocalDiskBudget   int64         // bytes
	RetryBudget       int           // PAUSE_RETRY_BUDGET, default 5
	ResumeMaxHosts    int           // RESUME_MAX_HOSTS, default 3
	ZstdLevel         int           // 1..19; default 1
	ReconcileInterval time.Duration // 1m
}

// runPauseAsync starts the pause flow for a live sandbox. runPause guards
// concurrent attempts with the local transition lock. After a host-service
// restart, RecoverStuckPauses validates durable artifacts separately.
//
// On success: storage has the bundle; row.status='paused';
// firecracker/network are torn down; local cache files remain in
// PausedDir/<id>/ for the locality cache window.
//
// Upload retry exhaustion attempts to resume the guest and restore running
// state. A failed rollback is handled separately; it is not reported as success.
func (s *Service) runPauseAsync(ctx context.Context, id string) {
	go s.runPause(ctx, id)
}

// RunPauseAsync is the package-external entry the reconcile poll uses
// to (re)kick the pause orchestrator. Wraps runPauseAsync — the
// transitionInflight set inside runPause makes the call idempotent.
func (s *Service) RunPauseAsync(ctx context.Context, id string) {
	s.runPauseAsync(ctx, id)
}

func (s *Service) runPause(ctx context.Context, id string) {
	// Idempotent against double-trigger: HTTP /pause and the reconcile
	// poll both reach here. First in wins; the other returns no-op
	// before doing any work.
	if !s.tryClaimTransition(id) {
		return
	}
	defer s.releaseTransition(id)

	sb, ok := s.Mgr.Lookup(id)
	if !ok {
		log.WithContext(ctx).Warnf("[pause] %s: not in manager (already torn down?)", id)
		return
	}

	dir := filepath.Join(s.PauseCfg.PausedDir, id)
	lease, err := s.reserveDiskWork(ctx, "pause", diskNeed{dir, snapshotWorkBytes(int64(sb.MemMib), sb.DiskMib)})
	if err != nil {
		// No hooks or Firecracker pause have run. Restore the durable running
		// state directly; never mark a healthy VM failed for disk pressure.
		retryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		msg := "pause temporarily unavailable; please retry"
		if _, e := s.Repo.MarkPauseRolledBack(retryCtx, sb.ID, &msg, time.Now().UTC()); e != nil {
			log.WithContext(ctx).WithError(e).Warn("[disk-budget] could not defer pause")
		}
		return
	}
	defer lease.release()
	build, err := s.Mgr.SnapshotFirecrackerBuild(sb)
	if err != nil {
		// Nothing is frozen yet. Keep the guest running if its binary/policy
		// was not retained; never create a bundle we cannot restore.
		log.WithContext(ctx).WithError(err).Warn("[pause] producer runtime unavailable")
		retryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		msg := "pause temporarily unavailable; please retry"
		if _, e := s.Repo.MarkPauseRolledBack(retryCtx, sb.ID, &msg, time.Now().UTC()); e != nil {
			log.WithContext(ctx).WithError(e).Warn("[pause] could not defer pause")
		}
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.markPauseFailed(ctx, sb, fmt.Sprintf("mkdir paused dir: %v", err))
		return
	}
	// The directory is temporarily handed to Firecracker's per-slot UID
	// below. Restore the root-only at-rest invariant on every return path,
	// including PauseVM/CreateSnapshot failures and future early exits.
	defer func() {
		if err := securePausedDir(dir); err != nil {
			log.WithContext(ctx).Warnf("[pause] %s secure paused dir on exit: %v", id, err)
		}
	}()
	if sb.Net != nil {
		s.Mgr.ChownForSlot(dir, sb.Net.VsockCID)
	}
	memPath := filepath.Join(dir, "memfile")
	vmStatePath := filepath.Join(dir, "vmstate")
	memZstPath := filepath.Join(dir, storage.ArtifactMemfile)
	overlayZstPath := filepath.Join(dir, storage.ArtifactOverlay)
	manifestPath := filepath.Join(dir, storage.ArtifactManifest)
	// The manifest is the completion record for this pause attempt. Never let
	// a previous attempt authorize recovery of newly overwritten artifacts.
	if err := os.Remove(manifestPath); err != nil && !os.IsNotExist(err) {
		s.markPauseFailed(ctx, sb, fmt.Sprintf("remove old manifest: %v", err))
		return
	}

	tStart := time.Now()
	// (No pre-snapshot hardlink needed anymore — sb.OverlayPath now
	// lives under runtimeDir, decoupled from the pausedDir cache. The
	// archive step below reads directly from sb.OverlayPath and writes
	// straight to overlayZstPath in pausedDir.)

	// Step 0: run guest-side pre-pause hooks, synchronously. This is the
	// "FUSE-safe pause" path — userspace daemons (s3fs, rclone, fuse
	// mounts in general) hold open TCP sockets to remote services. If
	// we snapshot with those sockets live, the post-resume kernel TCP
	// state is stale and any read on the mount EIOs or hangs until the
	// daemon notices and reconnects. Hooks under /etc/createos/pre-pause.d/
	// are expected to fuser/unmount/teardown such daemons; the matching
	// /etc/createos/post-resume.d/ scripts re-establish them after restore.
	//
	// Best-effort: hooks shouldn't block pause if they fail (nothing to
	// roll back to). 5s soft budget; if hooks need longer they should
	// background themselves.
	hookCtx, hookCancel := context.WithTimeout(ctx, 5*time.Second)
	hookResp, hookErr := sb.Exec(hookCtx, proto.ExecRequest{
		Cmd:  "sh",
		Args: []string{"-c", `for f in /etc/createos/pre-pause.d/*; do [ -x "$f" ] && "$f" || true; done`},
	})
	hookCancel()
	if hookErr != nil {
		log.WithContext(ctx).Warnf("[pause] %s: pre-pause hooks: %v (continuing)", id, hookErr)
	} else if hookResp != nil && hookResp.ExitCode != 0 {
		log.WithContext(ctx).Warnf("[pause] %s: pre-pause hooks exit=%d stderr=%q (continuing)",
			id, hookResp.ExitCode, hookResp.Stderr)
	}
	// Disks are unmounted by the pre-pause hook. Flip every attachment
	// for this sandbox back to 'pending' so the user-facing status
	// doesn't keep showing 'mounted' across the pause boundary. The
	// disk status poller will reconcile back to 'mounted' on resume.
	if rerr := s.Repo.ResetSandboxDiskStatus(ctx, id); rerr != nil {
		log.WithContext(ctx).Debugf("[pause] %s: reset disk status: %v", id, rerr)
	}

	// Step 1 (idempotent): pause the VM at firecracker level + create
	// snapshot files. PauseVM on an already-paused VM is a no-op per
	// firecracker docs; CreateSnapshot overwrites.
	//
	// Two driver paths:
	//   - sb.Machine != nil: fresh-create or post-resume — use the SDK.
	//   - sb.Machine == nil: rehydrated across serve restart — the SDK
	//     handle is gone but the firecracker process and its API socket
	//     are still live, so we drive it via raw HTTP over the socket.
	// Mute the per-VM liveness watcher BEFORE freezing the guest. Without
	// this, a long snapshot operation can exhaust the liveness recovery
	// window and tear the VM down mid-pause instead of leaving it paused.
	sb.Freezing.Store(true)
	// Note: we used to UpdateGuestDrive(overlayfs) to a stable paused-dir
	// path here so vmstate's captured path would survive serve restarts
	// across pause/resume. The new firecracker fork exposes
	// `block_path_overrides` on PUT /snapshot/load, so resume can point
	// the overlay drive at any host path at restore — vmstate's baked
	// path is now informational only. Drop the swap; less moving parts.
	if sb.Machine != nil {
		if err := sb.Machine.PauseVM(ctx); err != nil {
			sb.Freezing.Store(false)
			s.markPauseFailed(ctx, sb, fmt.Sprintf("PauseVM: %v", err))
			return
		}
		if err := sb.Machine.CreateSnapshot(ctx, memPath, vmStatePath); err != nil {
			s.rollbackAndFail(ctx, sb, fmt.Sprintf("CreateSnapshot: %v", err))
			return
		}
	} else {
		if sb.ApiSocket == "" {
			sb.Freezing.Store(false)
			s.markPauseFailed(ctx, sb, "rehydrated VM has no api_sock recorded; cannot pause")
			return
		}
		fc := vm.NewFirecrackerAPI(sb.ApiSocket)
		if err := fc.PauseVM(ctx); err != nil {
			sb.Freezing.Store(false)
			s.markPauseFailed(ctx, sb, fmt.Sprintf("PauseVM (rehydrated): %v", err))
			return
		}
		if err := fc.CreateSnapshot(ctx, memPath, vmStatePath); err != nil {
			s.rollbackAndFail(ctx, sb, fmt.Sprintf("CreateSnapshot (rehydrated): %v", err))
			return
		}
	}

	tSnapshot := time.Now()
	log.WithContext(ctx).Infof("[pause] %s phase=snapshot took=%v", id, tSnapshot.Sub(tStart))

	// Restore the paused dir + its contents to root:root mode 0700/0600.
	// At pause time we chowned the dir to the pause-slot uid so the
	// post-drop firecracker could write memfile/vmstate. Now that the
	// snapshot is on disk, lock it back down so other tenants on this
	// host can't read another VM's RAM dump. Resume re-chowns to the
	// new slot uid right before /snapshot/load (see resume_snapshot.go).
	if err := securePausedDir(dir); err != nil {
		log.WithContext(ctx).Warnf("[pause] %s secure snapshot artifacts: %v", id, err)
	}

	// Step 2 (idempotent): compress + hash artifacts. Recomputes from
	// scratch every attempt — the inputs are deterministic so the
	// outputs are too.
	tMem := time.Now()
	memDesc, err := s.compressAndHash(memPath, memZstPath)
	if err != nil {
		s.rollbackAndFail(ctx, sb, fmt.Sprintf("compress mem: %v", err))
		return
	}
	_ = os.Chmod(memZstPath, 0o600)
	log.WithContext(ctx).Infof("[pause] %s phase=compress.mem took=%v size=%d", id, time.Since(tMem), memDesc.Size)
	tVm := time.Now()
	vmstateDesc, err := hashFile(vmStatePath)
	if err != nil {
		s.rollbackAndFail(ctx, sb, fmt.Sprintf("hash vmstate: %v", err))
		return
	}
	log.WithContext(ctx).Infof("[pause] %s phase=hash.vmstate took=%v", id, time.Since(tVm))
	tOv := time.Now()
	// Overlay is a 10 GiB sparse ext4 file with typically <10 MiB of
	// live data. Stream-compressing it through zstd would force the
	// encoder to consume the full apparent size (mostly zero bytes),
	// making it the dominant cost of the pause path. The sparse
	// archive format walks data regions via SEEK_DATA/SEEK_HOLE and
	// writes only [offset, length, bytes] tuples — runtime is
	// proportional to live data, not file size.
	_, overlayArchiveSize, overlaySHA, err := sparse.WriteArchive(sb.OverlayPath, overlayZstPath)
	if err != nil {
		s.rollbackAndFail(ctx, sb, fmt.Sprintf("archive overlay: %v", err))
		return
	}
	_ = os.Chmod(overlayZstPath, 0o600)
	overlayDesc := storage.ArtifactDescriptor{SHA256: overlaySHA, Size: overlayArchiveSize}
	log.WithContext(ctx).Infof("[pause] %s phase=archive.overlay took=%v size=%d srcPath=%s", id, time.Since(tOv), overlayArchiveSize, sb.OverlayPath)
	// Hardlink already done above pre-compress for crash-recovery; no-op
	// here other than the timing log.
	tCompress := time.Now()
	log.WithContext(ctx).Infof("[pause] %s phase=compress took=%v memzst=%dB ovzst=%dB", id, tCompress.Sub(tSnapshot), memDesc.Size, overlayDesc.Size)

	// The path that goes into the manifest must match what's actually
	// manifest.OriginalOverlayPath is now informational only — the
	// resume call passes a block_path_override that points the overlay
	// drive at the resuming host's local file regardless of what
	// vmstate captured. Kept on the manifest for diagnostics and
	// backward compat with any consumer that still reads it.
	vmstateBakedPath := sb.OverlayPath
	if sb.VMStateOverlayPath != "" {
		vmstateBakedPath = sb.VMStateOverlayPath
	}
	// The rootfs drive's path is also baked into vmstate (read-only
	// drive). On cross-host resume the resuming host's catalog will
	// almost certainly resolve to a different absolute path, so we
	// record the source path here and symlink it on resume.
	bakedRootfsPath, _ := s.Mgr.LookupRootfs(sb.Rootfs)
	manifest, manifestBody, err := storage.NewManifest(memDesc, vmstateDesc, overlayDesc, vmstateBakedPath, bakedRootfsPath)
	if err != nil {
		s.rollbackAndFail(ctx, sb, fmt.Sprintf("manifest build: %v", err))
		return
	}
	log.WithContext(ctx).WithField("sandbox_id", id).WithField("firecracker_build", build).Info("[pause] recorded producer runtime")
	manifest.FirecrackerBuild = build
	manifestBody, err = json.Marshal(manifest)
	if err != nil {
		s.rollbackAndFail(ctx, sb, fmt.Sprintf("manifest encode: %v", err))
		return
	}
	if err := publishPauseManifest(manifestPath, manifestBody); err != nil {
		s.rollbackAndFail(ctx, sb, fmt.Sprintf("write manifest: %v", err))
		return
	}

	// Upload the complete bundle before publishing the paused state. This
	// keeps status=paused equivalent to "restorable from shared storage."
	keyPrefix := storage.BundlePrefix(id)
	uri := "s3://" + keyPrefix
	manifestJSON, _ := json.Marshal(manifest)

	if !s.uploadBundleWithRetry(ctx, sb, keyPrefix, memZstPath, vmStatePath,
		overlayZstPath, manifestBody, memDesc, vmstateDesc, overlayDesc) {
		return
	}
	tUpload := time.Now()
	log.WithContext(ctx).Infof("[pause] %s phase=upload took=%v", id, tUpload.Sub(tCompress))

	now := time.Now().UTC()
	cachedUntil := now.Add(s.PauseCfg.LocalRetain)
	cachedHostID := s.PauseCfg.HostID
	// Sync path: the bundle is already in object storage by the time we get here.
	// Stamp bundle_uploaded_at atomically with status='paused' so a
	// client that polls status and then immediately calls fork can't
	// land in a window where the row says paused but bundle_uploaded_at
	// is still NULL.
	st, err := s.Repo.MarkPaused(ctx, id, manifestJSON, &uri, &cachedHostID, cachedUntil, now)
	if err != nil {
		log.WithContext(ctx).Errorf("[pause] %s MarkPaused failed: %v", id, err)
		return
	}
	if st == "" {
		log.WithContext(ctx).Warnf("[pause] %s CAS missed (row no longer pausing); leaving local files alone", id)
		return
	}
	s.tearDownAfterPause(sb)
	log.WithContext(ctx).Infof("[pause] %s paused successfully; cached locally until %s", id, cachedUntil.Format(time.RFC3339))
}

// uploadBundleWithRetry uploads all snapshot artifacts before the row may
// transition to paused.
func (s *Service) uploadBundleWithRetry(
	ctx context.Context, sb *vm.Sandbox, keyPrefix,
	memZst, vmstate, overlayZst string, manifestBody []byte,
	memDesc, vmstateDesc, overlayDesc storage.ArtifactDescriptor,
) bool {
	// Bound all SDK and bundle retries together; individual stalled uploads
	// are also cancelled by the storage client's progress watchdog.
	uploadBytes := memDesc.Size + vmstateDesc.Size + overlayDesc.Size + int64(len(manifestBody))
	uploadTimeout := pauseUploadTimeout(uploadBytes)
	uploadCtx, cancel := context.WithTimeout(ctx, uploadTimeout)
	defer cancel()
	backoff := 2 * time.Second
	var lastErr error
	for attempt := 1; attempt <= s.PauseCfg.RetryBudget; attempt++ {
		if err := s.uploadBundle(uploadCtx, keyPrefix, memZst, vmstate, overlayZst, manifestBody, memDesc, vmstateDesc, overlayDesc); err != nil {
			lastErr = err
			log.WithContext(ctx).Warnf("[pause] %s upload attempt %d/%d failed: %v", sb.ID, attempt, s.PauseCfg.RetryBudget, err)
			if uploadCtx.Err() != nil {
				s.rollbackAndFail(ctx, sb, fmt.Sprintf("upload stopped: %v", uploadCtx.Err()))
				return false
			}
			if attempt == s.PauseCfg.RetryBudget {
				break
			}
			select {
			case <-time.After(backoff):
			case <-uploadCtx.Done():
				s.rollbackAndFail(ctx, sb, fmt.Sprintf("upload stopped: %v", uploadCtx.Err()))
				return false
			}
			backoff *= 2
			continue
		}
		return true
	}
	s.rollbackAndFail(ctx, sb, fmt.Sprintf("upload exhausted (%d attempts): %v", s.PauseCfg.RetryBudget, lastErr))
	return false
}

// tryRollback resumes the VM before re-enabling guest liveness checks.
func (s *Service) tryRollback(ctx context.Context, sb *vm.Sandbox) error {
	var err error
	if sb.Machine != nil {
		err = sb.Machine.ResumeVM(ctx)
	} else if sb.ApiSocket != "" {
		err = vm.NewFirecrackerAPI(sb.ApiSocket).ResumeVM(ctx)
	} else {
		return fmt.Errorf("no firecracker handle for rollback")
	}
	if err != nil {
		return err
	}
	sb.Freezing.Store(false)
	return nil
}

// securePausedDir restores a pause staging tree to root-only ownership.
// WalkDir does not follow symlinks; Lchown therefore cannot be redirected to
// an arbitrary host path if a compromised slot UID created one while it owned
// the staging directory.
func securePausedDir(dir string) error {
	var secureErrs []error
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			secureErrs = append(secureErrs, fmt.Errorf("walk %s: %w", path, walkErr))
			return nil
		}
		if err := os.Lchown(path, 0, 0); err != nil && !os.IsNotExist(err) {
			secureErrs = append(secureErrs, fmt.Errorf("chown %s: %w", path, err))
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		mode := os.FileMode(0o600)
		if entry.IsDir() {
			mode = 0o700
		}
		if err := os.Chmod(path, mode); err != nil && !os.IsNotExist(err) {
			secureErrs = append(secureErrs, fmt.Errorf("chmod %s: %w", path, err))
		}
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return errors.Join(secureErrs...)
		}
		secureErrs = append(secureErrs, err)
	}
	return errors.Join(secureErrs...)
}

// rollbackAndFail flips the row back to 'running' and resumes the VM.
// Used when the VM is still alive but pause hit a non-retriable error.
func (s *Service) rollbackAndFail(ctx context.Context, sb *vm.Sandbox, msg string) {
	// An expired upload/request context must not prevent recovery of the VM.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := s.tryRollback(ctx, sb); err != nil {
		s.markPauseFailed(ctx, sb, fmt.Sprintf("%s; resume rollback failed: %v", msg, err))
		return
	}
	if _, err := s.Repo.MarkPauseRolledBack(ctx, sb.ID, &msg, time.Now().UTC()); err != nil {
		log.WithContext(ctx).Errorf("[pause] %s MarkPauseRolledBack failed: %v", sb.ID, err)
	}
	// Cleanup local snapshot files — no successful upload to anchor them.
	_ = os.RemoveAll(filepath.Join(s.PauseCfg.PausedDir, sb.ID))
	log.WithContext(ctx).Warnf("[pause] %s rolled back to running: %s", sb.ID, msg)
}

// markPauseFailed is for the rare case where the VM is gone entirely
// (rehydrated with missing snapshot files). Marks 'failed'.
func (s *Service) markPauseFailed(ctx context.Context, sb *vm.Sandbox, msg string) {
	log.WithContext(ctx).Errorf("[pause] %s permanently failed: %s", sb.ID, msg)
	_ = s.Repo.MarkFailed(ctx, sb.ID, &msg, time.Now().UTC())
}

func (s *Service) tearDownAfterPause(sb *vm.Sandbox) {
	// Remove the VM from the running set while holding the same lock used by
	// live egress replacement. This prevents a concurrent PUT /egress from
	// recreating policy after the teardown batch has removed it.
	unlockEgress, ok := s.Mgr.BeginTeardown(sb)
	if !ok {
		return
	}
	defer unlockEgress()

	// Mirrors vm.Manager.Destroy's cleanup but without DB updates (already
	// done by MarkPaused). Marks the sandbox as destroyed-from-vm.Manager's
	// perspective so WatchDeath doesn't fire.
	sb.Destroyed.Store(true)

	s.StopSelfSignal(sb.ID)

	// Per-VM cleanup parity with Mgr.Destroy — without these, the slot
	// returns to NetPool with the previous VM's BPF map entries and
	// iptables chain still in place. They're inert for the next VM
	// (keyed on the old sandbox id) but accumulate over time and
	// pollute observability.
	teardownFailed := false
	if sb.HostVeth != "" {
		vm.DetachBPFMeter(sb.ID, sb.HostVeth)
		vm.ResetBPFMeter(sb.ID)
		if err := vm.EnqueueTeardown(sb.ID, sb.HostVeth); err != nil {
			teardownFailed = true
			log.Warnf("[pause] iptables teardown failed sandbox=%s veth=%s: %v; discarding slot",
				sb.ID, sb.HostVeth, err)
		}
	}

	// Kill the firecracker process. Critical: Machine.Shutdown sends
	// SendCtrlAltDel to the *guest*, not SIGTERM to firecracker — the
	// guest agent may not even respond, and even if it does the parent
	// firecracker process keeps running until SIGTERM/SIGKILL hits it
	// directly. Without this kill, every resume after a pause spawns a
	// NEW firecracker that competes with the old one for the same
	// api-sock path, causing exec wedges and orphan PIDs.
	if sb.Machine != nil {
		_ = sb.Machine.StopVMM() // SIGTERM via SDK process handle
	}
	if sb.FCPid > 0 {
		// Belt-and-suspenders: also send SIGKILL to the recorded PID.
		// Cheap (one syscall on a possibly-already-dead PID) and
		// ensures cleanup even when the SDK Machine handle is stale.
		vm.KillFirecrackerFast(sb.FCPid)
	}
	if err := s.Mgr.RevokeTemplateAccess(sb); err != nil {
		log.Warnf("[template-acl] revoke paused sandbox=%s: %v", sb.ID, err)
	}

	if sb.Uffd != nil {
		sb.Uffd.Close()
		sb.Uffd = nil
	}
	if sb.OverlayPath != "" {
		_ = os.Remove(sb.OverlayPath)
	}
	if sb.ApiSocket != "" {
		_ = os.Remove(sb.ApiSocket)
	}
	if sb.VsockUDSPath != "" {
		// firecracker creates both the bare path and a per-port "_PORT"
		// peer for guest-initiated connections. Clean both.
		_ = os.Remove(sb.VsockUDSPath)
		_ = os.Remove(sb.VsockUDSPath + "_1024")
	}
	// Mirror Mgr.Destroy: catch the per-VM runtime subdir + any stray
	// sockets firecracker bound there. Without this every successful
	// pause leaks an empty runtime/<sb>/ directory.
	_ = os.RemoveAll(vm.SlotRuntimeDir(sb.ID))
	if sb.Net != nil && teardownFailed {
		// Never recycle a veth whose sandbox-specific policy could not be
		// removed. Keep it discoverable until the reaper retries cleanup;
		// resume will acquire a clean replacement slot.
		s.Mgr.Pool.QuarantineAfterTeardownFailure(sb.Net, sb.ID)
	} else if sb.Net != nil {
		// Slot returns to NetPool last, after all per-VM artifacts are
		// scrubbed. MarkPaused has already committed the DB row to
		// `paused`, so there's no pinning-window concern like the
		// destroy path has — the DB is settled before this returns.
		s.Mgr.Pool.Return(sb.Net)
	}
}

// compressAndHash streams srcPath through zstd into dstPath while
// computing a sha256 over the COMPRESSED bytes (because that's what
// goes to storage, and it's what we verify on download).
//
// Uses sparseReader for the source so hole regions (typical 99%+ of a
// fresh ext4 overlay) get fed to the compressor as in-memory zeros
// without a disk read. Drops compress wall time on a 10 GB sparse
// overlay from ~17s to ~50ms.
func (s *Service) compressAndHash(srcPath, dstPath string) (storage.ArtifactDescriptor, error) {
	src, err := os.Open(srcPath)
	if err != nil {
		return storage.ArtifactDescriptor{}, err
	}
	defer src.Close()
	sparse, err := sparse.NewReader(src)
	if err != nil {
		return storage.ArtifactDescriptor{}, err
	}
	dst, err := os.Create(dstPath)
	if err != nil {
		return storage.ArtifactDescriptor{}, err
	}

	hasher := sha256.New()
	tee := io.MultiWriter(dst, hasher)

	// Parallelize stream sections with a bounded worker count per pause.
	// Encoder concurrency alone does not enable parallel block compression.
	enc, err := zstd.NewWriter(tee,
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(s.PauseCfg.ZstdLevel)),
		zstd.WithEncoderConcurrency(2),
		zstd.WithConcurrentBlocks(true),
	)
	if err != nil {
		dst.Close()
		return storage.ArtifactDescriptor{}, err
	}
	if _, err := io.Copy(enc, sparse); err != nil {
		enc.Close()
		dst.Close()
		return storage.ArtifactDescriptor{}, err
	}
	if err := enc.Close(); err != nil {
		dst.Close()
		return storage.ArtifactDescriptor{}, err
	}
	if err := dst.Sync(); err != nil {
		dst.Close()
		return storage.ArtifactDescriptor{}, err
	}
	dst.Close()

	stat, err := os.Stat(dstPath)
	if err != nil {
		return storage.ArtifactDescriptor{}, err
	}
	return storage.ArtifactDescriptor{
		SHA256: hex.EncodeToString(hasher.Sum(nil)),
		Size:   stat.Size(),
	}, nil
}

func hashFile(path string) (storage.ArtifactDescriptor, error) {
	sum, n, err := storage.HashFile(path)
	if err != nil {
		return storage.ArtifactDescriptor{}, err
	}
	return storage.ArtifactDescriptor{SHA256: sum, Size: n}, nil
}

func pauseUploadTimeout(size int64) time.Duration {
	// Allow slower transfers and snapshot read-back verification. R2.Put
	// separately bounds inactivity, so a stalled upload need not use this entire
	// budget. Keep a hard cap for pause rollback; captures also have a durable
	// one-hour deadline which a host restart cannot renew.
	return min(30*time.Minute, 2*time.Minute+time.Duration(max(size, 0)/(1024*1024))*time.Second)
}

func (s *Service) uploadBundle(ctx context.Context, keyPrefix, memZst, vmstate, overlayZst string, manifestBody []byte, memDesc, vmstateDesc, overlayDesc storage.ArtifactDescriptor) error {
	// Recovery calls this directly, without the outer retry loop's deadline.
	ctx, cancel := context.WithTimeout(ctx, pauseUploadTimeout(memDesc.Size+vmstateDesc.Size+overlayDesc.Size+int64(len(manifestBody))))
	defer cancel()
	if err := s.uploadFile(ctx, keyPrefix+storage.ArtifactMemfile, memZst, memDesc); err != nil {
		return err
	}
	if err := s.uploadFile(ctx, keyPrefix+storage.ArtifactVMState, vmstate, vmstateDesc); err != nil {
		return err
	}
	if err := s.uploadFile(ctx, keyPrefix+storage.ArtifactOverlay, overlayZst, overlayDesc); err != nil {
		return err
	}
	if err := s.Storage.Put(ctx, keyPrefix+storage.ArtifactManifest,
		bytes.NewReader(manifestBody), int64(len(manifestBody)), ""); err != nil {
		return fmt.Errorf("upload manifest: %w", err)
	}
	return nil
}

func (s *Service) uploadFile(ctx context.Context, key, path string, desc storage.ArtifactDescriptor) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return s.Storage.Put(ctx, key, f, desc.Size, desc.SHA256)
}

// Resume runs the resume flow for a paused sandbox. vm.Manager.Resume is
// invoked by the host's API handler with the row already in 'resuming'.
func (s *Service) runResumeAsync(ctx context.Context, row models.Sandbox) {
	go s.runResume(ctx, row)
}

// RunResumeAsync is the package-external entry the reconcile poll uses
// to (re)kick the resume orchestrator. transitionInflight makes it
// idempotent vs the HTTP /resume forward path.
func (s *Service) RunResumeAsync(ctx context.Context, row models.Sandbox) {
	s.runResumeAsync(ctx, row)
}

func (s *Service) runResume(ctx context.Context, row models.Sandbox) {
	id := row.ID
	// Idempotent against double-trigger: HTTP /resume and the reconcile
	// poll both reach here. First in wins.
	if !s.tryClaimTransition(id) {
		return
	}
	defer s.releaseTransition(id)
	releaseRuntime := s.Mgr.HoldRuntime(id)
	defer releaseRuntime()
	if len(row.SnapshotManifest) == 0 {
		s.markResumeFailed(ctx, id, "row has no snapshot_manifest")
		return
	}
	manifest, err := storage.ParseManifest(row.SnapshotManifest)
	if err != nil {
		s.markResumeFailed(ctx, id, "parse manifest: "+err.Error())
		return
	}

	dir := filepath.Join(s.PauseCfg.PausedDir, id)
	var compressed int64
	for _, a := range manifest.Artifacts {
		compressed += a.Size
	}
	lease, err := s.reserveDiskWork(ctx, "resume",
		diskNeed{dir, compressed + int64(row.MemMib)*1024*1024 + 64*1024*1024},
		diskNeed{vm.SlotRuntimeDir(id), row.DiskMib * 1024 * 1024})
	if err != nil {
		s.markResumeFailed(ctx, id, "insufficient disk working space")
		return
	}
	defer lease.release()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.markResumeFailed(ctx, id, "mkdir: "+err.Error())
		return
	}

	memZstPath := filepath.Join(dir, storage.ArtifactMemfile)
	vmstatePath := filepath.Join(dir, storage.ArtifactVMState)
	overlayZstPath := filepath.Join(dir, storage.ArtifactOverlay)
	memPath := filepath.Join(dir, "memfile")

	// Runtime overlay path — the LIVE block device firecracker opens.
	// Deliberately under runtimeDir, NOT pausedDir: the reaper
	// (sweepOrphanedPausedDirs) treats any paused/<sb>/ dir for a
	// running VM as stale and rm-rf's it. If firecracker were opening
	// a file inside paused/<sb>/, the reaper would unlink the
	// directory entry while firecracker still held the fd — VM keeps
	// working, but the next pause's archive step can't open by path
	// and fails ENOENT. Keeping live overlay under runtime/<sb>/
	// decouples cache management from VM lifecycle.
	runtimeOverlayPath := filepath.Join(vm.SlotRuntimeDir(id), "overlay.ext4")
	if err := os.MkdirAll(filepath.Dir(runtimeOverlayPath), 0o700); err != nil {
		s.markResumeFailed(ctx, id, "mkdir runtime: "+err.Error())
		return
	}

	// Locality fast-path: pause leaves the COMPRESSED memfile/overlay +
	// raw vmstate alongside the manifest. If we're resuming on the same
	// host (cached_host_id matches us), we can skip the S3 download —
	// but we still decompress fresh into the runtime overlay path,
	// since the previous live overlay (if any) was a different VM
	// lifecycle and is gone.
	//
	// Correctness gate: only trust local artifacts if cached_host_id
	// matches this host. Otherwise the sandbox last paused elsewhere
	// (or here but then resumed+paused on another host), and any local
	// files are STALE — restoring them would silently roll back to the
	// older snapshot. Force a fresh fetch.
	t0 := time.Now()
	cachedHere := row.CachedHostID != nil && *row.CachedHostID == s.PauseCfg.HostID
	cacheHit := cachedHere && fileExists(memZstPath) && fileExists(vmstatePath) && fileExists(overlayZstPath)
	if cacheHit {
		log.WithContext(ctx).Infof("[resume] %s locality cache hit; skipping fetch", id)
	} else {
		// Local files (if any) belong to an older epoch — wipe before
		// fetching so a partial old artifact can't be mistaken for the
		// new one mid-download.
		if !cachedHere {
			for _, p := range []string{memPath, vmstatePath, memZstPath, overlayZstPath} {
				_ = os.Remove(p)
			}
		}
		if err := s.fetchAndVerify(ctx, id, manifest, memZstPath, vmstatePath, overlayZstPath); err != nil {
			s.markResumeFailed(ctx, id, "fetch: "+err.Error())
			return
		}
	}
	// Decompress memfile (firecracker mmaps it during resume; can stay
	// in paused/ since firecracker releases it after restore).
	if err := decompressZst(memZstPath, memPath); err != nil {
		s.markResumeFailed(ctx, id, "decompress mem: "+err.Error())
		return
	}
	// Expand overlay directly into the runtime path so firecracker
	// opens a file under runtime/<sb>/ — the reaper never touches that.
	if err := sparse.ReadArchive(overlayZstPath, runtimeOverlayPath); err != nil {
		s.markResumeFailed(ctx, id, "expand overlay archive: "+err.Error())
		return
	}
	log.WithContext(ctx).Infof("[resume] %s artifacts ready in %v (cache_hit=%v)", id, time.Since(t0), cacheHit)

	// Symlink both drives to the paths baked into vmstate (firecracker
	// resume reads vmstate's drive paths verbatim and dies if the files
	// aren't there). Manifest carries the original paths so resume can
	// reproduce them on any host. Both targets need MkdirAll on the
	// parent — os.Symlink does NOT create parent dirs, and the source
	// host's path may resolve under a directory that doesn't exist on
	// this host (e.g. a relative `images/foo.ext4` that became
	// `/images/foo.ext4` against a `WorkingDirectory=/` systemd unit).
	// Overlay drive's path baked in vmstate is now irrelevant — the
	// resume call below passes a block_path_override that points
	// firecracker at spec.OverlayPath (this host's actual file)
	// regardless of what vmstate says. No symlink needed. Requires
	// a Firecracker build with `block_path_overrides` support on
	// PUT /snapshot/load.
	_ = manifest.OriginalOverlayPath
	rootfsName := ""
	if row.Rootfs != nil {
		rootfsName = *row.Rootfs
	}
	if want := manifest.OriginalRootfsPath; want != "" {
		// Template ext4s are an on-demand host cache, not a permanent
		// catalog entry. A paused sandbox may resume long after the local
		// cache TTL expired, or on a host that has never run this template.
		// Match the create path: fetch + verify + register the template on a
		// cache miss before asking Firecracker to restore the snapshot.
		localRootfs := ""
		ok := false
		if strings.HasPrefix(rootfsName, models.TemplateIDPrefix) {
			release, err := s.useTemplate(ctx, rootfsName)
			if err != nil {
				s.markResumeFailed(ctx, id, "ensure template: "+err.Error())
				return
			}
			defer release()
			localRootfs, err = s.EnsureTemplate(ctx, rootfsName, id)
			if err != nil {
				s.markResumeFailed(ctx, id, "ensure template: "+err.Error())
				return
			}
			ok = true
		} else {
			localRootfs, ok = s.Mgr.LookupRootfs(rootfsName)
		}
		if !ok {
			s.markResumeFailed(ctx, id, fmt.Sprintf("rootfs %q not in this host's catalog", rootfsName))
			return
		}
		if want != localRootfs {
			if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
				s.markResumeFailed(ctx, id, "mkdir rootfs parent: "+err.Error())
				return
			}
			// Only replace existing entries that are our own symlinks —
			// never clobber a real catalog file (host could legitimately
			// have a same-named rootfs at this absolute path).
			if fi, err := os.Lstat(want); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				_ = os.Remove(want)
			}
			if _, err := os.Lstat(want); os.IsNotExist(err) {
				if err := os.Symlink(localRootfs, want); err != nil {
					s.markResumeFailed(ctx, id, "symlink rootfs: "+err.Error())
					return
				}
			}
		}
	}

	// Hand off to vm.Manager.ResumeFromSnapshot to spin firecracker.
	resumeName := ""
	if row.Name != nil {
		resumeName = *row.Name
	}
	resumeSecret := ""
	if row.SecretToken != nil {
		resumeSecret = *row.SecretToken
	}
	// Re-resolve disks from control (credentials are re-decrypted on
	// every resume; we never hold plaintext across the pause boundary).
	// Failure here is non-fatal — the VM resumes without disks, and the
	// status poll surfaces 'pending' until the user retries.
	resumeDisks, derr := s.Repo.ResolveSandboxDisks(ctx, id)
	if derr != nil {
		log.WithContext(ctx).Warnf("[resume] %s resolve disks: %v", id, derr)
	}
	sb, err := s.Mgr.ResumeFromSnapshot(ctx, vm.ResumeSpec{
		FirecrackerBuild:         manifest.FirecrackerBuild,
		ID:                       id,
		Name:                     resumeName,
		MemPath:                  memPath,
		VMStatePath:              vmstatePath,
		OverlayPath:              runtimeOverlayPath,
		VMStateOverlayPath:       manifest.OriginalOverlayPath,
		Shape:                    row.Shape,
		Rootfs:                   rootfsName,
		VCPU:                     row.VCPU,
		MemMib:                   row.MemMib,
		DiskMib:                  row.DiskMib,
		Egress:                   row.Egress,
		SecretToken:              resumeSecret,
		Envs:                     row.Envs,
		BandwidthQuota:           row.BandwidthQuotaBytes,
		BandwidthUsedBaseline:    row.BandwidthUsedBytes,
		BandwidthIngressBaseline: row.BandwidthIngressBytes,
		Disks:                    resumeDisks,
	})
	if err != nil {
		s.markResumeFailed(ctx, id, "spawn fc: "+err.Error())
		return
	}

	s.StartSelfSignal(sb)

	rIP, rMAC, rSock := sb.IP, sb.Net.MAC, sb.ApiSocket
	rCID, rOverlay := sb.Net.ContainerID, sb.OverlayPath
	// MarkResumed is the last DB write of the resume flow; if it fails
	// the VM is running but its row is still `resuming`. Retry a few
	// times before giving up so a transient DB blip doesn't strand the
	// VM. On final failure, tear it down synchronously — leaving a
	// resuming row with a live VM forces the stale-watchdog +
	// reverse-sweep round trip (~5 min) and the user loses the VM
	// anyway.
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	var markErr error
	for attempt := 0; attempt < 3; attempt++ {
		if _, err := s.Repo.MarkResumed(bg, id, &rIP, &rMAC, &rSock, &rCID, &rOverlay, sb.FCPid, time.Now().UTC(), s.PauseCfg.HostID); err == nil {
			markErr = nil
			break
		} else {
			markErr = err
			log.WithContext(ctx).Warnf("[resume] %s MarkResumed attempt %d/3 failed: %v", id, attempt+1, err)
			time.Sleep(time.Duration(1<<attempt) * 200 * time.Millisecond)
		}
	}
	if markErr != nil {
		log.WithContext(ctx).Errorf("[resume] %s MarkResumed gave up after 3 retries: %v — tearing down VM", id, markErr)
		// Synchronous teardown: kill fc, scrub per-VM state, pin slot
		// in pendingRelease. The row will then be picked up by the
		// stale-state watchdog (5 min → error), then reverse-sweep
		// (30 s → destroyed) will release the slot. Better than
		// leaving a live VM with no DB record.
		_ = s.Mgr.Destroy(id)
		s.markResumeFailed(bg, id, "MarkResumed failed: "+markErr.Error())
		return
	}
	log.WithContext(ctx).Infof("[resume] %s resumed on %s ip=%s", id, s.PauseCfg.HostID, sb.IP)
}

func (s *Service) markResumeFailed(ctx context.Context, id, msg string) {
	log.WithContext(ctx).Warnf("[resume] %s failed on %s: %s", id, s.PauseCfg.HostID, msg)
	if _, err := s.Repo.MarkResumeFailed(ctx, id, s.PauseCfg.HostID, &msg, time.Now().UTC()); err != nil {
		log.WithContext(ctx).Errorf("[resume] %s MarkResumeFailed: %v", id, err)
	}
}

// fetchAndVerify ensures local files match the manifest. Tries local
// first; on integrity miss falls back to storage download with sha256
// verify on the fly.
func (s *Service) fetchAndVerify(ctx context.Context, id string, manifest *storage.Manifest, memZst, vmstate, overlayZst string) error {
	keyPrefix := storage.BundlePrefix(id)
	mapping := []struct {
		artifactName string
		localPath    string
		key          string
	}{
		{storage.ArtifactMemfile, memZst, keyPrefix + storage.ArtifactMemfile},
		{storage.ArtifactVMState, vmstate, keyPrefix + storage.ArtifactVMState},
		{storage.ArtifactOverlay, overlayZst, keyPrefix + storage.ArtifactOverlay},
	}

	for _, m := range mapping {
		if err := s.fetchOne(ctx, m.artifactName, m.localPath, m.key, manifest); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) fetchOne(ctx context.Context, artifactName, localPath, key string, manifest *storage.Manifest) error {
	want := manifest.Artifacts[artifactName]

	// Fast path: file exists locally with correct hash.
	if fileExists(localPath) {
		got, sz, err := storage.HashFile(localPath)
		if err == nil && got == want.SHA256 && sz == want.Size {
			return nil
		}
		// Stale or corrupt — remove and fall through.
		_ = os.Remove(localPath)
	}

	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		lastErr = s.fetchOneAttempt(ctx, key, localPath, want.Size, want.SHA256)
		if lastErr == nil {
			return nil
		}
		if errors.Is(lastErr, storage.ErrNotFound) || attempt == maxAttempts {
			break
		}
		backoff := time.Duration(1<<(attempt-1)) * 250 * time.Millisecond
		log.WithContext(ctx).Warnf("[resume] fetch retry key=%s attempt=%d/%d backoff=%s err=%v",
			key, attempt, maxAttempts, backoff, lastErr)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
	return fmt.Errorf("fetch %s failed after %d attempts: %w", key, maxAttempts, lastErr)
}

func (s *Service) fetchOneAttempt(ctx context.Context, key, localPath string, expectedSize int64, expectedSHA string) error {
	rc, objectSize, err := s.Storage.Get(ctx, key)
	if err != nil {
		return err
	}
	if objectSize != expectedSize {
		_ = rc.Close()
		return fmt.Errorf("object size %d, want %d", objectSize, expectedSize)
	}

	part, err := os.CreateTemp(filepath.Dir(localPath), filepath.Base(localPath)+".part.*")
	if err != nil {
		_ = rc.Close()
		return fmt.Errorf("create partial: %w", err)
	}
	partPath := part.Name()
	defer os.Remove(partPath)
	if err := part.Chmod(0o600); err != nil {
		_ = part.Close()
		_ = rc.Close()
		return fmt.Errorf("secure partial: %w", err)
	}

	// Bound actual bytes as well as Content-Length, including cache reservations.
	hr := storage.NewHashingReader(io.LimitReader(rc, expectedSize+1))
	written, copyErr := io.Copy(part, hr)
	readCloseErr := rc.Close()
	writeCloseErr := part.Close()
	if copyErr != nil {
		return fmt.Errorf("read: %w", copyErr)
	}
	if readCloseErr != nil {
		return fmt.Errorf("close source: %w", readCloseErr)
	}
	if writeCloseErr != nil {
		return fmt.Errorf("close partial: %w", writeCloseErr)
	}
	if written != expectedSize || hr.Sum() != expectedSHA {
		return fmt.Errorf("integrity mismatch: size=%d/%d sha256=%s/%s",
			written, expectedSize, hr.Sum(), expectedSHA)
	}
	if err := os.Rename(partPath, localPath); err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	return nil
}

// CacheReaperLoop periodically deletes expired locality-cache entries
// AND any entries whose row says cached_host_id no longer points at us.
// Spawned at host startup.
func (s *Service) CacheReaperLoop(ctx context.Context) {
	interval := s.PauseCfg.ReconcileInterval
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.runCacheReaper(ctx)
		}
	}
}

func (s *Service) runCacheReaper(ctx context.Context) {
	if s.snapshotCache != nil {
		s.snapshotCache.reap()
	}
	candidates, err := s.Repo.LocalCacheCandidates(ctx, s.PauseCfg.HostID)
	if err != nil {
		log.WithContext(ctx).Warnf("[cache-reaper] list candidates: %v", err)
		return
	}
	now := time.Now().UTC()
	expired := 0
	for _, rec := range candidates {
		if rec.CachedUntil != nil && rec.CachedUntil.Before(now) {
			if s.evictLocalCache(ctx, rec.ID, true) {
				expired++
			}
		}
	}
	if expired > 0 {
		log.WithContext(ctx).Infof("[cache-reaper] evicted %d expired cache entries", expired)
	}
	// One retention budget covers pause bundles, capture checkpoints and downloads.
	s.reapDiskBudget(ctx)

	// On-disk sweep: any sb-* dir under PausedDir whose row says it's
	// cached elsewhere (or has been destroyed) is stale and must be
	// removed. LocalCacheCandidates above only returns rows where
	// cached_host_id = us, so a dir for a sandbox that resumed+paused
	// on a different host would never be reaped by candidate-walking
	// alone — it has to be discovered from disk.
	s.sweepOrphanedPausedDirs(ctx)
}

// sweepOrphanedPausedDirs walks PausedDir and asks control only whether this
// host should retain each directory. The cache-state endpoint derives the host
// from mTLS and returns one boolean, so paused rows and their secrets are never
// exposed merely to perform local housekeeping.
func (s *Service) sweepOrphanedPausedDirs(ctx context.Context) {
	entries, err := os.ReadDir(s.PauseCfg.PausedDir)
	if err != nil {
		return
	}
	removed := 0
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "sb-") {
			continue
		}
		id := e.Name()
		if !s.tryClaimTransition(id) {
			continue
		}
		keep, err := s.Repo.KeepLocalCache(ctx, id)
		if err == nil && !keep {
			if err := os.RemoveAll(filepath.Join(s.PauseCfg.PausedDir, id)); err == nil {
				removed++
			}
		}
		s.releaseTransition(id)
	}
	if removed > 0 {
		log.WithContext(ctx).Infof("[cache-reaper] swept %d orphaned paused dir(s)", removed)
	}
}

func (s *Service) evictLocalCache(ctx context.Context, id string, expiredOnly bool) bool {
	if !s.tryClaimTransition(id) {
		return false
	}
	defer s.releaseTransition(id)
	// Recheck through the host-scoped cache list; paused rows are deliberately
	// not readable via the general sandbox endpoint. A newly refreshed bundle
	// must not be expired using an older candidate list.
	candidates, err := s.Repo.LocalCacheCandidates(ctx, s.PauseCfg.HostID)
	if err != nil {
		return false
	}
	eligible := false
	for _, rec := range candidates {
		if rec.ID == id {
			eligible = !expiredOnly || (rec.CachedUntil != nil && rec.CachedUntil.Before(time.Now()))
			break
		}
	}
	if !eligible {
		return false
	}
	dir := filepath.Join(s.PauseCfg.PausedDir, id)
	if err := os.RemoveAll(dir); err != nil {
		log.WithContext(ctx).Warnf("[cache-reaper] remove %s: %v", dir, err)
		return false
	}
	if err := s.Repo.ClearLocalCache(ctx, id, s.PauseCfg.HostID); err != nil {
		log.WithContext(ctx).Warnf("[cache-reaper] clear cache row %s: %v", id, err)
	}
	return true
}

// ── helpers ─────────────────────────────────────────────────────────────

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func dirSize(root string) int64 {
	var total int64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// decompressZst expands a zstd-compressed file into dst, using
// sparse.Copy so all-zero blocks in the decompressed stream are turned
// into sparse holes on disk via Seek instead of Write. A 10 GB
// overlay that's mostly zeros lands on disk as a 10 GB sparse file
// with only its non-zero blocks allocated. Drops decompress wall
// time on the typical pause bundle from ~20s to ~100ms.
func decompressZst(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	_ = os.Chmod(dst, 0o600)
	defer out.Close()
	dec, err := zstd.NewReader(in)
	if err != nil {
		return err
	}
	defer dec.Close()
	_, err = sparse.Copy(out, dec)
	return err
}

// publishPauseManifest records completion only after all artifacts were written
// and hashed. Recovery never manufactures a new manifest from partial files.
func publishPauseManifest(path string, body []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".manifest-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
