package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/hosts/api"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/metrics"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/vm"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/vm/sparse"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/internal/storage"
	"github.com/NodeOps-app/createos-sandbox/internal/trace"
	"github.com/NodeOps-app/createos-sandbox/models"
	log "github.com/sirupsen/logrus"
)

// snapshotProfile records wall-clock phases, including the phase that fails.
// Phase names are fixed in code; identifiers belong in logs, never metric labels.
type snapshotProfile struct {
	trace *trace.Trace
	log   *log.Entry
	phase string
	stop  func()
}

func newSnapshotProfile(operation string, row models.Snapshot) *snapshotProfile {
	fields := log.Fields{"snapshot_id": row.ID, "sandbox_id": row.SandboxID, "snapshot_type": row.Type, "operation": operation}
	t := trace.Start("snapshot."+operation).Attr("snapshot_id", row.ID).Attr("sandbox_id", row.SandboxID)
	t.WithObserver(func(phase string, elapsed time.Duration) {
		metrics.SnapshotCapturePhaseSeconds.WithLabelValues(operation, phase).Observe(elapsed.Seconds())
	})
	return &snapshotProfile{trace: t, log: log.WithFields(fields)}
}

func (p *snapshotProfile) next(phase string) {
	if p.stop != nil {
		p.stop()
	}
	p.phase = phase
	p.log.WithField("phase", phase).Info("[snapshot] phase started")
	p.stop = p.trace.Phase(phase)
}

func (p *snapshotProfile) end(err error) {
	if p.stop != nil {
		p.stop()
	}
	outcome := "ok"
	if err != nil {
		outcome = "error"
		// Storage errors can contain signed URLs. Record the stage and error
		// classification here; the existing internal failure log retains details.
		p.log.WithField("phase", p.phase).WithField("error_type", fmt.Sprintf("%T", err)).Warn("[snapshot] phase failed")
	}
	p.trace.Attr("outcome", outcome).End()
}

// captureCheckpoint lives in a root-only directory, separate from the temporary
// slot-owned Firecracker output. Intent is durable BEFORE freezing the guest.
// Raw records only complete, fsynced files; absence means recapture is required.
type captureCheckpoint struct {
	SandboxID   string            `json:"sandbox_id"`
	PID         int               `json:"pid"`
	NeedsResume bool              `json:"needs_resume"`
	Raw         *storage.Manifest `json:"raw,omitempty"`
	Attempts    int               `json:"attempts"`
	NextAttempt time.Time         `json:"next_attempt"`
}

func validCaptureID(id string) bool {
	return strings.HasPrefix(id, models.SnapshotIDPrefix) && filepath.Base(id) == id && !strings.ContainsAny(id, "/\\")
}
func (s *Service) captureDir(id string) string { return filepath.Join(s.PauseCfg.PausedDir, id) }

func saveCaptureCheckpoint(dir string, cp *captureCheckpoint) error {
	body, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	if err = publishPauseManifest(filepath.Join(dir, "capture.json"), body); err != nil {
		return err
	}
	return syncCaptureDir(dir)
}
func syncCaptureDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func loadCaptureCheckpoint(dir string) (*captureCheckpoint, error) {
	b, err := os.ReadFile(filepath.Join(dir, "capture.json"))
	if err != nil {
		return nil, err
	}
	var cp captureCheckpoint
	err = json.Unmarshal(b, &cp)
	return &cp, err
}

// SnapshotFreezeIntents restores watchdog suppression before rehydrated VMs
// start their liveness watchers. Intent is root-owned and tied to the exact PID.
func SnapshotFreezeIntents(pausedDir string) map[string]int {
	out := map[string]int{}
	entries, err := os.ReadDir(pausedDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() || !validCaptureID(e.Name()) {
			continue
		}
		cp, err := loadCaptureCheckpoint(filepath.Join(pausedDir, e.Name()))
		if err == nil && cp.NeedsResume && cp.PID > 0 {
			out[cp.SandboxID] = cp.PID
		}
	}
	return out
}

// RecoverSnapshotGuests runs before slow pause recovery and storage operations.
// It does not need control connectivity: durable local intent identifies the
// exact surviving VM incarnation that may have been frozen by this worker.
func (s *Service) RecoverSnapshotGuests(ctx context.Context) {
	entries, err := os.ReadDir(s.PauseCfg.PausedDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !validCaptureID(e.Name()) {
			continue
		}
		dir := s.captureDir(e.Name())
		cp, err := loadCaptureCheckpoint(dir)
		if err != nil {
			log.WithError(err).Warn("[snapshot] cannot read recovery checkpoint")
			continue
		}
		if cp.NeedsResume {
			if err := s.resumeCapturedGuest(ctx, dir, cp); err != nil {
				log.WithError(err).WithField("snapshot_id", e.Name()).Error("[snapshot] guest recovery pending")
			}
		}
	}
}
func (s *Service) resumeCapturedGuest(ctx context.Context, dir string, cp *captureCheckpoint) error {
	if !cp.NeedsResume {
		return nil
	}
	if sb, ok := s.Mgr.Lookup(cp.SandboxID); ok && sb.FCPid == cp.PID {
		sb.Freezing.Store(true)
		recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		fc := vm.NewFirecrackerAPI(sb.ApiSocket)
		state, err := fc.VMState(recovery)
		if err != nil {
			return err
		}
		log.WithFields(log.Fields{"snapshot_id": filepath.Base(dir), "sandbox_id": cp.SandboxID, "pid": cp.PID, "vm_state": state}).Info("[snapshot] checking guest recovery")
		if state == vm.FirecrackerStatePaused {
			if err := fc.ResumeVM(recovery); err != nil {
				return err
			}
			state, err = fc.VMState(recovery)
			if err != nil {
				return err
			}
			if state != vm.FirecrackerStateRunning {
				return fmt.Errorf("guest has not resumed")
			}
		}
		sb.Freezing.Store(false)
	}
	// No matching manager entry means this VM incarnation has exited. Never
	// resume a later incarnation just because it has the same sandbox ID.
	cp.NeedsResume = false
	return saveCaptureCheckpoint(dir, cp)
}

// ReconcileSnapshots bounds work to one capture/upload per host at a time.
// Callers may invoke it every tick; TryLock prevents overlapping passes.
func (s *Service) ReconcileSnapshots(ctx context.Context) {
	if s.Storage == nil || !s.snapshotMu.TryLock() {
		return
	}
	defer s.snapshotMu.Unlock()
	s.RecoverSnapshotGuests(ctx)
	s.cleanupSnapshotCheckpoints(ctx)
	rows, err := s.Repo.ListSnapshotJobs(ctx)
	if err != nil {
		log.WithError(err).Warn("[snapshot] list pending captures")
		return
	}
	for _, row := range rows {
		if ctx.Err() != nil {
			return
		}
		if row.HostID == nil || *row.HostID != s.Host || row.Region != s.Region || !validCaptureID(row.ID) {
			continue
		}
		if err := s.reconcileSnapshot(ctx, row); err != nil {
			log.WithError(err).WithField("snapshot_id", row.ID).Warn("[snapshot] reconciliation deferred")
		}
	}
}

func (s *Service) reconcileSnapshot(ctx context.Context, row models.Snapshot) error {
	dir := s.captureDir(row.ID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := syncCaptureDir(s.PauseCfg.PausedDir); err != nil {
		return err
	}
	cp, err := loadCaptureCheckpoint(dir)
	if errors.Is(err, os.ErrNotExist) {
		cp = &captureCheckpoint{SandboxID: row.SandboxID}
		if err = saveCaptureCheckpoint(dir, cp); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if cp.SandboxID != row.SandboxID {
		return fmt.Errorf("checkpoint source mismatch")
	}
	if cp.NeedsResume {
		if err = s.resumeCapturedGuest(ctx, dir, cp); err != nil {
			return err
		}
	}
	if time.Now().Before(cp.NextAttempt) {
		return nil
	}
	// The deadline is based on durable row creation, so a restart cannot renew it.
	deadline := row.CreatedAt.Add(time.Hour)
	if time.Now().After(deadline) {
		log.WithFields(log.Fields{"snapshot_id": row.ID, "sandbox_id": row.SandboxID, "attempts": cp.Attempts, "deadline": deadline}).Warn("[snapshot] capture deadline exceeded")
		if err = s.Repo.SnapshotProgress(ctx, row.ID, proto.SnapshotActionFailed, proto.ControlSnapshotProgressReq{ErrorCode: proto.SnapshotErrorUploadTimeout}); err != nil {
			return err
		}
		return removeCaptureFiles(dir, row.SandboxID, row.ID)
	}
	attempt, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	// Protect local source transition operations while obtaining independent files.
	if !s.tryClaimTransition(row.SandboxID) {
		return nil
	}
	var released sync.Once
	release := func() { released.Do(func() { s.releaseTransition(row.SandboxID) }) }
	defer release()
	log.WithFields(log.Fields{"snapshot_id": row.ID, "sandbox_id": row.SandboxID, "host_id": s.Host, "attempt": cp.Attempts + 1, "age_ms": time.Since(row.CreatedAt).Milliseconds(), "raw_checkpoint": cp.Raw != nil}).Info("[snapshot] attempt started")
	// Existing checkpoints remain accounted by statfs across restarts. Reserve
	// future output before capture/compression; never evict an unuploaded bundle.
	needs := []diskNeed{{dir, 64 * 1024}} // publishing retry metadata only
	if !fileExists(filepath.Join(dir, storage.ArtifactManifest)) {
		if cp.Raw == nil {
			mem := int64(0)
			if row.Type == models.SnapshotTypeFull {
				mem = int64(row.MemMib)
			}
			needs = []diskNeed{{dir, snapshotWorkBytes(mem, row.DiskMib)},
				{filepath.Join(vm.SlotRuntimeDir(row.SandboxID), row.ID), int64(row.MemMib)*1024*1024 + 64*1024*1024}}
		} else if row.Type == models.SnapshotTypeFull {
			needs = []diskNeed{{dir, compressedWorkBytes(int64(row.MemMib) * 1024 * 1024)}}
		}
	}
	lease, reserveErr := s.reserveDiskWork(attempt, "snapshot capture", needs...)
	if reserveErr != nil {
		return reserveErr
	} // defer without freezing or losing checkpoint
	defer lease.release()
	err = s.captureAndUpload(attempt, row, dir, cp, release)
	if err == nil {
		return removeCaptureFiles(dir, row.SandboxID, row.ID)
	}
	if cp.NeedsResume {
		if recoveryErr := s.resumeCapturedGuest(ctx, dir, cp); recoveryErr != nil {
			return errors.Join(err, recoveryErr)
		}
	}
	// Discard incomplete Firecracker outputs only after recovery succeeded.
	// Completed independent checkpoints under dir remain available for retry.
	if err := os.RemoveAll(filepath.Join(vm.SlotRuntimeDir(row.SandboxID), row.ID)); err != nil {
		return err
	}
	cp.Attempts++
	cp.NextAttempt = time.Now().Add(time.Duration(1<<min(cp.Attempts, 8)) * time.Second)
	if saveErr := saveCaptureCheckpoint(dir, cp); saveErr != nil {
		return errors.Join(err, saveErr)
	}
	log.WithFields(log.Fields{"snapshot_id": row.ID, "sandbox_id": row.SandboxID, "attempt": cp.Attempts, "next_attempt": cp.NextAttempt, "deadline": deadline}).Warn("[snapshot] retry scheduled")
	return err
}

func (s *Service) captureAndUpload(ctx context.Context, row models.Snapshot, dir string, cp *captureCheckpoint, release func()) (retErr error) {
	profile := newSnapshotProfile("prepare_upload", row)
	defer func() { profile.end(retErr) }()
	profile.next("local_checkpoint")

	full := row.Type == models.SnapshotTypeFull
	manifestPath := filepath.Join(dir, storage.ArtifactManifest)
	body, readErr := os.ReadFile(manifestPath)
	var manifest *storage.Manifest
	var err error
	if readErr == nil {
		manifest, err = storage.ParseCaptureManifest(body, full)
		if err != nil {
			return err
		}
		if err = verifyCaptureFiles(dir, manifest); err != nil {
			return err
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	if manifest == nil {
		if cp.Raw == nil {
			if row.CapturedAt != nil {
				return s.failCapture(ctx, row, proto.SnapshotErrorCheckpointMissing)
			}
			profile.next("source_lookup")
			src, e := s.Repo.SnapshotSource(ctx, row.ID)
			if e != nil {
				return e
			}
			if src == nil {
				return s.failCapture(ctx, row, proto.SnapshotErrorSourceUnavailable)
			}
			if src.Status == models.StatusRunning {
				sb, ok := s.Mgr.Lookup(row.SandboxID)
				if !ok {
					return s.failCapture(ctx, row, proto.SnapshotErrorSourceUnavailable)
				}
				profile.next("capture_running")
				if err = s.captureRunning(ctx, row, dir, cp, sb); err != nil {
					return err
				}
			} else {
				return s.failCapture(ctx, row, proto.SnapshotErrorSourceUnavailable)
			}
		}
		if manifest == nil {
			profile.next("verify_raw")
			if err = verifyRawCapture(dir, cp.Raw, full); err != nil {
				return err
			}
			manifest = &storage.Manifest{FirecrackerBuild: cp.Raw.FirecrackerBuild, Version: storage.ManifestVersion, Encryption: storage.EncryptionMeta{Mode: "none"}, Artifacts: map[string]storage.ArtifactDescriptor{}, OriginalOverlayPath: cp.Raw.OriginalOverlayPath, OriginalRootfsPath: cp.Raw.OriginalRootfsPath, CPUVendor: cp.Raw.CPUVendor, CPUFamily: cp.Raw.CPUFamily}
			manifest.Artifacts[storage.ArtifactOverlay] = cp.Raw.Artifacts[storage.ArtifactOverlay]
			if full {
				profile.next("compress_memory")
				mem, err := s.compressAndHash(filepath.Join(dir, "memfile"), filepath.Join(dir, storage.ArtifactMemfile))
				if err != nil {
					return err
				}
				if err = syncCaptureFile(filepath.Join(dir, storage.ArtifactMemfile)); err != nil {
					return err
				}
				manifest.Artifacts[storage.ArtifactMemfile] = mem
				manifest.Artifacts[storage.ArtifactVMState] = cp.Raw.Artifacts[storage.ArtifactVMState]
			}
		}
		profile.next("publish_checkpoint")
		body, err = json.Marshal(manifest)
		if err != nil {
			return err
		}
		if _, err = storage.ParseCaptureManifest(body, full); err != nil {
			return err
		}
		if err = publishPauseManifest(manifestPath, body); err != nil {
			return err
		}
		if err = syncCaptureDir(dir); err != nil {
			return err
		}
	}
	// This acknowledgement releases capture conflicts only after the independent
	// files are durable and any running guest has been resumed.
	if row.CapturedAt == nil {
		profile.next("report_captured")
		if err = s.Repo.SnapshotProgress(ctx, row.ID, proto.SnapshotActionCaptured, proto.ControlSnapshotProgressReq{}); err != nil {
			return err
		}
	}
	// No live VM files are accessed after this point. User deletion is safe.
	release()
	profile.trace.Attr("bytes", fmt.Sprint(captureSize(manifest)))
	upload, cancel := context.WithTimeout(ctx, pauseUploadTimeout(captureSize(manifest)))
	defer cancel()
	for name, desc := range manifest.Artifacts {
		profile.next("upload." + name)
		key := storage.BundlePrefix(row.ID) + name
		if err = s.uploadFile(upload, key, filepath.Join(dir, name), desc); err != nil {
			return err
		}
		// Verify remote bytes, bypassing the locality cache. A successful local read
		// is not evidence that upload completed on the object store.
		profile.next("verify_remote." + name)
		st := s.Storage
		if cache, ok := st.(*storage.LocalCache); ok {
			st = cache.Underlying
		}
		rc, n, e := st.Get(upload, key)
		if e != nil {
			return e
		}
		hr := storage.NewHashingReader(rc)
		written, e := io.Copy(io.Discard, hr)
		closeErr := rc.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		if n != desc.Size || written != desc.Size || hr.Sum() != desc.SHA256 {
			return fmt.Errorf("uploaded artifact failed verification")
		}
	}
	profile.next("upload_manifest")
	if err = s.Storage.Put(upload, storage.BundlePrefix(row.ID)+storage.ArtifactManifest, bytes.NewReader(body), int64(len(body)), ""); err != nil {
		return err
	}
	profile.next("report_ready")
	if err = s.Repo.SnapshotProgress(ctx, row.ID, proto.SnapshotActionReady, proto.ControlSnapshotProgressReq{Manifest: body}); err != nil {
		return err
	}
	log.WithField("snapshot_id", row.ID).Info("[snapshot] capture ready")
	return nil
}

func (s *Service) failCapture(ctx context.Context, row models.Snapshot, code string) error {
	log.WithFields(log.Fields{"snapshot_id": row.ID, "sandbox_id": row.SandboxID, "reason": code}).Warn("[snapshot] marking capture failed")
	// Called only after any persisted freeze intent has been recovered.
	return s.Repo.SnapshotProgress(ctx, row.ID, proto.SnapshotActionFailed, proto.ControlSnapshotProgressReq{ErrorCode: code})
}
func captureSize(m *storage.Manifest) int64 {
	var n int64
	for _, a := range m.Artifacts {
		n += a.Size
	}
	return n
}
func syncCaptureFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("capture artifact is not regular")
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func verifyCaptureFiles(dir string, m *storage.Manifest) error {
	for name, a := range m.Artifacts {
		if name != storage.ArtifactOverlay && name != storage.ArtifactMemfile && name != storage.ArtifactVMState {
			return fmt.Errorf("unexpected capture artifact")
		}
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("capture artifact is not regular")
		}
		got, err := hashFile(path)
		if err != nil {
			return err
		}
		if got != a {
			return fmt.Errorf("capture checkpoint checksum mismatch")
		}
	}
	return sparse.ValidateArchive(filepath.Join(dir, storage.ArtifactOverlay))
}
func verifyRawCapture(dir string, m *storage.Manifest, full bool) error {
	if m == nil {
		return fmt.Errorf("missing raw checkpoint")
	}
	names := []string{storage.ArtifactOverlay}
	if full {
		names = append(names, "memfile", storage.ArtifactVMState)
	}
	if len(m.Artifacts) != len(names) {
		return fmt.Errorf("invalid raw checkpoint")
	}
	for _, name := range names {
		a, ok := m.Artifacts[name]
		if !ok {
			return fmt.Errorf("missing raw artifact")
		}
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("raw artifact is not regular")
		}
		got, err := hashFile(path)
		if err != nil {
			return err
		}
		if got != a {
			return fmt.Errorf("raw checkpoint checksum mismatch")
		}
	}
	return sparse.ValidateArchive(filepath.Join(dir, storage.ArtifactOverlay))
}

func (s *Service) captureRunning(ctx context.Context, row models.Snapshot, dir string, cp *captureCheckpoint, sb *vm.Sandbox) (retErr error) {
	profile := newSnapshotProfile("capture", row)
	defer func() { profile.end(retErr) }()
	profile.next("prepare")
	var build string
	if row.Type == models.SnapshotTypeFull {
		var err error
		build, err = s.Mgr.SnapshotFirecrackerBuild(sb)
		if err != nil {
			return err
		}
	}
	if sb.FCPid <= 0 {
		return fmt.Errorf("capture source has no process identity")
	}
	// Firecracker can write only inside its runtime slot. Durable checkpoints stay
	// root-owned; the VM never receives write access to capture.json or manifests.
	rawDir := filepath.Join(vm.SlotRuntimeDir(sb.ID), row.ID)
	if err := os.MkdirAll(rawDir, 0700); err != nil {
		return err
	}
	if sb.Net != nil {
		s.Mgr.ChownForSlot(rawDir, sb.Net.VsockCID)
	}
	if row.Type == models.SnapshotTypeDisk {
		profile.next("guest_sync")
		syncCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		resp, err := sb.Exec(syncCtx, proto.ExecRequest{Cmd: "sync"})
		cancel()
		if err != nil {
			return err
		}
		if resp == nil || resp.ExitCode != 0 {
			return fmt.Errorf("guest disk flush failed")
		}
	}
	cp.PID = sb.FCPid
	cp.NeedsResume = true
	if err := saveCaptureCheckpoint(dir, cp); err != nil {
		return err
	}
	sb.Freezing.Store(true)
	defer func() {
		if cp.NeedsResume {
			profile.trace.Attr("capture_failure_phase", profile.phase)
			profile.next("rollback_resume")
			retErr = errors.Join(retErr, s.resumeCapturedGuest(ctx, dir, cp))
		}
	}()
	fc := vm.NewFirecrackerAPI(sb.ApiSocket)
	freeze, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	profile.next("pause")
	if err := fc.PauseVM(freeze); err != nil {
		return err
	}
	start := time.Now()
	// PauseVM stops vCPUs only. CreateSnapshot also drains asynchronous block
	// device work; disk-only captures need that barrier too. Their temporary
	// memory/state outputs are discarded rather than published.
	profile.next("firecracker_snapshot")
	if err := fc.CreateSnapshot(freeze, filepath.Join(rawDir, "memfile"), filepath.Join(rawDir, storage.ArtifactVMState)); err != nil {
		return err
	}
	profile.next("archive_disk")
	_, size, sha, err := sparse.WriteArchiveContext(freeze, sb.OverlayPath, filepath.Join(dir, storage.ArtifactOverlay))
	if err != nil {
		return err
	}
	if err = syncCaptureFile(filepath.Join(dir, storage.ArtifactOverlay)); err != nil {
		return err
	}
	profile.next("resume")
	if err = s.resumeCapturedGuest(ctx, dir, cp); err != nil {
		return err
	}
	log.WithField("snapshot_id", row.ID).WithField("freeze_ms", time.Since(start).Milliseconds()).Info("[snapshot] guest resumed")
	profile.next("persist_raw")
	if err = securePausedDir(rawDir); err != nil {
		return err
	}
	raw := &storage.Manifest{Artifacts: map[string]storage.ArtifactDescriptor{storage.ArtifactOverlay: {Size: size, SHA256: sha}}, OriginalOverlayPath: sb.OverlayPath}
	raw.OriginalRootfsPath, _ = s.Mgr.LookupRootfs(sb.Rootfs)
	raw.CPUVendor, raw.CPUFamily = s.CPUVendor, s.CPUFamily
	if row.Type == models.SnapshotTypeFull {
		raw.FirecrackerBuild = build
		profile.trace.Attr("firecracker_build", build)
		for _, name := range []string{"memfile", storage.ArtifactVMState} {
			src := filepath.Join(rawDir, name)
			info, err := os.Lstat(src)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("invalid Firecracker output")
			}
			// Rename is cheap when both paths share a filesystem. Copy otherwise;
			// the source guard remains held until both independent files are durable.
			dst := filepath.Join(dir, name)
			if err = os.Rename(src, dst); err != nil {
				in, e := os.Open(src)
				if e != nil {
					return e
				}
				out, e := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
				if e != nil {
					in.Close()
					return e
				}
				_, e = sparse.Copy(out, in)
				in.Close()
				closeErr := out.Close()
				if e != nil {
					return e
				}
				if closeErr != nil {
					return closeErr
				}
			}
			if err = syncCaptureFile(dst); err != nil {
				return err
			}
			desc, err := hashFile(dst)
			if err != nil {
				return err
			}
			raw.Artifacts[name] = desc
		}
	}
	cp.Raw = raw
	if err = saveCaptureCheckpoint(dir, cp); err != nil {
		return err
	}
	return os.RemoveAll(rawDir)
}

// Reap successful/failed local checkpoints even if the final RPC response was
// lost. Never infer completion from absence in a bounded pending-jobs list.
func (s *Service) cleanupSnapshotCheckpoints(ctx context.Context) {
	entries, err := os.ReadDir(s.PauseCfg.PausedDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !validCaptureID(e.Name()) {
			continue
		}
		dir := s.captureDir(e.Name())
		cp, err := loadCaptureCheckpoint(dir)
		if err != nil || cp.NeedsResume {
			continue
		}
		row, err := s.Repo.GetSnapshotJob(ctx, e.Name())
		if err != nil {
			continue
		}
		if row == nil || row.Status != models.SnapshotStatusCreating {
			if err := removeCaptureFiles(dir, cp.SandboxID, e.Name()); err != nil {
				log.WithError(err).WithField("snapshot_id", e.Name()).Warn("[snapshot] local cleanup failed")
			}
		}
	}
}

func removeCaptureFiles(dir, source, id string) error {
	if filepath.Base(source) != source || strings.ContainsAny(source, "/\\") || !validCaptureID(id) {
		return fmt.Errorf("invalid capture cleanup identity")
	}
	if err := os.RemoveAll(filepath.Join(vm.SlotRuntimeDir(source), id)); err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

// createFromUserSnapshot uses only the restore descriptor on the creating row
// assigned to this host. Public callers cannot choose bucket keys or host paths.
// Every restore expands into its new VM's runtime directory, never the shared
// source bundle or another VM's writable overlay.
func (s *Service) createFromUserSnapshot(ctx context.Context, caller string, req api.CreateReq, vmReq vm.CreateRequest) (_ *vm.CreateResult, retErr error) {
	if s.Storage == nil || vmReq.ID == "" || req.SnapshotID == nil || !validCaptureID(*req.SnapshotID) {
		return nil, fmt.Errorf("%w: snapshot restore is unavailable", api.ErrInvalidRequest)
	}
	row, err := s.loadOwned(ctx, vmReq.ID, caller)
	if err != nil {
		return nil, err
	}
	if row.Status != models.StatusCreating || row.HostID == nil || *row.HostID != s.Host || row.SnapshotID == nil || *row.SnapshotID != *req.SnapshotID || row.Shape != req.Shape || row.DiskMib != req.DiskMib || row.Rootfs == nil || *row.Rootfs != vmReq.Rootfs {
		return nil, fmt.Errorf("%w: snapshot restore assignment changed", api.ErrInvalidRequest)
	}
	var decoded storage.Manifest
	if err := json.Unmarshal(row.SnapshotManifest, &decoded); err != nil {
		return nil, err
	}
	_, full := decoded.Artifacts[storage.ArtifactMemfile]
	manifest, err := storage.ParseCaptureManifest(row.SnapshotManifest, full)
	if err != nil {
		return nil, err
	}
	if full && manifest.CPUVendor != "" && manifest.CPUVendor != s.CPUVendor {
		return nil, fmt.Errorf("%w: snapshot is incompatible with this host", api.ErrInfrastructure)
	}
	profile := newSnapshotProfile("restore", models.Snapshot{ID: *row.SnapshotID, SandboxID: row.ID})
	defer func() { profile.end(retErr) }()
	start := time.Now()
	releaseRuntime := s.Mgr.HoldRuntime(row.ID)
	defer releaseRuntime()
	if !s.tryClaimTransition(row.ID) {
		return nil, fmt.Errorf("%w: sandbox is busy", api.ErrInvalidRequest)
	}
	defer s.releaseTransition(row.ID)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	dir := filepath.Join(vm.SlotRuntimeDir(row.ID), "restore")
	var compressed int64
	for _, a := range manifest.Artifacts {
		compressed += a.Size
	}
	memMiB := int64(0)
	if full {
		memMiB = int64(row.MemMib)
	}
	lease, err := s.reserveDiskWork(ctx, "snapshot restore", diskNeed{vm.SlotRuntimeDir(row.ID), compressed + (memMiB+row.DiskMib)*1024*1024 + 64*1024*1024})
	if err != nil {
		return nil, fmt.Errorf("%w: snapshot working space unavailable", api.ErrInfrastructure)
	}
	defer lease.release()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(vm.SlotRuntimeDir(row.ID))
		}
	}()
	for name := range manifest.Artifacts {
		profile.next("download." + name)
		if err := s.fetchSnapshotArtifact(ctx, name, filepath.Join(dir, name), storage.BundlePrefix(*row.SnapshotID)+name, manifest, req.SnapshotCache); err != nil {
			return nil, err
		}
	}
	s.rememberSnapshot(*row.SnapshotID, manifest)
	profile.next("expand_disk")
	overlay := filepath.Join(vm.SlotRuntimeDir(row.ID), "overlay.ext4")
	if err := sparse.ReadArchive(filepath.Join(dir, storage.ArtifactOverlay), overlay); err != nil {
		return nil, err
	}
	info, err := os.Stat(overlay)
	if err != nil {
		return nil, err
	}
	diskBytes := row.DiskMib * 1024 * 1024
	if info.Size() > diskBytes || (full && info.Size() != diskBytes) {
		return nil, fmt.Errorf("snapshot disk size does not match restore size")
	}
	if !full && info.Size() < diskBytes {
		profile.next("grow_disk")
		// Recover an unmounted captured ext4 before resizing its private copy.
		if err := exec.CommandContext(ctx, "e2fsck", "-p", "-f", overlay).Run(); err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				return nil, fmt.Errorf("check snapshot disk: %w", err)
			}
		}
		if err := os.Truncate(overlay, diskBytes); err != nil {
			return nil, err
		}
		if err := exec.CommandContext(ctx, "resize2fs", overlay).Run(); err != nil {
			return nil, fmt.Errorf("grow snapshot disk: %w", err)
		}
	}
	var result *vm.CreateResult
	if full {
		profile.next("expand_memory")
		mem := filepath.Join(dir, "memfile")
		if err := decompressZst(filepath.Join(dir, storage.ArtifactMemfile), mem); err != nil {
			return nil, err
		}
		profile.next("resume")
		sb, err := s.Mgr.ResumeFromSnapshot(ctx, vm.ResumeSpec{
			FirecrackerBuild: manifest.FirecrackerBuild,
			ID:               row.ID, Name: vmReq.Name, MemPath: mem, VMStatePath: filepath.Join(dir, storage.ArtifactVMState), OverlayPath: overlay,
			VMStateOverlayPath: manifest.OriginalOverlayPath, Shape: row.Shape, Rootfs: vmReq.Rootfs, VCPU: row.VCPU, MemMib: row.MemMib, DiskMib: row.DiskMib,
			Egress: vmReq.Egress, SecretToken: vmReq.SecretToken, Envs: vmReq.Envs, BandwidthQuota: vmReq.BandwidthQuotaBytes, Disks: vmReq.Disks,
		})
		if err != nil {
			return nil, err
		}
		// A TCP listener alone does not prove the restored agent accepted its
		// new identity. Probe with the new secret before publishing running.
		profile.next("authenticate_guest")
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, ok := s.Mgr.SandboxGuestMemUsedBytes(sb.ID); ok {
				break
			}
			if ctx.Err() != nil || time.Now().After(deadline) {
				_ = s.Mgr.Destroy(sb.ID)
				return nil, fmt.Errorf("restored agent did not accept new identity")
			}
			time.Sleep(50 * time.Millisecond)
		}
		sb.SetCachedOwner(caller)
		result = &vm.CreateResult{Sandbox: sb, Mode: "snapshot", SpawnMs: float64(time.Since(start).Microseconds()) / 1000}
	} else {
		profile.next("boot_disk")
		vmReq.RestoreOverlay = overlay
		result, err = s.Mgr.Create(ctx, vmReq)
		if err != nil {
			return nil, err
		}
		result.Mode = "disk-snapshot"
		result.SpawnMs = float64(time.Since(start).Microseconds()) / 1000
	}
	complete = true
	for name := range manifest.Artifacts {
		// Full restore still has the raw vmstate/memory open under runtime.
		if name != storage.ArtifactVMState {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
	return result, nil
}
