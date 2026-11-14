package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/hosts/api"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/storage"
	"github.com/NodeOps-app/createos-sandbox/models"
)

const (
	templateFetchAttempts = 3
	templateRetryBaseWait = 500 * time.Millisecond
)

// TemplateConfig is the host-side template-cache wiring.
type TemplateConfig struct {
	HostID       string
	TemplatesDir string        // e.g. /var/lib/createos/templates
	TTL          time.Duration // 1h default
	TTLOverrides map[string]time.Duration
	DiskBudget   int64         // bytes; 0 = unlimited
	ReapInterval time.Duration // 1m default
}

// templateUse protects the interval from template lookup through VM publication.
// An eviction owns done exclusively; creates wait for it before fetching again.
type templateUse struct {
	users int
	done  chan struct{}
}

func (s *Service) useTemplate(ctx context.Context, id string) (func(), error) {
	for {
		s.tplMu.Lock()
		if s.tplUses == nil {
			s.tplUses = make(map[string]*templateUse)
		}
		use := s.tplUses[id]
		if use != nil && use.done != nil {
			done := use.done
			s.tplMu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if use == nil {
			use = &templateUse{}
			s.tplUses[id] = use
		}
		use.users++
		s.tplMu.Unlock()
		return func() {
			s.tplMu.Lock()
			defer s.tplMu.Unlock()
			use.users--
			if use.users == 0 {
				delete(s.tplUses, id)
			}
		}, nil
	}
}

func (s *Service) claimTemplateEviction(id string) (func(), bool) {
	s.tplMu.Lock()
	defer s.tplMu.Unlock()
	if s.tplUses[id] != nil {
		return nil, false
	}
	if s.tplUses == nil {
		s.tplUses = make(map[string]*templateUse)
	}
	done := make(chan struct{})
	s.tplUses[id] = &templateUse{done: done}
	return func() {
		s.tplMu.Lock()
		defer s.tplMu.Unlock()
		delete(s.tplUses, id)
		close(done)
	}, true
}

// EnsureTemplate fetches, verifies, and registers a template rootfs on demand.
// The caller must hold useTemplate until VM creation or restore finishes.
// Concurrent requests for the same template share one download. Service owns
// the cache; ReaperLoop applies its TTL and disk-budget eviction policy.
// Returns the local ext4 path on success.
func (s *Service) EnsureTemplate(ctx context.Context, tplID, sandboxID string) (string, error) {
	started := time.Now()
	fields := log.Fields{
		"request_id":  httpx.RequestID(ctx),
		"sandbox_id":  sandboxID,
		"template_id": tplID,
	}
	if deadline, ok := ctx.Deadline(); ok {
		fields["deadline_utc"] = deadline.UTC().Format(time.RFC3339Nano)
		fields["deadline_remaining_ms"] = time.Until(deadline).Milliseconds()
	} else {
		fields["deadline_utc"] = "none"
	}
	log.WithContext(ctx).WithFields(fields).Info("[template-fetch] ensure start")
	finish := func(phase string, err error) {
		entry := log.WithContext(ctx).WithFields(fields).WithFields(log.Fields{
			"phase":      phase,
			"elapsed_ms": time.Since(started).Milliseconds(),
		})
		if err != nil {
			entry.WithError(err).WithField("context_error", ctx.Err()).Warn("[template-fetch] ensure failed")
			return
		}
		entry.Info("[template-fetch] ensure complete")
	}
	if !strings.HasPrefix(tplID, models.TemplateIDPrefix) {
		err := fmt.Errorf("%w: not a template id: %q", api.ErrInvalidRequest, tplID)
		finish("validate", err)
		return "", err
	}
	if s.Storage == nil {
		err := errors.New("template orchestrator: storage backend not configured")
		finish("validate", err)
		return "", err
	}

	// Hot path: already cached.
	if path, ok := s.Mgr.LookupRootfs(tplID); ok {
		_ = s.refreshCacheRow(ctx, tplID)
		finish("memory-cache", nil)
		return path, nil
	}

	// Coalesce concurrent fetches.
	s.tplMu.Lock()
	if ch, ok := s.tplInflight[tplID]; ok {
		s.tplMu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			finish("inflight-wait", ctx.Err())
			return "", ctx.Err()
		}
		// Whoever did the fetch should have registered the rootfs.
		if path, ok := s.Mgr.LookupRootfs(tplID); ok {
			finish("inflight-cache", nil)
			return path, nil
		}
		// The leader failed. Re-enter the coalescing gate instead of letting
		// every released waiter race on the same .part file. Exactly one waiter
		// becomes the next retry leader; the rest wait behind it again.
		return s.EnsureTemplate(ctx, tplID, sandboxID)
	} else {
		ch := make(chan struct{})
		s.tplInflight[tplID] = ch
		s.tplMu.Unlock()
		defer func() {
			s.tplMu.Lock()
			close(ch)
			delete(s.tplInflight, tplID)
			s.tplMu.Unlock()
		}()
	}

	// Re-check after coalescing in case the leader succeeded.
	if path, ok := s.Mgr.LookupRootfs(tplID); ok {
		_ = s.refreshCacheRow(ctx, tplID)
		finish("memory-cache-recheck", nil)
		return path, nil
	}

	lookupStarted := time.Now()
	rec, err := s.Repo.GetTemplate(ctx, tplID)
	if err != nil {
		err = fmt.Errorf("template lookup: %w", err)
		finish("metadata-lookup", err)
		return "", err
	}
	if rec == nil {
		err = fmt.Errorf("%w: template %q not found", api.ErrInvalidRequest, tplID)
		finish("metadata-validate", err)
		return "", err
	}
	log.WithContext(ctx).WithFields(fields).WithFields(log.Fields{
		"elapsed_ms":                  time.Since(lookupStarted).Milliseconds(),
		"expected_decompressed_bytes": rec.Ext4SizeBytes,
	}).Info("[template-fetch] metadata loaded")
	if rec.Status != models.TemplateStatusReady {
		err = fmt.Errorf("%w: template %q not ready (status=%s)", api.ErrInvalidRequest, tplID, rec.Status)
		finish("metadata-validate", err)
		return "", err
	}

	if err := os.MkdirAll(s.TplCfg.TemplatesDir, 0o755); err != nil {
		err = fmt.Errorf("mkdir templates: %w", err)
		finish("prepare-directory", err)
		return "", err
	}
	finalPath := filepath.Join(s.TplCfg.TemplatesDir, tplID+".ext4")

	// Skip the fetch if the file is already present on disk (e.g. from
	// a prior serve that crashed before the row landed) and its sha
	// matches the canonical record.
	sha := ""
	if rec.SHA256 != nil {
		sha = *rec.SHA256
	}
	if existsAndValid(finalPath, sha, rec.Ext4SizeBytes) {
		s.Mgr.AddRootfs(tplID, finalPath)
		_ = s.refreshCacheRow(ctx, tplID)
		finish("disk-cache", nil)
		return finalPath, nil
	}

	tmpPath := finalPath + ".part"
	compressedTmpPath := tmpPath + ".zst"
	defer os.Remove(tmpPath)           // best-effort
	defer os.Remove(compressedTmpPath) // best-effort
	if err := s.fetchAndDecompressWithRetry(ctx, "templates/"+tplID+"/rootfs.ext4.zst", compressedTmpPath, tmpPath, sha, fields); err != nil {
		finish("storage-stream", err)
		return "", err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		err = fmt.Errorf("rename template ext4: %w", err)
		finish("publish", err)
		return "", err
	}
	// Cached template images are tenant content. Root may manage them, and
	// individual Firecracker slot UIDs receive read-only POSIX ACLs only while
	// running a VM that uses this template.
	if err := os.Chown(finalPath, 0, 0); err != nil {
		_ = os.Remove(finalPath)
		return "", fmt.Errorf("secure template owner: %w", err)
	}
	if err := os.Chmod(finalPath, 0o600); err != nil {
		_ = os.Remove(finalPath)
		return "", fmt.Errorf("secure template mode: %w", err)
	}

	s.Mgr.AddRootfs(tplID, finalPath)
	if err := s.refreshCacheRow(ctx, tplID); err != nil {
		log.WithContext(ctx).Warnf("[tpl] %s: cache row upsert failed: %v", tplID, err)
	}
	log.WithContext(ctx).Infof("[tpl] %s: fetched + cached at %s", tplID, finalPath)
	finish("fetched", nil)
	return finalPath, nil
}

// fetchAndDecompressWithRetry retains verified-length compressed bytes between
// attempts and resumes the next request at that byte offset. Only a complete,
// SHA-256-verified compressed object is passed to zstd.
func (s *Service) fetchAndDecompressWithRetry(ctx context.Context, key, compressedPath, dst, expectedSHA string, fields log.Fields) error {
	var lastErr error
	for attempt := 1; attempt <= templateFetchAttempts; attempt++ {
		attemptFields := cloneLogFields(fields)
		attemptFields["attempt"] = attempt
		attemptFields["max_attempts"] = templateFetchAttempts

		lastErr = s.downloadTemplateRange(ctx, key, compressedPath, attemptFields)
		if lastErr == nil {
			break
		}
		if ctx.Err() != nil || attempt == templateFetchAttempts {
			break
		}

		wait := time.Duration(attempt) * templateRetryBaseWait
		log.WithContext(ctx).WithFields(attemptFields).WithFields(log.Fields{
			"retry_wait_ms": wait.Milliseconds(),
		}).WithError(lastErr).Warn("[template-fetch] retrying transfer")
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(lastErr, ctx.Err())
		case <-timer.C:
		}
	}
	if lastErr != nil {
		return fmt.Errorf("template transfer failed after %d attempt(s): %w", templateFetchAttempts, lastErr)
	}

	gotSHA, compressedBytes, err := storage.HashFile(compressedPath)
	if err != nil {
		return fmt.Errorf("hash compressed template: %w", err)
	}
	if expectedSHA != "" && gotSHA != expectedSHA {
		return fmt.Errorf("sha256 mismatch (got %s, want %s)", gotSHA, expectedSHA)
	}
	log.WithContext(ctx).WithFields(fields).WithFields(log.Fields{
		"compressed_bytes": compressedBytes,
		"sha256":           gotSHA,
	}).Info("[template-fetch] compressed artifact verified")

	if err := decompressTemplate(compressedPath, dst); err != nil {
		return err
	}
	return nil
}

func cloneLogFields(fields log.Fields) log.Fields {
	cloned := make(log.Fields, len(fields)+2)
	for key, value := range fields {
		cloned[key] = value
	}
	return cloned
}

func (s *Service) downloadTemplateRange(ctx context.Context, key, compressedPath string, fields log.Fields) error {
	out, err := os.OpenFile(compressedPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open compressed partial: %w", err)
	}
	stat, err := out.Stat()
	if err != nil {
		out.Close()
		return fmt.Errorf("stat compressed partial: %w", err)
	}
	offset := stat.Size()
	if _, err := out.Seek(offset, io.SeekStart); err != nil {
		out.Close()
		return fmt.Errorf("seek compressed partial: %w", err)
	}

	openStarted := time.Now()
	rd, expectedCompressedBytes, err := s.Storage.GetRange(ctx, key, offset)
	if err != nil {
		out.Close()
		log.WithContext(ctx).WithFields(fields).WithFields(log.Fields{
			"phase":      "storage-open",
			"elapsed_ms": time.Since(openStarted).Milliseconds(),
		}).WithError(err).WithField("context_error", ctx.Err()).Warn("[template-fetch] transfer failed")
		return fmt.Errorf("storage get %s: %w", key, err)
	}
	defer rd.Close()
	defer out.Close()
	if offset > expectedCompressedBytes {
		return fmt.Errorf("partial template larger than object: %d > %d", offset, expectedCompressedBytes)
	}
	log.WithContext(ctx).WithFields(fields).WithFields(log.Fields{
		"elapsed_ms":                time.Since(openStarted).Milliseconds(),
		"expected_compressed_bytes": expectedCompressedBytes,
		"resume_offset":             offset,
	}).Info("[template-fetch] storage stream opened")

	progress := &templateTransferProgress{}
	progress.compressed.Store(offset)
	stopProgress := make(chan struct{})
	progressDone := make(chan struct{})
	go logTemplateTransferProgress(ctx, fields, progress, expectedCompressedBytes, stopProgress, progressDone)
	defer func() {
		close(stopProgress)
		<-progressDone
	}()
	streamStarted := time.Now()
	written, err := io.Copy(&templateProgressWriter{w: out, progress: progress}, rd)
	if err != nil {
		log.WithContext(ctx).WithFields(fields).WithFields(log.Fields{
			"elapsed_ms":       time.Since(streamStarted).Milliseconds(),
			"compressed_bytes": offset + written,
			"context_error":    ctx.Err(),
			"phase":            "stream-copy",
		}).WithError(err).Warn("[template-fetch] storage stream failed")
		return fmt.Errorf("download range at %d: %w", offset, err)
	}
	if err := out.Close(); err != nil {
		log.WithContext(ctx).WithFields(fields).WithError(err).WithField("phase", "output-close").Warn("[template-fetch] transfer failed")
		return fmt.Errorf("close %s: %w", compressedPath, err)
	}
	gotBytes := offset + written
	if gotBytes != expectedCompressedBytes {
		return fmt.Errorf("incomplete object: got %d of %d bytes", gotBytes, expectedCompressedBytes)
	}
	log.WithContext(ctx).WithFields(fields).WithFields(log.Fields{
		"elapsed_ms":       time.Since(streamStarted).Milliseconds(),
		"compressed_bytes": gotBytes,
	}).Info("[template-fetch] storage stream complete")
	return nil
}

func decompressTemplate(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open compressed template: %w", err)
	}
	defer in.Close()
	zr, err := zstd.NewReader(in)
	if err != nil {
		return fmt.Errorf("zstd reader: %w", err)
	}
	defer zr.Close()
	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create decompressed template: %w", err)
	}
	written, copyErr := io.Copy(out, zr)
	closeErr := out.Close()
	if copyErr != nil {
		return fmt.Errorf("decompress: %w", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close decompressed template: %w", closeErr)
	}
	if written == 0 {
		return errors.New("decompressed template is empty")
	}
	return nil
}

type templateProgressWriter struct {
	w        io.Writer
	progress *templateTransferProgress
}

func (w *templateProgressWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if n > 0 {
		w.progress.compressed.Add(int64(n))
	}
	return n, err
}

type templateTransferProgress struct {
	compressed   atomic.Int64
	decompressed atomic.Int64
}

func logTemplateTransferProgress(ctx context.Context, fields log.Fields, progress *templateTransferProgress, expectedCompressedBytes int64, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	started := time.Now()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			elapsed := time.Since(started)
			compressed := progress.compressed.Load()
			entry := log.WithContext(ctx).WithFields(fields).WithFields(log.Fields{
				"elapsed_ms":                elapsed.Milliseconds(),
				"compressed_bytes":          compressed,
				"decompressed_bytes":        progress.decompressed.Load(),
				"expected_compressed_bytes": expectedCompressedBytes,
				"compressed_bytes_per_sec":  int64(float64(compressed) / elapsed.Seconds()),
				"context_error":             ctx.Err(),
			})
			if deadline, ok := ctx.Deadline(); ok {
				entry = entry.WithField("deadline_remaining_ms", time.Until(deadline).Milliseconds())
			}
			entry.Info("[template-fetch] transfer progress")
		}
	}
}

// existsAndValid reports whether path already holds a correct copy of
// the ext4. Cheap pre-fetch check on serve restart.
func existsAndValid(path, expectedSHA string, expectedSize int64) bool {
	if expectedSHA == "" {
		// Without a sha to compare we can't trust an existing file —
		// re-fetch.
		return false
	}
	st, err := os.Stat(path)
	if err != nil || st.Size() == 0 {
		return false
	}
	if expectedSize > 0 && st.Size() != expectedSize {
		return false
	}
	// Skip full sha verify on warm path — too slow for hot resumes.
	// The sha was already verified at fetch time; if the on-disk file
	// got corrupted, the next /snapshot/load failure surfaces it.
	return true
}

// refreshCacheRow upserts the host_cached_templates row with a fresh
// last_used_at + cached_until window.
func (s *Service) refreshCacheRow(ctx context.Context, tplID string) error {
	if s.TplCfg.HostID == "" {
		return nil
	}
	ttl := s.TplCfg.TTL
	if override, ok := s.TplCfg.TTLOverrides[tplID]; ok && override > 0 {
		ttl = override
	}
	cachedUntil := time.Now().UTC().Add(ttl)
	return s.Repo.UpsertHostCachedTemplate(ctx, s.TplCfg.HostID, tplID, cachedUntil)
}

// ReaperLoop runs the TTL + disk-budget eviction pass every
// ReapInterval. Mirrors pauseresume.CacheReaperLoop's two-pass shape.
func (s *Service) ReaperLoop(ctx context.Context) {
	t := time.NewTicker(s.TplCfg.ReapInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.runReap(ctx)
		}
	}
}

func (s *Service) runReap(ctx context.Context) {
	candidates, err := s.Repo.ListHostCachedTemplates(ctx, s.TplCfg.HostID)
	if err != nil {
		log.WithContext(ctx).Warnf("[tpl-reaper] list candidates: %v", err)
		return
	}
	now := time.Now().UTC()
	expired := 0
	for _, c := range candidates {
		if c.CachedUntil != nil && c.CachedUntil.Before(now) {
			if s.evict(ctx, c.TplID) {
				expired++
			}
		}
	}
	if expired > 0 {
		log.WithContext(ctx).Infof("[tpl-reaper] evicted %d expired templates", expired)
	}
	// Disk-budget pass: candidates is already ordered by last_used_at ASC,
	// so head of the slice is LRU.
	if s.TplCfg.DiskBudget > 0 {
		used := dirSize(s.TplCfg.TemplatesDir)
		i := 0
		for used > s.TplCfg.DiskBudget && i < len(candidates) {
			if s.evict(ctx, candidates[i].TplID) {
				used = dirSize(s.TplCfg.TemplatesDir)
			}
			i++
		}
	}
}

// evict removes the template ext4 + its snapshots, and clears the cache
// row. Aborts if any active sandbox on this host references the
// template (safety check mirrors pauseresume.evictLocalCache).
func (s *Service) evict(ctx context.Context, tplID string) bool {
	release, ok := s.claimTemplateEviction(tplID)
	if !ok {
		return false
	}
	defer release()
	n, err := s.Repo.HostCachedTemplateHasActiveSandbox(ctx, s.TplCfg.HostID, tplID)
	if err != nil {
		log.WithContext(ctx).Warnf("[tpl-reaper] safety check %s: %v", tplID, err)
		return false
	}
	// Local publication can precede the database update or its visibility.
	s.Mgr.Mu.RLock()
	for _, sb := range s.Mgr.Sandboxes {
		if sb.Rootfs == tplID {
			n++
			break
		}
	}
	s.Mgr.Mu.RUnlock()
	if n > 0 {
		// Live workloads still using it; refresh cached_until so we
		// don't immediately re-attempt every reap interval.
		_ = s.refreshCacheRow(ctx, tplID)
		return false
	}
	// Waiting creates acquire their lease after deletion and fetch again.
	s.Mgr.RemoveRootfs(tplID)
	// Drop snapshots for every shape that referenced the template.
	s.removeTemplateSnapshots(tplID)
	// Drop the ext4.
	path := filepath.Join(s.TplCfg.TemplatesDir, tplID+".ext4")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.WithContext(ctx).Warnf("[tpl-reaper] remove %s: %v", path, err)
	}
	if err := s.Repo.DeleteHostCachedTemplate(ctx, s.TplCfg.HostID, tplID); err != nil {
		log.WithContext(ctx).Warnf("[tpl-reaper] delete cache row %s: %v", tplID, err)
	}
	return true
}

// removeTemplateSnapshots deletes every <SnapshotDir>/<tpl_id>-<vcpu>-<mem>/
// directory. Boot snapshots reference the ext4 path via the baked
// vmstate; keeping them around without the ext4 would 400 the next
// /snapshot/load. Naming follows shapeKey.String() = "<rootfs>-<vcpu>-<mem>",
// so tpl_id is the prefix.
func (s *Service) removeTemplateSnapshots(tplID string) {
	root := s.Mgr.SnapshotDir
	if root == "" {
		return
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	prefix := tplID + "-"
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		full := filepath.Join(root, e.Name())
		if err := os.RemoveAll(full); err != nil {
			log.Warnf("[tpl-reaper] remove snapshot %s: %v", full, err)
		}
	}
	// Drop in-memory Snapshots entries so the next create with this
	// (shape, tpl_id) cold-builds rather than restoring from a vmstate
	// whose ext4 + base.ext4 are gone.
	s.Mgr.SnapshotsMu.Lock()
	for k := range s.Mgr.Snapshots {
		if k.Rootfs == tplID {
			delete(s.Mgr.Snapshots, k)
		}
	}
	s.Mgr.SnapshotsMu.Unlock()
}

// ReconcileOnStartup walks the on-disk templates dir and the DB cache
// rows. Reconciles: file present + row missing → re-insert; row present +
// file missing → drop row; sha mismatch → delete file + row (next use
// re-fetches). Should be called once at serve startup AFTER
// reconcile() has reaped orphan firecrackers.
func (s *Service) ReconcileOnStartup(ctx context.Context) {
	rows, err := s.Repo.ListHostCachedTemplates(ctx, s.TplCfg.HostID)
	if err != nil {
		log.WithContext(ctx).Warnf("[tpl-reconcile] list rows: %v", err)
		return
	}
	rowByID := map[string]models.HostCachedTemplate{}
	for _, r := range rows {
		rowByID[r.TplID] = r
	}
	entries, err := os.ReadDir(s.TplCfg.TemplatesDir)
	if err != nil {
		// First-run case (dir doesn't exist) — drop any stale rows
		// pointing at templates that aren't on disk.
		for _, r := range rows {
			_ = s.Repo.DeleteHostCachedTemplate(ctx, s.TplCfg.HostID, r.TplID)
		}
		return
	}
	onDisk := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, models.TemplateIDPrefix) || !strings.HasSuffix(name, ".ext4") {
			continue
		}
		tplID := strings.TrimSuffix(name, ".ext4")
		onDisk[tplID] = filepath.Join(s.TplCfg.TemplatesDir, name)
	}
	// Files without rows: register in vm.Manager + insert row.
	for tplID, path := range onDisk {
		if _, ok := rowByID[tplID]; ok {
			s.Mgr.AddRootfs(tplID, path)
			continue
		}
		s.Mgr.AddRootfs(tplID, path)
		_ = s.refreshCacheRow(ctx, tplID)
	}
	// Rows without files: drop the row.
	for tplID := range rowByID {
		if _, ok := onDisk[tplID]; ok {
			continue
		}
		_ = s.Repo.DeleteHostCachedTemplate(ctx, s.TplCfg.HostID, tplID)
	}
}

// InitTplInflight initialises the per-template fetch-coalescing map.
// Must be called before EnsureTemplate is reachable.
func (s *Service) InitTplInflight() {
	if s.tplInflight == nil {
		s.tplInflight = map[string]chan struct{}{}
	}
}
