package service

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/internal/storage"
	log "github.com/sirupsen/logrus"
)

const snapshotDownloadTTL = 10 * time.Minute

// Only compressed, verified artifacts live here. No VM maps these files and
// no guest UID can traverse this directory. A restore always receives a private
// copy; changing its permissions or writable disk cannot modify another VM.
type snapshotDownloadCache struct {
	mu                  sync.Mutex
	dir                 string
	entries             map[string]*snapshotCacheEntry
	snapshots           map[string][]string
	used, budget, floor int64 // bytes; used includes in-flight reservations
	free                func() (int64, error)
}

type snapshotCacheEntry struct {
	path    string
	size    int64
	ready   chan struct{} // non-nil while downloading
	refs    int
	expires time.Time
}

// InitSnapshotDownloadCache is called once before serving. Old entries are
// disposable: clearing them on restart avoids trusting a half-written download
// or retaining bytes outside our in-memory accounting. Live VMs use private files.
func (s *Service) InitSnapshotDownloadCache(pausedDir, capacityDir string) error {
	var a, b syscall.Stat_t
	if err := syscall.Stat(pausedDir, &a); err != nil {
		return err
	}
	if err := syscall.Stat(capacityDir, &b); err != nil {
		return err
	}
	if a.Dev != b.Dev {
		return fmt.Errorf("cache and scheduler capacity must use the same filesystem")
	}
	dir := filepath.Join(pausedDir, "snapshot-download-cache")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	c := &snapshotDownloadCache{dir: dir, entries: make(map[string]*snapshotCacheEntry), snapshots: make(map[string][]string)}
	c.free = func() (int64, error) {
		var st syscall.Statfs_t
		if err := syscall.Statfs(dir, &st); err != nil {
			return 0, err
		}
		return int64(st.Bavail) * st.Bsize, nil
	}
	s.snapshotCache = c
	return nil
}

// removeLocked retains accounting on deletion failure. Active readers and
// pending writers cannot be evicted, including under disk pressure.
func (c *snapshotDownloadCache) removeLocked(key string, e *snapshotCacheEntry) bool {
	if e.ready != nil || e.refs != 0 {
		return false
	}
	if err := os.Remove(e.path); err != nil && !os.IsNotExist(err) {
		log.Warnf("[snapshot-cache] eviction failed: %v", err)
		return false
	}
	delete(c.entries, key)
	c.used -= e.size
	return true
}

func (c *snapshotDownloadCache) trimLocked(need int64) bool {
	now := time.Now()
	for key, e := range c.entries {
		if now.After(e.expires) {
			c.removeLocked(key, e)
		}
	}
	free, err := c.free()
	if err != nil {
		return false
	}
	// Disk free already includes completed cache files, but not the remaining
	// bytes of pending downloads. Count the whole reservation conservatively.
	pending := int64(0)
	for _, e := range c.entries {
		if e.ready != nil {
			pending += e.size
		}
	}
	for c.used+need > c.budget || free-need-pending < c.floor {
		var oldest *snapshotCacheEntry
		var oldestKey string
		for key, e := range c.entries {
			if e.refs == 0 && e.ready == nil && (oldest == nil || e.expires.Before(oldest.expires)) {
				oldest, oldestKey = e, key
			}
		}
		if oldest == nil || !c.removeLocked(oldestKey, oldest) {
			return false
		}
		free, err = c.free()
		if err != nil {
			return false
		}
	}
	return true
}

func (c *snapshotDownloadCache) reap() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.trimLocked(0)
	c.hintsLocked()
}

func (s *Service) fetchSnapshotArtifact(ctx context.Context, name, dest, key string, manifest *storage.Manifest, policy *proto.SnapshotCachePolicy) error {
	c := s.snapshotCache
	want := manifest.Artifacts[name]
	// Older control/scheduler builds supply no allowance: fail open to ordinary
	// uncached restore, never invent headroom on the host.
	if c == nil || policy == nil || policy.BudgetMiB <= 0 || policy.BudgetMiB > 20*1024 || policy.FreeFloorMiB < 0 || policy.FreeFloorMiB > 1<<40 || want.Size <= 0 {
		return s.fetchOne(ctx, name, dest, key, manifest)
	}
	// Include bucket object identity AND manifest hash/size. Authorization and
	// durable restore-assignment checks have already run before this function.
	cacheKey := snapshotArtifactCacheKey(key, want)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.mu.Lock()
		c.budget = min(policy.BudgetMiB*1024*1024, s.PauseCfg.LocalDiskBudget)
		c.floor = policy.FreeFloorMiB*1024*1024 + policy.BudgetMiB*1024*1024 - max(int64(0), c.budget)
		c.trimLocked(0)
		if e := c.entries[cacheKey]; e != nil {
			if e.ready != nil {
				ready := e.ready
				c.mu.Unlock()
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-ready:
					continue
				}
			}
			e.refs++
			c.mu.Unlock()
			err := copySnapshotCache(ctx, e.path, dest, want)
			c.mu.Lock()
			e.refs--
			if err != nil {
				e.expires = time.Time{}
				c.removeLocked(cacheKey, e)
			}
			c.mu.Unlock()
			if err == nil {
				log.WithContext(ctx).Infof("[snapshot-cache] hit key=%s artifact=%s bytes=%d", key, name, want.Size)
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.WithContext(ctx).Warnf("[snapshot-cache] read failed; fetching key=%s artifact=%s: %v", key, name, err)
			return s.fetchOne(ctx, name, dest, key, manifest)
		}
		if want.Size > c.budget || !c.trimLocked(want.Size) {
			c.mu.Unlock()
			log.WithContext(ctx).Infof("[snapshot-cache] bypass key=%s artifact=%s bytes=%d reason=disk_budget", key, name, want.Size)
			return s.fetchOne(ctx, name, dest, key, manifest)
		}
		var lease *diskLease
		if s.diskBudget != nil {
			var err error
			lease, err = s.diskBudget.reserve([]diskNeed{{filepath.Join(c.dir, cacheKey), want.Size + 4096}}, true, c.floor)
			if err != nil {
				c.mu.Unlock()
				log.WithContext(ctx).Infof("[snapshot-cache] bypass key=%s reason=shared_disk_budget", key)
				return s.fetchOne(ctx, name, dest, key, manifest)
			}
		}
		e := &snapshotCacheEntry{path: filepath.Join(c.dir, cacheKey), size: want.Size, ready: make(chan struct{}), refs: 1}
		c.entries[cacheKey] = e
		c.used += e.size
		c.mu.Unlock()
		log.WithContext(ctx).Infof("[snapshot-cache] miss key=%s artifact=%s bytes=%d", key, name, want.Size)
		err := s.fetchOne(ctx, name, e.path, key, manifest)
		lease.release()
		c.mu.Lock()
		ready := e.ready
		e.ready = nil
		e.expires = time.Now().Add(snapshotDownloadTTL)
		if err != nil {
			e.refs--
			c.removeLocked(cacheKey, e)
		}
		close(ready)
		c.mu.Unlock()
		if err != nil {
			return err
		}
		err = copySnapshotCache(ctx, e.path, dest, want)
		c.mu.Lock()
		e.refs--
		c.trimLocked(0)
		c.mu.Unlock()
		return err
	}
}

// Verify while copying, so local corruption never becomes a sandbox disk. A
// bounded reader prevents an unexpectedly enlarged file consuming disk space.
func copySnapshotCache(ctx context.Context, src, dst string, want storage.ArtifactDescriptor) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	out, err := os.CreateTemp(filepath.Dir(dst), ".snapshot-copy-*")
	if err != nil {
		return err
	}
	defer os.Remove(out.Name())
	hr := storage.NewHashingReader(io.LimitReader(&snapshotContextReader{ctx: ctx, r: f}, want.Size+1))
	n, err := io.Copy(out, hr)
	closeErr := out.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if n != want.Size || hr.Sum() != want.SHA256 {
		return fmt.Errorf("cached snapshot integrity mismatch")
	}
	return os.Rename(out.Name(), dst)
}

type snapshotContextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *snapshotContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func snapshotArtifactCacheKey(key string, want storage.ArtifactDescriptor) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", key, want.SHA256, want.Size))))
}

// rememberSnapshot runs only after the whole manifest was fetched successfully.
// Bypassed or evicted artifacts prevent advertisement of a partial snapshot.
func (s *Service) rememberSnapshot(id string, manifest *storage.Manifest) {
	c := s.snapshotCache
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hintsLocked()
	if len(c.snapshots) >= proto.MaxCachedSnapshotHints {
		return
	}
	keys := make([]string, 0, len(manifest.Artifacts))
	for name, artifact := range manifest.Artifacts {
		keys = append(keys, snapshotArtifactCacheKey(storage.BundlePrefix(id)+name, artifact))
	}
	c.snapshots[id] = keys
	c.hintsLocked()
}

// SnapshotCacheHints is called by heartbeat. Expiry is fixed at download time,
// not extended by heartbeats; evictions and restarts remove the advertisement.
func (s *Service) SnapshotCacheHints() []proto.CachedSnapshot {
	c := s.snapshotCache
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hintsLocked()
}

func (c *snapshotDownloadCache) hintsLocked() []proto.CachedSnapshot {
	out := make([]proto.CachedSnapshot, 0, len(c.snapshots))
	now := time.Now()
	for id, keys := range c.snapshots {
		expiry := time.Time{}
		complete := len(keys) > 0
		for _, key := range keys {
			e := c.entries[key]
			if e == nil || e.ready != nil || !e.expires.After(now) {
				complete = false
				break
			}
			if expiry.IsZero() || e.expires.Before(expiry) {
				expiry = e.expires
			}
		}
		if !complete {
			delete(c.snapshots, id)
			continue
		}
		out = append(out, proto.CachedSnapshot{ID: id, ExpiresAt: expiry})
	}
	return out
}
