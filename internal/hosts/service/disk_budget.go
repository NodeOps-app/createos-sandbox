package service

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
)

var errDiskBudget = errors.New("insufficient disk working space")

// diskBudget coordinates all snapshot working-space reservations on this host.
// Statfs accounts for existing files (including crash leftovers). Reservations
// account for future growth. This is admission control, not a filesystem quota:
// unrelated writers still share the device and can consume free space.
type diskBudget struct {
	mu         sync.Mutex
	root       string
	cacheLimit int64
	leases     map[*diskLease]struct{}
	space      func(string) (uint64, int64, error)
	allocated  func(string) (int64, error)
}

type diskNeed struct {
	path  string
	bytes int64
}
type diskClaim struct {
	diskNeed
	dev      uint64
	baseline int64
}
type diskLease struct {
	owner  *diskBudget
	claims []diskClaim
}

func (s *Service) InitDiskBudget() error {
	if err := os.MkdirAll(s.PauseCfg.PausedDir, 0700); err != nil {
		return err
	}
	b := &diskBudget{root: s.PauseCfg.PausedDir, cacheLimit: s.PauseCfg.LocalDiskBudget,
		leases: make(map[*diskLease]struct{}), space: diskSpace, allocated: allocatedDiskBytes}
	// Validate accounting before recovery or requests can write more data. We
	// deliberately retain unfinished bundles; they are not eviction candidates.
	if _, err := b.allocated(b.root); err != nil {
		return err
	}
	if _, _, err := b.space(b.root); err != nil {
		return err
	}
	s.diskBudget = b
	return nil
}

func diskSpace(path string) (uint64, int64, error) {
	for {
		var st syscall.Stat_t
		err := syscall.Stat(path, &st)
		if os.IsNotExist(err) {
			parent := filepath.Dir(path)
			if parent == path {
				return 0, 0, err
			}
			path = parent
			continue
		}
		if err != nil {
			return 0, 0, err
		}
		var v syscall.Statfs_t
		if err := syscall.Statfs(path, &v); err != nil {
			return 0, 0, err
		}
		return uint64(st.Dev), int64(v.Bavail) * v.Bsize, nil
	}
}

// Count allocated blocks, not sparse apparent lengths. WalkDir does not follow
// symlinks into other directories. Concurrent unlink is harmless.
func allocatedDiskBytes(path string) (int64, error) {
	var total int64
	err := filepath.WalkDir(path, func(_ string, e fs.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if e.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := e.Info()
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			total += st.Blocks * 512
		}
		return nil
	})
	return total, err
}

func (b *diskBudget) pendingLocked() (map[uint64]int64, int64, error) {
	pending := make(map[uint64]int64)
	var cachePending int64
	for l := range b.leases {
		for _, c := range l.claims {
			actual, err := b.allocated(c.path)
			if err != nil {
				return nil, 0, err
			}
			remaining := max(int64(0), c.bytes-max(int64(0), actual-c.baseline))
			pending[c.dev] += remaining
			rel, err := filepath.Rel(b.root, c.path)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				cachePending += remaining
			}
		}
	}
	return pending, cachePending, nil
}

// cache=true enforces the retention budget as well as the scheduler's free-space
// floor. Mandatory working operations can exceed the retention limit temporarily,
// but always reserve actual free space against every other operation's claims.
func (b *diskBudget) reserve(needs []diskNeed, cache bool, floor int64) (*diskLease, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	pending, cachePending, err := b.pendingLocked()
	if err != nil {
		return nil, err
	}
	l := &diskLease{owner: b}
	requested := make(map[uint64]int64)
	free := make(map[uint64]int64)
	var bytes int64
	for _, need := range needs {
		if need.bytes < 0 {
			return nil, fmt.Errorf("invalid disk reservation")
		}
		dev, avail, err := b.space(need.path)
		if err != nil {
			return nil, err
		}
		baseline, err := b.allocated(need.path)
		if err != nil {
			return nil, err
		}
		requested[dev] += need.bytes
		free[dev] = avail
		bytes += need.bytes
		l.claims = append(l.claims, diskClaim{diskNeed: need, dev: dev, baseline: baseline})
	}
	for dev, n := range requested {
		if free[dev]-pending[dev]-n < floor {
			return nil, errDiskBudget
		}
	}
	if cache {
		used, err := b.allocated(b.root)
		if err != nil {
			return nil, err
		}
		if b.cacheLimit <= 0 || used+cachePending+bytes > b.cacheLimit {
			return nil, errDiskBudget
		}
	}
	b.leases[l] = struct{}{}
	return l, nil
}

func (l *diskLease) release() {
	if l == nil {
		return
	}
	l.owner.mu.Lock()
	delete(l.owner.leases, l)
	l.owner.mu.Unlock()
}

func (b *diskBudget) cacheUsage() (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, pending, err := b.pendingLocked()
	if err != nil {
		return 0, err
	}
	used, err := b.allocated(b.root)
	return used + pending, err
}

func (s *Service) reserveDiskWork(ctx context.Context, operation string, needs ...diskNeed) (*diskLease, error) {
	if s.diskBudget == nil {
		return nil, nil
	} // lightweight service fixtures
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lease, err := s.diskBudget.reserve(needs, false, 0)
		if err == nil {
			return lease, nil
		}
		if !errors.Is(err, errDiskBudget) || !s.evictDiskCache(ctx) {
			log.WithContext(ctx).WithField("operation", operation).WithError(err).Warn("[disk-budget] working reservation denied")
			return nil, err
		}
	}
}

// Never hold the budget mutex while taking cache/lifecycle locks or doing RPCs.
// Both eviction paths recheck eligibility under their normal protection. Only
// uploaded pause bundles appear in LocalCacheCandidates; snap_ checkpoints do not.
func (s *Service) evictDiskCache(ctx context.Context) bool {
	if c := s.snapshotCache; c != nil {
		c.mu.Lock()
		var oldest *snapshotCacheEntry
		var key string
		for k, e := range c.entries {
			if e.ready == nil && e.refs == 0 && (oldest == nil || e.expires.Before(oldest.expires)) {
				key, oldest = k, e
			}
		}
		removed := oldest != nil && c.removeLocked(key, oldest)
		c.hintsLocked()
		c.mu.Unlock()
		if removed {
			return true
		}
	}
	if s.Repo == nil {
		return false
	}
	candidates, err := s.Repo.LocalCacheCandidates(ctx, s.PauseCfg.HostID)
	if err != nil {
		return false
	}
	for _, rec := range candidates {
		if s.evictLocalCache(ctx, rec.ID, false) {
			return true
		}
	}
	return false
}

func (s *Service) reapDiskBudget(ctx context.Context) {
	if s.diskBudget == nil || s.diskBudget.cacheLimit <= 0 {
		return
	}
	for {
		used, err := s.diskBudget.cacheUsage()
		if err != nil {
			log.WithError(err).Warn("[disk-budget] accounting failed")
			return
		}
		if used <= s.diskBudget.cacheLimit || !s.evictDiskCache(ctx) {
			return
		}
	}
}

// Conservative peak bounds include raw memory, compressed output, sparse archive
// framing and VM state. Reserve before freezing, rather than discover ENOSPC
// after the guest has stopped. Compression is allowed to expand slightly.
func snapshotWorkBytes(memMiB, diskMiB int64) int64 {
	raw := (2*memMiB + diskMiB) * 1024 * 1024
	return compressedWorkBytes(raw)
}

func compressedWorkBytes(raw int64) int64 {
	return raw + raw/50 + 64*1024*1024
}
