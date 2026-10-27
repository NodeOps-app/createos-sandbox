package vm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

// OverlayPool pre-creates empty ext4 overlay files so sandbox creation doesn't
// pay the mkfs.ext4 cost on the hot path (~150-250ms per create). A single
// OverlayPool holds pre-made overlays of ONE size.
type OverlayPool struct {
	ready  chan string
	sizeMB int64
	target int
	closed chan struct{}
}

func NewOverlayPool(size int, sizeMB int64) *OverlayPool {
	p := &OverlayPool{
		ready:  make(chan string, size*2),
		sizeMB: sizeMB,
		target: size,
		closed: make(chan struct{}),
	}
	for i := 0; i < size; i++ {
		path, err := createSparseOverlay(sizeMB)
		if err != nil {
			log.Warnf("[overlay-pool] initial create (%dMB): %v", sizeMB, err)
			continue
		}
		p.ready <- path
	}
	go p.replenish()
	return p
}

// Get returns a ready overlay path, or falls back to an on-demand mkfs if the
// pool is empty (preserves correctness under load bursts).
func (p *OverlayPool) Get() (string, error) {
	select {
	case path := <-p.ready:
		return path, nil
	default:
		return createSparseOverlay(p.sizeMB)
	}
}

func (p *OverlayPool) Release(path string)   { _ = os.Remove(path) }
func (p *OverlayPool) Close()                { close(p.closed) }
func (p *OverlayPool) DefaultSizeMib() int64 { return p.sizeMB }

func (p *OverlayPool) replenish() {
	for {
		select {
		case <-p.closed:
			return
		default:
		}
		if len(p.ready) >= p.target {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		path, err := createSparseOverlay(p.sizeMB)
		if err != nil {
			log.Warnf("[overlay-pool] replenish (%dMB): %v", p.sizeMB, err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		select {
		case p.ready <- path:
		case <-p.closed:
			os.Remove(path)
			return
		}
	}
}

// OverlayPools holds one OverlayPool per allowed disk size. Lazy-initialised
// per size to avoid pre-creating pools for sizes nobody has requested yet.
type OverlayPools struct {
	mu         sync.Mutex
	perSize    map[int64]*OverlayPool
	perSizeCap int // target pool size per disk size
}

// NewOverlayPools creates an OverlayPools with `perSizeCap` slots pre-built
// for each size in seedSizes (MiB). Other sizes get lazy-created on first use.
func NewOverlayPools(perSizeCap int, seedSizes []int64) *OverlayPools {
	p := &OverlayPools{
		perSize:    make(map[int64]*OverlayPool),
		perSizeCap: perSizeCap,
	}
	for _, s := range seedSizes {
		log.Infof("[overlay-pool] pre-creating %d slots at %dMB", perSizeCap, s)
		p.perSize[s] = NewOverlayPool(perSizeCap, s)
	}
	return p
}

// GetOverlay returns an overlay of exactly sizeMib, pool-hit if warm, else
// creates a pool for this size (caching it) and hits it after the first slot
// is built. First access for a brand-new size pays one mkfs; the pool fills in
// behind.
func (p *OverlayPools) GetOverlay(sizeMib int64) (string, error) {
	p.mu.Lock()
	pool, ok := p.perSize[sizeMib]
	if !ok {
		pool = NewOverlayPool(p.perSizeCap, sizeMib)
		p.perSize[sizeMib] = pool
	}
	p.mu.Unlock()
	return pool.Get()
}

func (p *OverlayPools) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, pool := range p.perSize {
		pool.Close()
	}
}

// GCStaleOverlays removes fc-overlay-*.ext4 files whose embedded PID
// belongs to a dead machine host process. These leak when serve is
// SIGKILL'd / OOM-killed / host-rebooted: the OverlayPool's in-memory
// channel vanishes along with its paths, but the files it had pre-created
// stay on disk. Reconcile's CleanupOrphan only matches overlays tied to a
// sandbox DB row; pre-made pool files have no row, so without this sweep
// they accumulate indefinitely.
//
// Safety:
//   - Skip files whose PID is our own or a currently-alive PID (supports
//     future multi-serve-on-one-host setups).
//   - Skip files in `keepPaths` — these are overlays held open by
//     rehydrated firecracker VMs whose serve parent is dead. Removing
//     them by path doesn't break the running VM (firecracker keeps the
//     FD; the inode survives), but it permanently breaks any later
//     path-based access — pause's archive.overlay step in particular.
//
// Returns how many files were removed.
func GCStaleOverlays(keepPaths ...string) int {
	keep := make(map[string]struct{}, len(keepPaths))
	for _, p := range keepPaths {
		if p != "" {
			keep[filepath.Clean(p)] = struct{}{}
		}
	}
	glob := filepath.Join(runtimeDir, "fc-overlay-*.ext4")
	matches, _ := filepath.Glob(glob)
	myPID := os.Getpid()
	var removed int
	for _, p := range matches {
		if _, pinned := keep[filepath.Clean(p)]; pinned {
			continue
		}
		// Filename: fc-overlay-<PID>-<unixnano>.ext4
		base := strings.TrimSuffix(filepath.Base(p), ".ext4")
		parts := strings.SplitN(strings.TrimPrefix(base, "fc-overlay-"), "-", 2)
		if len(parts) < 2 {
			continue
		}
		pid, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		if pid == myPID {
			continue
		}
		// syscall.Kill with signal 0 is the standard "is this PID alive?" probe.
		// ESRCH = no such process; EPERM = alive but owned by someone else.
		if err := syscall.Kill(pid, 0); err == nil || err == syscall.EPERM {
			continue
		}
		if err := os.Remove(p); err == nil {
			removed++
		}
	}
	if removed > 0 {
		log.Infof("[overlay-gc] removed %d stale overlay file(s) from dead serve processes", removed)
	}
	return removed
}

func createSparseOverlay(sizeMB int64) (string, error) {
	path := runtimePath(fmt.Sprintf("fc-overlay-%d-%d.ext4", os.Getpid(), time.Now().UnixNano()))
	if err := createOverlayAt(path, sizeMB); err != nil {
		return "", err
	}
	return path, nil
}

// createOverlayAt formats an empty ext4 overlay of sizeMB at the given path.
// Used for the snapshot base overlay, which must live at a stable path
// (inside the snapshot dir) so the path baked into vmstate keeps resolving
// across serve restarts and host reboots that wipe /tmp.
func createOverlayAt(path string, sizeMB int64) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := f.Truncate(sizeMB * 1024 * 1024); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	f.Close()
	// 0600: only the owning slot uid can read this VM's filesystem
	// state. Without this, os.Create's default 0644 leaks the overlay
	// to every other slot uid on the host.
	_ = os.Chmod(path, 0o600)
	out, err := exec.Command("mkfs.ext4", "-F", "-m", "0", "-O", "^has_journal", path).CombinedOutput()
	if err != nil {
		os.Remove(path)
		return fmt.Errorf("mkfs.ext4: %w\n%s", err, out)
	}
	return nil
}
