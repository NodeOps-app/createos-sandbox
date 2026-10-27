package vm

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// LoadSnapshots scans m.SnapshotDir and registers any (shape, rootfs) snapshot
// whose vmstate+mem files exist, the rootfs is still in the catalog, and the
// rootfs file's mtime is not newer than the snapshot. Stale snapshots are
// removed so the next prewarm/create rebuilds them.
//
// Returns the number of ready snapshots registered.
func (m *Manager) LoadSnapshots() (int, error) {
	entries, err := os.ReadDir(m.SnapshotDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read snapshot dir: %w", err)
	}

	ready := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		key, ok := parseShapeKey(e.Name())
		if !ok {
			continue
		}
		dir := filepath.Join(m.SnapshotDir, e.Name())
		files, manifestErr := readSnapshotManifest(dir)
		if manifestErr != nil {
			if !os.IsNotExist(manifestErr) {
				log.Warnf("[snapshot] ignoring invalid manifest for %s: %v", key, manifestErr)
				continue
			}
			// Backward compatibility for snapshots produced before immutable
			// generations were introduced.
			files = &snapshotFiles{
				VmStatePath: filepath.Join(dir, "vmstate"),
				MemFilePath: filepath.Join(dir, "mem"),
				BaseOverlay: filepath.Join(dir, "base.ext4"),
				Ready:       true,
			}
		}

		vmStat, err := os.Stat(files.VmStatePath)
		if err != nil {
			continue
		}
		if _, err := os.Stat(files.MemFilePath); err != nil {
			continue
		}

		// Catalog membership — rootfs name must still be configured.
		rootfsPath, ok := m.LookupRootfs(key.Rootfs)
		if !ok {
			log.Infof("[snapshot] dropping %s — rootfs %q no longer in catalog", key, key.Rootfs)
			_ = os.RemoveAll(dir)
			continue
		}

		// Invalidate if the rootfs file is newer than the snapshot.
		rootfsStat, err := os.Stat(rootfsPath)
		if err != nil {
			log.Warnf("[snapshot] cannot stat rootfs %s: %v (skipping %s)", rootfsPath, err, key)
			continue
		}
		if rootfsStat.ModTime().After(vmStat.ModTime()) {
			log.Infof("[snapshot] %s stale — rootfs newer than snapshot, will rebuild", key)
			_ = os.RemoveAll(dir)
			continue
		}

		// Base overlay is expected to live alongside vmstate/mem at the
		// canonical path embedded into vmstate by createBaseSnapshot. If a
		// snapshot was produced by an older createos that wrote the overlay
		// to /tmp with a per-process path, the file is gone after any
		// restart and restore will fail — treat as stale so the next
		// prewarm/create rebuilds cleanly.
		if _, err := os.Stat(files.BaseOverlay); err != nil {
			log.Infof("[snapshot] %s stale — base overlay missing at %s, will rebuild", key, files.BaseOverlay)
			_ = os.RemoveAll(dir)
			continue
		}

		m.SnapshotsMu.Lock()
		m.Snapshots[key] = files
		m.SnapshotsMu.Unlock()
		ready++
		log.Infof("[snapshot] loaded %s from disk", key)
	}
	return ready, nil
}

// parseShapeKey is the inverse of shapeKey.String() = "<rootfs>-<vcpu>-<mem>".
// rootfs name may itself contain '-', so split from the right.
func parseShapeKey(s string) (shapeKey, bool) {
	parts := strings.Split(s, "-")
	if len(parts) < 3 {
		return shapeKey{}, false
	}
	mem, err1 := strconv.Atoi(parts[len(parts)-1])
	vcpu, err2 := strconv.Atoi(parts[len(parts)-2])
	if err1 != nil || err2 != nil {
		return shapeKey{}, false
	}
	rootfs := strings.Join(parts[:len(parts)-2], "-")
	if rootfs == "" {
		return shapeKey{}, false
	}
	return shapeKey{VCPU: vcpu, MemMib: mem, Rootfs: rootfs}, true
}
