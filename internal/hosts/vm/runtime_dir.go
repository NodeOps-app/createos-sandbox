package vm

import (
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

// runtimeDir is the host-local directory under which createos drops
// short-lived but file-namespaced VM artifacts: per-VM overlays, the
// firecracker API socket, the UFFD page-server socket, the per-shape
// snapshot template socket. Defaults to /var/lib/createos/runtime so
// the files survive hosts where `/tmp` is a tmpfs and
// reboots that wipe `/tmp`. The host config resolves any override before use.
//
// The host installs the resolved path once during startup; if the directory
// doesn't exist on first use, runtimePath() creates it.
var runtimeDir = "/var/lib/createos/runtime"

// SetRuntimeDir installs the resolved host runtime directory before startup.
func SetRuntimeDir(dir string) {
	if dir != "" {
		runtimeDir = dir
	}
}

// RuntimeDir returns the resolved runtime directory.
func RuntimeDir() string { return runtimeDir }

// runtimePath joins runtimeDir with the given filename and lazily
// ensures the dir exists. Errors creating the dir are non-fatal —
// callers will see them when they try to open the file.
//
// Mode 0711 (root rwx, others execute-only): per-slot UID firecracker
// processes can traverse INTO their per-VM subdir to bind sockets but
// can't `ls` the parent to enumerate sibling sandbox IDs. Each
// per-VM subdir is still 0700 (set by slotRuntimePath), so an
// unprivileged process can't read sibling sockets even if it guesses
// the path. hidepid=2 closes the process-list enumeration in parallel.
func runtimePath(name string) string {
	_ = os.MkdirAll(runtimeDir, 0o711)
	return filepath.Join(runtimeDir, name)
}

// SlotRuntimeDir returns the per-sandbox runtime subdirectory path
// (caller's responsibility to mkdir). Used by code paths that need
// to chown the dir to a per-slot UID before firecracker can bind a
// socket inside it.
func SlotRuntimeDir(sandboxID string) string {
	return filepath.Join(runtimeDir, sandboxID)
}

// slotRuntimePath returns the path to a file inside the per-sandbox
// subdir of runtimeDir, creating the subdir on demand mode 0700.
// Per-VM artifacts (API socket, vsock UDS, UFFD socket) live here so
// that when per-slot UIDs are enabled, each VM's firecracker can be
// dropped into its own writable dir — siblings can't even traverse.
// When per-slot UIDs are disabled, this still works (dir stays 0700
// root, firecracker runs as root, no permission issue).
func slotRuntimePath(sandboxID, filename string) string {
	dir := SlotRuntimeDir(sandboxID)
	_ = os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, filename)
}

// SweepOrphanRuntimeDirs removes any runtime/sb-* subdir whose id is
// neither live (running VMs in m.Sandboxes) nor paused-on-this-host
// (rows kept under pausedDir for locality). Catches dirs leaked by
// teardown paths that miss os.RemoveAll — historically tearDownAfterPause
// (every successful pause), agent_not_ready failures, and crashes between
// firecracker exit and Destroy.
//
// Idempotent; cheap (readdir + map lookups per entry). Called from the
// same 1-min host loop that runs SweepOrphanCgroups.
func (m *Manager) SweepOrphanRuntimeDirs(pausedIDs map[string]struct{}) int {
	entries, err := os.ReadDir(runtimeDir)
	if err != nil {
		return 0
	}
	removed := 0
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || !strings.HasPrefix(name, "sb-") {
			continue
		}
		if _, paused := pausedIDs[name]; paused {
			continue
		}
		// Registration and deletion share Mu, so a create/resume cannot
		// acquire this directory between the ownership check and removal.
		m.Mu.Lock()
		_, live := m.Sandboxes[name]
		if !live && m.creating[name] == 0 {
			if err := os.RemoveAll(filepath.Join(runtimeDir, name)); err == nil {
				removed++
			}
		}
		m.Mu.Unlock()
	}
	if removed > 0 {
		log.Infof("[runtime] sweep removed %d orphan dir(s)", removed)
	}
	return removed
}

// HoldRuntime protects filesystem work before a VM enters Sandboxes. Nested
// service/manager operations retain ownership until the last holder releases it.
func (m *Manager) HoldRuntime(id string) func() {
	m.Mu.Lock()
	if m.creating == nil {
		m.creating = make(map[string]int)
	}
	m.creating[id]++
	m.Mu.Unlock()
	return func() {
		m.Mu.Lock()
		m.creating[id]--
		if m.creating[id] == 0 {
			delete(m.creating, id)
		}
		m.Mu.Unlock()
	}
}
