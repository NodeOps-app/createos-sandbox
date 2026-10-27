package vm

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/proto"
)

// DiskResolver is a function that fetches the desired disk set for a
// sandbox from the control plane. Injected by main.go so the vm
// package stays free of control-client deps.
type DiskResolver func(ctx context.Context, sandboxID string) ([]proto.MMDSDisk, error)

// StartDiskReconcileLoop walks every running sandbox-with-disks on a
// timer, fetches the canonical disk set from control, and brings each
// sandbox's MMDS into line via ReconcileSandboxDisks.
//
// Runs at a deliberately slow cadence: disk attach/detach already
// pushes MMDS synchronously, so the reconciler is a safety net for
// the failed-forward / failed-row-delete cases. 60 s is plenty —
// even a worst-case orphan unmount converges within one tick.
func (m *Manager) StartDiskReconcileLoop(ctx context.Context, resolve DiskResolver, interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	if resolve == nil {
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.diskReconcileTick(ctx, resolve)
			}
		}
	}()
}

// diskReconcileTick walks live sandboxes, resolves each one's desired
// disk set from control, and calls ReconcileSandboxDisks for any drift.
// Snapshots the sandbox list under RLock so we don't hold the lock
// through the HTTP fetch.
func (m *Manager) diskReconcileTick(ctx context.Context, resolve DiskResolver) {
	m.Mu.RLock()
	ids := make([]string, 0, len(m.Sandboxes))
	for id := range m.Sandboxes {
		// Include empty applied sets: a first attach or last detach may have failed.
		ids = append(ids, id)
	}
	m.Mu.RUnlock()

	for _, id := range ids {
		fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		desired, err := resolve(fetchCtx, id)
		cancel()
		if err != nil {
			// Sandbox vanishing during the tick is common (destroy).
			// Other errors are debug-noise.
			log.WithContext(ctx).Debugf("[disks-reconcile] resolve %s: %v", id, err)
			continue
		}
		if err := m.ReconcileSandboxDisks(ctx, id, desired); err != nil {
			log.WithContext(ctx).Warnf("[disks-reconcile] %s: %v", id, err)
		}
	}
}

// ReconcileSandboxDisks brings firecracker's MMDS disks field into line
// with `desired` (the control-plane truth from
// /v1/internal/db/sandboxes/:id/disks/resolved). Idempotent: a no-op
// when the in-memory + MMDS state already matches.
//
// Closes the gap left by the user-facing detach handler if its host
// forward succeeds but the DB row delete fails (or vice-versa for a
// future bug). Without this, a divergence between control's
// sandbox_disks rows and the agent's mounted disks could persist
// indefinitely — the previous code only re-pushed MMDS on pause/resume
// or on credential rotation.
//
// Concurrency: takes diskOpMu so it can't race AttachDiskLive /
// DetachDiskLive. The mutex covers the entire read-modify-write —
// including the firecracker /mmds PUT — so a live attach issued mid-
// reconcile waits for the reconciler's push to finish, then runs on
// top of the (newly-correct) base.
func (m *Manager) ReconcileSandboxDisks(ctx context.Context, sandboxID string, desired []proto.MMDSDisk) error {
	m.diskOpMu.Lock()
	defer m.diskOpMu.Unlock()

	m.Mu.Lock()
	sb, ok := m.Sandboxes[sandboxID]
	if !ok {
		m.Mu.Unlock()
		return ErrSandboxNotFound
	}
	current := sb.Disks
	machine := sb.Machine
	apiSock := sb.ApiSocket
	m.Mu.Unlock()

	if mmdsDisksEqual(current, desired) {
		return nil
	}
	log.WithContext(ctx).Infof("[disks-reconcile] %s: current=%d desired=%d disk(s); pushing MMDS",
		sandboxID, len(current), len(desired))
	if err := pushDisksToMMDS(ctx, sandboxID, machine, apiSock, desired); err != nil {
		return fmt.Errorf("reconcile push: %w", err)
	}
	m.Mu.Lock()
	if sb2, ok := m.Sandboxes[sandboxID]; ok && sb2 == sb {
		sb2.Disks = desired
	}
	m.Mu.Unlock()
	return nil
}

// mmdsDisksEqual reports whether two MMDS disk slices represent the
// same desired state — same (disk_id, mount_path) set, same
// per-attachment config. Order-insensitive so a reorder doesn't
// trigger a spurious MMDS push.
func mmdsDisksEqual(a, b []proto.MMDSDisk) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(d proto.MMDSDisk) string {
		return d.ID + "@" + filepath.Clean(d.MountPath)
	}
	ac := append([]proto.MMDSDisk(nil), a...)
	bc := append([]proto.MMDSDisk(nil), b...)
	sort.Slice(ac, func(i, j int) bool { return key(ac[i]) < key(ac[j]) })
	sort.Slice(bc, func(i, j int) bool { return key(bc[i]) < key(bc[j]) })
	for i := range ac {
		if ac[i].ID != bc[i].ID ||
			ac[i].Kind != bc[i].Kind ||
			ac[i].MountPath != bc[i].MountPath ||
			strings.TrimPrefix(strings.TrimSuffix(ac[i].SubPath, "/"), "/") !=
				strings.TrimPrefix(strings.TrimSuffix(bc[i].SubPath, "/"), "/") {
			return false
		}
		if ac[i].Config != bc[i].Config {
			return false
		}
		// Credentials intentionally NOT compared: a rotated cred set
		// has the same (id, mount_path) and config but new keys; if
		// the reconciler skipped that, rotation wouldn't propagate
		// through this path. We treat unequal creds as "different" so
		// reconcile re-pushes.
		if ac[i].Credentials != bc[i].Credentials {
			return false
		}
	}
	return true
}
