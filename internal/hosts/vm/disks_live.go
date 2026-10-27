package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/proto"
)

// ErrSandboxNotFound is returned by AttachDiskLive / DetachDiskLive when
// the sandbox isn't in the Manager's live map (e.g. destroyed since the
// caller looked it up). Handlers translate to 404.
var ErrSandboxNotFound = fmt.Errorf("sandbox not found")

// AttachDiskLive adds one disk to a running sandbox's MMDS-fed desired
// set and pushes the updated set to firecracker. The agent's reconciler
// picks up the change on its next watchMMDS tick (~2 ms) and runs
// s3fs to mount the new entry. Returns the new full disks slice for
// caller bookkeeping (Sandbox.Disks already updated).
//
// One disk can mount at multiple paths; identity is (disk_id, mount_path).
// Re-attaching an existing (id, path) pair replaces the entry (idempotent
// for retries). A second attach with the same disk_id at a different
// path appends a new entry.
func (m *Manager) AttachDiskLive(ctx context.Context, sandboxID string, disk proto.MMDSDisk) error {
	m.diskOpMu.Lock()
	defer m.diskOpMu.Unlock()
	m.Mu.Lock()
	sb, ok := m.Sandboxes[sandboxID]
	if !ok {
		m.Mu.Unlock()
		return ErrSandboxNotFound
	}
	updated := make([]proto.MMDSDisk, 0, len(sb.Disks)+1)
	found := false
	for _, d := range sb.Disks {
		if d.ID == disk.ID && d.MountPath == disk.MountPath {
			updated = append(updated, disk)
			found = true
			continue
		}
		updated = append(updated, d)
	}
	if !found {
		updated = append(updated, disk)
	}
	machine := sb.Machine
	apiSock := sb.ApiSocket
	m.Mu.Unlock()

	if err := pushDisksToMMDS(ctx, sandboxID, machine, apiSock, updated); err != nil {
		return err
	}
	m.Mu.Lock()
	if m.Sandboxes[sandboxID] == sb {
		sb.Disks = updated
	}
	m.Mu.Unlock()
	// Poll with bounded backoff until the mount settles, so status reaches
	// the API within seconds instead of waiting for the 30-second loop.
	m.settleDiskStatus(sandboxID)
	return nil
}

// DetachDiskLive removes one disk from a sandbox's desired set + pushes
// the updated MMDS. Agent reconciler unmounts the FUSE backing on the
// next tick (existing applyDisks logic handles the diff).
//
// S3 contents are untouched — this only drops the in-VM mount.
//
// No-op (success) when the (disk_id, mount_path) pair isn't attached,
// so a UI retry doesn't 404 because of a previous successful detach.
func (m *Manager) DetachDiskLive(ctx context.Context, sandboxID, diskID, mountPath string) error {
	m.diskOpMu.Lock()
	defer m.diskOpMu.Unlock()
	m.Mu.Lock()
	sb, ok := m.Sandboxes[sandboxID]
	if !ok {
		m.Mu.Unlock()
		return ErrSandboxNotFound
	}
	updated := make([]proto.MMDSDisk, 0, len(sb.Disks))
	for _, d := range sb.Disks {
		if d.ID == diskID && d.MountPath == mountPath {
			continue
		}
		updated = append(updated, d)
	}
	machine := sb.Machine
	apiSock := sb.ApiSocket
	m.Mu.Unlock()

	if err := pushDisksToMMDS(ctx, sandboxID, machine, apiSock, updated); err != nil {
		return err
	}
	m.Mu.Lock()
	if m.Sandboxes[sandboxID] == sb {
		sb.Disks = updated
	}
	m.Mu.Unlock()
	// Opportunistic status poll — same rationale as AttachDiskLive.
	// After detach the agent's reconciler runs fusermount in ≤2 ms;
	// we wait briefly so the polled status reflects the unmount.
	go func() {
		time.Sleep(2 * time.Second)
		pollCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.PollDiskStatusOnce(pollCtx, sandboxID)
	}()
	return nil
}

// pushDisksToMMDS replaces the disks field while preserving other MMDS fields.
// Callers hold diskOpMu across the complete read-modify-write.
func pushDisksToMMDS(ctx context.Context, sandboxID string, machine *firecracker.Machine, apiSock string, disks []proto.MMDSDisk) error {
	// Read current MMDS so we can replace just the disks field.
	current, err := readCurrentMMDS(ctx, machine, apiSock)
	if err != nil {
		return fmt.Errorf("read mmds: %w", err)
	}
	if len(disks) == 0 {
		delete(current, "disks")
	} else {
		current["disks"] = disks
	}
	// Bump now_ns to wall-clock. Pool VMs can sit idle for hours between
	// prewarm-resume and user claim; without this, their guest clock stays
	// at resume time and any SigV4-signed request (geesefs mount, tenant's
	// S3 client) hits RequestTimeTooSkewed → 400. The agent only calls
	// clock_settime when NowNS changes, so setting it here is enough.
	current["now_ns"] = time.Now().UnixNano()
	buf, err := json.Marshal(current)
	if err != nil {
		return fmt.Errorf("marshal mmds: %w", err)
	}
	if machine != nil {
		if err := machine.SetMetadata(ctx, current); err != nil {
			return fmt.Errorf("set metadata (sdk): %w", err)
		}
	} else {
		api := NewFirecrackerAPI(apiSock)
		if err := api.SetMetadata(ctx, string(buf)); err != nil {
			return fmt.Errorf("set metadata (raw): %w", err)
		}
	}
	log.WithContext(ctx).Infof("[disks] %s mmds updated: %d disk(s)", sandboxID, len(disks))
	return nil
}

// RefreshNowNS bumps the sandbox's MMDS now_ns to wall-clock. Called by
// the control-plane pool-claim kick so a pool VM that sat idle since
// prewarm-resume rejoins wall time before the tenant issues any SigV4
// request. Idempotent — the agent only reacts when the value changes.
func (m *Manager) RefreshNowNS(ctx context.Context, sandboxID string) error {
	m.diskOpMu.Lock()
	defer m.diskOpMu.Unlock()
	m.Mu.RLock()
	sb, ok := m.Sandboxes[sandboxID]
	m.Mu.RUnlock()
	if !ok {
		return ErrSandboxNotFound
	}
	current, err := readCurrentMMDS(ctx, sb.Machine, sb.ApiSocket)
	if err != nil {
		return fmt.Errorf("read mmds: %w", err)
	}
	now := time.Now()
	current["now_ns"] = now.UnixNano()
	// Signal to the guest agent that this VM was just claimed off the pool.
	// The agent latches this timestamp and, 5 minutes after it, relaxes its
	// MMDS poll cap from 20ms → 200ms to give back the ~2% guest vCPU spent
	// on aggressive polling (see internal/agent/agent.go:watchMMDS). Only
	// set here (pool-claim-kick), so pool VMs never see it and keep polling
	// aggressively — which is required to keep their vCPU warm before claim.
	current["claimed_at_ms"] = now.UnixMilli()
	if sb.Machine != nil {
		return sb.Machine.SetMetadata(ctx, current)
	}
	buf, err := json.Marshal(current)
	if err != nil {
		return fmt.Errorf("marshal mmds: %w", err)
	}
	api := NewFirecrackerAPI(sb.ApiSocket)
	return api.SetMetadata(ctx, string(buf))
}

// readCurrentMMDS returns the current MMDS document as a map. Uses the
// SDK Machine when present (fresh VMs); falls back to raw HTTP GET on
// the API socket otherwise.
func readCurrentMMDS(ctx context.Context, machine *firecracker.Machine, apiSock string) (map[string]any, error) {
	if machine != nil {
		out := map[string]any{}
		if err := machine.GetMetadata(ctx, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	// Rehydrated path: raw HTTP GET on the API socket.
	api := NewFirecrackerAPI(apiSock)
	raw, err := api.getMMDSRaw(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode current mmds: %w", err)
	}
	return out, nil
}
