package vm

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// agentDiskStatusPort is the agent's HTTP file-server port; /disks/status
// is mounted on the same listener. Kept here as a constant so this file
// doesn't import the agent package (build-tag-gated).
const agentDiskStatusPort = 1025

// DiskStatusPersister is called per (sandbox_id, disk_id) when the
// poller detects a status that differs from what was last persisted.
// Wired by the host main to controlclient.SetSandboxDiskStatus.
type DiskStatusPersister func(ctx context.Context, sandboxID, diskID, mountPath, status, errMsg string) error

type diskStatusKey struct{ id, mp string }

func allDiskReportsSettled(disks []proto.MMDSDisk, reports []agentDiskReport) bool {
	if len(disks) == 0 {
		return true
	}
	expected := make(map[diskStatusKey]struct{}, len(disks))
	for _, d := range disks {
		expected[diskStatusKey{d.ID, path.Clean(d.MountPath)}] = struct{}{}
	}
	for _, r := range reports {
		key := diskStatusKey{r.DiskID, path.Clean(r.MountPath)}
		if _, ok := expected[key]; !ok {
			continue
		}
		if r.Status != models.SandboxDiskStatusMounted && r.Status != models.SandboxDiskStatusFailed {
			return false
		}
		delete(expected, key)
	}
	return len(expected) == 0
}

// extractStatusError pulls the two fields the dedup cache cares about
// out of an agentDiskReport. The cache stores the report verbatim;
// callers go through this so the comparison shape stays in one place.
func extractStatusError(r agentDiskReport) (status, errMsg string) {
	return r.Status, r.Error
}

// PollDiskStatusOnce fires a one-shot status fetch for a single sandbox
// and calls the persister stashed by StartDiskStatusLoop. Used right
// after a live attach / detach so the UI sees status changes within
// seconds instead of waiting up to a full status-loop interval.
// Best-effort: errors logged at debug only.
//
// Blocks until the agent responds (or timeout). Run in a goroutine if
// you don't want to wait. It returns true once every expected attachment
// has reached a terminal mount state (mounted or failed).
func (m *Manager) PollDiskStatusOnce(ctx context.Context, sandboxID string) bool {
	persist := m.diskStatusPersist
	if persist == nil {
		return false
	}
	m.Mu.RLock()
	sb, ok := m.Sandboxes[sandboxID]
	if !ok || sb.IP == "" {
		m.Mu.RUnlock()
		return false
	}
	ip, token, disks := sb.IP, sb.SecretToken, sb.Disks
	m.Mu.RUnlock()
	if len(disks) == 0 {
		return true
	}

	reports, err := fetchDiskStatus(ctx, ip, token)
	if err != nil {
		log.WithContext(ctx).Debugf("[disks] one-shot status fetch %s: %v", sandboxID, err)
		return false
	}
	// Resolve agent-reported mount_path against the stored attachment by
	// canonical form (path.Clean) so older rows persisted before the
	// validator normalised the input (e.g. "//double") still match a
	// report for "/double". DB writes use the stored mount_path so the
	// row lookup hits.
	storedByCanon := make(map[diskStatusKey]string, len(disks))
	for _, d := range disks {
		storedByCanon[diskStatusKey{d.ID, path.Clean(d.MountPath)}] = d.MountPath
	}
	seen := make(map[diskStatusKey]bool, len(reports))
	for _, r := range reports {
		canon := path.Clean(r.MountPath)
		key := diskStatusKey{r.DiskID, canon}
		stored, ok := storedByCanon[key]
		if !ok {
			stored = r.MountPath
		}
		seen[key] = true
		if err := persist(ctx, sandboxID, r.DiskID, stored, r.Status, r.Error); err != nil {
			return false
		}
	}
	// Attachments we expected but the agent didn't report on → pending.
	for _, d := range disks {
		if seen[diskStatusKey{d.ID, path.Clean(d.MountPath)}] {
			continue
		}
		if err := persist(ctx, sandboxID, d.ID, d.MountPath, models.SandboxDiskStatusPending, ""); err != nil {
			return false
		}
	}
	return allDiskReportsSettled(disks, reports)
}

// settleDiskStatus polls a newly-created, resumed, or live-attached sandbox
// more frequently while its guest mounts disks. The permanent 30-second loop
// remains the steady-state recovery path; this bounded helper only removes the
// otherwise-random 0-30 second API status delay after a disk-changing action.
func (m *Manager) settleDiskStatus(sandboxID string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		delay := 500 * time.Millisecond
		for {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}

			if m.PollDiskStatusOnce(ctx, sandboxID) {
				return
			}
			if delay < 4*time.Second {
				delay *= 2
				if delay > 4*time.Second {
					delay = 4 * time.Second
				}
			}
		}
	}()
}

// SetDisks replaces the in-memory disks slice for a live sandbox. Called
// during rehydrate after fetching the host-scoped resolved disk bundle.
// The manager mutex protects replacement against concurrent readers.
func (m *Manager) SetDisks(id string, disks []proto.MMDSDisk) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	if sb, ok := m.Sandboxes[id]; ok {
		sb.Disks = disks
	}
}

// StartDiskStatusLoop polls each running sandbox that has disks attached
// for its current mount status. Calls persist() for each (id, disk_id)
// whose status (or error message) differs from the last observation.
//
// Runs at a slow cadence (default 30 s). Mount status only changes at
// boot, resume, or explicit re-mount; polling faster would just waste
// VM CPU on /proc/self/mounts parses.
//
// Side effect: stashes `persist` on the Manager so PollDiskStatusOnce
// can reuse it for opportunistic per-sandbox polls (e.g. right after
// a live attach so the UI flips status quickly).
func (m *Manager) StartDiskStatusLoop(ctx context.Context, persist DiskStatusPersister, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if persist == nil {
		return
	}
	m.diskStatusPersist = persist
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		// last-observed status per (sandboxID, diskID, ip). The ip is in
		// the key so a fresh resume (which gives the VM a new IP) starts
		// a fresh dedup window — the pause path resets the DB row to
		// 'pending', and we want the next agent report to PATCH again
		// even though the value matches the pre-pause one.
		last := map[string]agentDiskReport{}
		var lastMu sync.Mutex
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.diskStatusTick(ctx, persist, last, &lastMu)
			}
		}
	}()
}

func (m *Manager) diskStatusTick(ctx context.Context, persist DiskStatusPersister,
	last map[string]agentDiskReport, mu *sync.Mutex) {
	// Snapshot live sandboxes-with-disks.
	type entry struct {
		id    string
		ip    string
		token string
		disks []proto.MMDSDisk
	}
	m.Mu.RLock()
	entries := make([]entry, 0, len(m.Sandboxes))
	for id, sb := range m.Sandboxes {
		if len(sb.Disks) == 0 || sb.IP == "" {
			continue
		}
		entries = append(entries, entry{id: id, ip: sb.IP, token: sb.SecretToken, disks: sb.Disks})
	}
	m.Mu.RUnlock()

	activeKeys := make(map[string]struct{})
	for _, e := range entries {
		for _, d := range e.disks {
			activeKeys[e.id+"/"+d.ID+"@"+path.Clean(d.MountPath)+"@"+e.ip] = struct{}{}
		}
	}
	mu.Lock()
	for key := range last {
		if _, ok := activeKeys[key]; !ok {
			delete(last, key)
		}
	}
	mu.Unlock()
	for _, e := range entries {
		reports, err := fetchDiskStatus(ctx, e.ip, e.token)
		if err != nil {
			// Common during boot / resume — agent file server not up yet.
			// Logged at debug-level to keep noise down.
			log.WithContext(ctx).Debugf("[disks] fetch status %s: %v", e.id, err)
			continue
		}
		// Match agent reports against expected attachments by canonical
		// mount_path (path.Clean) so older sandbox_disks rows stored with
		// non-canonical paths (e.g. "//double") still resolve to the agent's
		// kernel-normalised report ("/double"). Persist with the stored
		// mount_path so the DB-side PK lookup hits.
		type seenKey struct{ id, mp string }
		storedByCanon := make(map[seenKey]string, len(e.disks))
		for _, d := range e.disks {
			storedByCanon[seenKey{d.ID, path.Clean(d.MountPath)}] = d.MountPath
		}
		seen := make(map[seenKey]bool, len(reports))
		for _, r := range reports {
			canon := path.Clean(r.MountPath)
			stored, ok := storedByCanon[seenKey{r.DiskID, canon}]
			if !ok {
				stored = r.MountPath
			}
			seen[seenKey{r.DiskID, canon}] = true
			// Key includes the VM IP so a resume (fresh IP) restarts the
			// dedup window. Pause server-side resets the row to 'pending',
			// and we need the next agent report to PATCH even if the
			// pre-pause cache says the value matches. mount_path is part
			// of the key (canonicalised) so two attachments of the same
			// disk dedup independently regardless of stored-vs-reported
			// path-format drift.
			key := e.id + "/" + r.DiskID + "@" + canon + "@" + e.ip
			mu.Lock()
			prev, ok := last[key]
			mu.Unlock()
			prevStatus, prevErr := extractStatusError(prev)
			if ok && prevStatus == r.Status && prevErr == r.Error {
				continue
			}
			if err := persist(ctx, e.id, r.DiskID, stored, r.Status, r.Error); err != nil {
				continue
			}
			mu.Lock()
			last[key] = r
			mu.Unlock()
		}
		// Attachments we expected but the agent didn't report on → pending.
		for _, d := range e.disks {
			if seen[seenKey{d.ID, path.Clean(d.MountPath)}] {
				continue
			}
			key := e.id + "/" + d.ID + "@" + path.Clean(d.MountPath) + "@" + e.ip
			synth := agentDiskReport{DiskID: d.ID, MountPath: d.MountPath, Status: models.SandboxDiskStatusPending}
			mu.Lock()
			prev, ok := last[key]
			mu.Unlock()
			prevStatus, prevErr := extractStatusError(prev)
			if ok && prevStatus == synth.Status && prevErr == synth.Error {
				continue
			}
			if err := persist(ctx, e.id, d.ID, d.MountPath, synth.Status, synth.Error); err != nil {
				continue
			}
			mu.Lock()
			last[key] = synth
			mu.Unlock()
		}
	}
}

// fetchDiskStatus dials the agent's :1025 endpoint with the AUTH line
// and returns the per-disk status array.
func fetchDiskStatus(ctx context.Context, ip, token string) ([]agentDiskReport, error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			c, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if _, werr := c.Write([]byte(proto.AuthPrefix + token + "\n")); werr != nil {
				c.Close()
				return nil, fmt.Errorf("auth line: %w", werr)
			}
			return c, nil
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://%s:%d/disks/status", ip, agentDiskStatusPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent http %d", resp.StatusCode)
	}
	var body agentDiskStatusResp
	if err := decodeGuestProbe(resp.Body, &body); err != nil {
		return nil, err
	}
	return body.Disks, nil
}

type agentDiskStatusResp struct {
	Disks []agentDiskReport `json:"disks"`
}

// agentDiskReport mirrors the agent's diskStatus shape. Repeated here
// rather than imported because the vm package cannot import agent
// (build-tag-gated).
type agentDiskReport struct {
	DiskID    string `json:"disk_id"`
	MountPath string `json:"mount_path"`
	Status    string `json:"status"`
	Error     string `json:"error"`
}
