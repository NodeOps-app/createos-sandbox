package hosts

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/hosts/controlclient"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/vm"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// reconcile brings the set of running firecracker processes into agreement
// with the DB. Kubelet-style: the DB is the desired state, the running
// firecracker processes are the actual state.
//
// Three cases after walking both sides:
//
//  1. DB: running, VM: alive and matches → rehydrate (keep both).
//  2. DB: running, VM: gone / pid mismatch → mark row destroyed.
//  3. DB: not-running (destroyed / missing), VM: alive → kill the orphan
//     firecracker + best-effort clean up its netns and overlay.
//
// Returning:
//   - reservedIPs: IPs of case-1 survivors AND of any destroying rows
//     whose slot we're holding open until MarkDestroyed succeeds.
//     NetPool's IPAM must exclude them.
//   - aliveRecords: case-1 records so the caller can rehydrate them
//     after Manager is built.
//   - pendingDestroyingRecords: destroying rows whose slot/netns we
//     deliberately keep alive across startup so the slot stays pinned
//     in Manager.pendingRelease until MarkDestroyed lands. Without this
//     the slot's IP could be reassigned to a fresh VM while the old
//     row is still destroying.
func reconcile(ctx context.Context, repo *controlclient.Client, host string) (reservedIPs []string, aliveRecords []models.Sandbox, pendingDestroyingRecords []models.Sandbox, err error) {
	// Reconciliation only acts on these non-terminal states. Asking for
	// every historical row can exceed the control client's response cap
	// on a busy host and truncate the JSON envelope. Fetch each live state
	// separately so the desired-state snapshot stays small and explicit.
	var recs []models.Sandbox
	for _, status := range []models.Status{
		models.StatusRunning,
		models.StatusCreating,
		models.StatusPausing,
		models.StatusResuming,
		models.StatusDestroying,
	} {
		rows, listErr := repo.List(ctx, host, "", string(status), 1000)
		if listErr != nil {
			// The DB list is the authoritative desired state. Continuing with
			// a partial list makes surviving Firecracker processes look orphaned
			// and allows the startup reaper to kill healthy VMs.
			return nil, nil, nil, fmt.Errorf("list host sandboxes status=%s: %w", status, listErr)
		}
		recs = append(recs, rows...)
	}
	byID := make(map[string]models.Sandbox, len(recs))
	for _, r := range recs {
		byID[r.ID] = r
	}

	// ── Walk actual state: every live firecracker process on this host.
	live := scanLiveFirecrackers()
	now := time.Now().UTC()
	unwanted := 0
	for pid, id := range live {
		r, ok := byID[id]
		if ok && r.Status == models.StatusRunning && r.FCPid == pid {
			continue // healthy; handled below
		}
		// This firecracker is not reconciled to a running DB row. Kill it.
		// We may or may not have a DB record; if we do, use its persisted
		// fields to clean up the netns/overlay, otherwise just kill.
		fmt.Fprintf(os.Stderr, "[reconcile] killing unwanted firecracker pid=%d id=%s (db_status=%q, db_pid=%d)\n",
			pid, id, r.Status, r.FCPid)
		killFirecracker(pid)
		// Do not fetch an unassigned/paused row by id here: host ownership
		// is deliberately revoked when host_id is cleared. MarkPaused also
		// clears the runtime columns, so such a lookup cannot provide useful
		// cleanup metadata. CleanupOrphan still removes canonical resources
		// discoverable from the sandbox id and Firecracker pid.
		// Full teardown: iptables chains, netns, veth, overlay, api_sock.
		// Safe when r is zero-valued (unknown DB record) — every field is
		// optional and CleanupOrphan no-ops on missing identifiers.
		spec := vm.OrphanCleanupSpec{ID: id, FCPid: pid}
		if r.IP != nil {
			spec.IP = *r.IP
		}
		if r.ContainerID != nil {
			spec.ContainerID = *r.ContainerID
		}
		if r.APISock != nil {
			spec.APISock = *r.APISock
		}
		if r.OverlayPath != nil {
			spec.OverlayPath = *r.OverlayPath
		}
		vm.CleanupOrphan(spec)
		unwanted++
	}

	// ── Walk desired state: every DB row marked running.
	dead := 0
	for _, r := range recs {
		if r.Status != models.StatusRunning {
			continue
		}
		if r.IP == nil || *r.IP == "" {
			noIPNote := reconcileDeathNote(r.ID, "no IP recorded; assumed gone")
			_ = repo.MarkDestroyed(ctx, r.ID, now, &noIPNote)
			spec := vm.OrphanCleanupSpec{ID: r.ID, FCPid: r.FCPid}
			if r.ContainerID != nil {
				spec.ContainerID = *r.ContainerID
			}
			if r.APISock != nil {
				spec.APISock = *r.APISock
			}
			if r.OverlayPath != nil {
				spec.OverlayPath = *r.OverlayPath
			}
			vm.CleanupOrphan(spec)
			dead++
			continue
		}
		livePid, hasLive := findLivePidByID(live, r.ID)
		if !vmIPRouted(*r.IP) || !hasLive || r.FCPid != livePid {
			noProcNote := reconcileDeathNote(r.ID, "no matching firecracker process on serve start")
			_ = repo.MarkDestroyed(ctx, r.ID, now, &noProcNote)
			spec := vm.OrphanCleanupSpec{ID: r.ID, IP: *r.IP, FCPid: r.FCPid}
			if r.ContainerID != nil {
				spec.ContainerID = *r.ContainerID
			}
			if r.APISock != nil {
				spec.APISock = *r.APISock
			}
			if r.OverlayPath != nil {
				spec.OverlayPath = *r.OverlayPath
			}
			vm.CleanupOrphan(spec)
			dead++
			continue
		}
		reservedIPs = append(reservedIPs, *r.IP)
		aliveRecords = append(aliveRecords, r)
	}

	// ── Walk stuck-creating state: rows pinned to THIS host that never
	// reached 'running'. Cause: the host crashed/restarted between
	// scheduler ack and the Create handler finishing — or, in rare
	// cases, between `Manager.Sandboxes[id]=…` and the final status
	// flip. The sweeper would flip these to 'failed' after
	// `OrphanCreatingAge` (~5m) anyway, but the host has the strongest
	// evidence (firecracker isn't alive, host didn't survive), so we
	// fast-path it here on every reconcile.
	//
	// We CAS-gate the SQL on (status='creating' AND host_id=self) so a
	// row that legitimately raced to 'running' isn't trampled. Local
	// cleanup runs ONLY when flipped=true — see CleanupOrphan below.
	stuckCreating := 0
	for _, r := range recs {
		if r.Status != models.StatusCreating {
			continue
		}
		errText := "host restarted while sandbox was still creating"
		flipped, err := repo.MarkFailedFromCreatingCAS(ctx, r.ID, host, &errText, now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[reconcile] mark-failed-from-creating %s: %v\n", r.ID, err)
			continue
		}
		if !flipped {
			// Lost the CAS — the row moved out from under us (running,
			// destroying, etc.). Let the subsequent passes handle it.
			continue
		}
		// Whatever the host had managed to persist before crash — IP,
		// netns, overlay, api_sock — gets scrubbed so the slot can be
		// reused. CleanupOrphan no-ops on missing fields, so this is
		// safe even when the crash happened before any of them were
		// written.
		spec := vm.OrphanCleanupSpec{ID: r.ID, FCPid: r.FCPid}
		if r.IP != nil {
			spec.IP = *r.IP
		}
		if r.ContainerID != nil {
			spec.ContainerID = *r.ContainerID
		}
		if r.APISock != nil {
			spec.APISock = *r.APISock
		}
		if r.OverlayPath != nil {
			spec.OverlayPath = *r.OverlayPath
		}
		vm.CleanupOrphan(spec)
		stuckCreating++
	}

	// ── Walk pending-delete state: every DB row marked destroying.
	// User issued DELETE while host was down (or in between this serve's
	// start and the user's request). Two cases:
	//
	//  1. Row has a container_id + IP we can hang on to → KEEP the slot
	//     alive (don't tear down netns/veth). Reserve the IP, register
	//     the container_id as live, and hand the record to NewManager
	//     so it can stash a synthetic PooledNet in pendingRelease. The
	//     periodic tick later runs MarkDestroyed + ReleaseSlot, which
	//     tears down the slot atomically with the DB ack.
	//
	//  2. Row has no usable slot bookkeeping → just per-VM scrub +
	//     CleanupOrphan + MarkDestroyed inline; nothing to pin.
	pendingDelete := 0
	for _, r := range recs {
		if r.Status != models.StatusDestroying {
			continue
		}
		livePid, hasLive := findLivePidByID(live, r.ID)
		if hasLive {
			killFirecracker(livePid)
		}
		spec := vm.OrphanCleanupSpec{ID: r.ID, FCPid: r.FCPid}
		if r.IP != nil {
			spec.IP = *r.IP
		}
		if r.ContainerID != nil {
			spec.ContainerID = *r.ContainerID
		}
		if r.APISock != nil {
			spec.APISock = *r.APISock
		}
		if r.OverlayPath != nil {
			spec.OverlayPath = *r.OverlayPath
		}
		// Per-VM scrub is always safe (kills fc + clears BPF map +
		// removes per-VM iptables + removes overlay/api_sock). Leaves
		// the slot's netns/veth intact.
		vm.CleanupVMArtifacts(spec)
		if r.ContainerID != nil && *r.ContainerID != "" && r.IP != nil && *r.IP != "" {
			// Pin the slot. NetPool must NOT reap its netns and IPAM
			// must NOT allocate its IP — both happen via the
			// reservedIPs / liveContainerIDs sets the caller passes
			// into NewNetPool.
			reservedIPs = append(reservedIPs, *r.IP)
			pendingDestroyingRecords = append(pendingDestroyingRecords, r)
			pendingDelete++
			continue
		}
		// Fallback: nothing to pin. Tear down what we can and flip the row.
		vm.CleanupOrphan(spec)
		destroyingNote := "destroying → destroyed by reconcile"
		_ = repo.MarkDestroyed(ctx, r.ID, now, &destroyingNote)
		pendingDelete++
	}

	if len(aliveRecords) > 0 || dead > 0 || unwanted > 0 || pendingDelete > 0 || stuckCreating > 0 {
		fmt.Fprintf(os.Stderr, "[reconcile] %d alive (rehydrate), %d dead (marked destroyed), %d unwanted (killed), %d stuck-creating (marked failed), %d pending-delete (%d pinned for tick)\n",
			len(aliveRecords), dead, unwanted, stuckCreating, pendingDelete, len(pendingDestroyingRecords))
	}
	return reservedIPs, aliveRecords, pendingDestroyingRecords, nil
}

func reconcileDeathNote(id, reason string) string {
	if cause := vm.GuestConsoleCause(id); cause != "" {
		fmt.Fprintf(os.Stderr, "[reconcile] sandbox %s guest_cause=%s\n", id, cause)
		return reason + "; guest_cause=" + cause
	}
	return reason
}

// scanLiveFirecrackers returns pid→sandbox_id for every firecracker
// process on the host. sandboxIDFromCmdline extracts the ID from the
// explicit --id argument, independent of the API socket's runtime path.
func scanLiveFirecrackers() map[int]string {
	out := map[int]string{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if !pidIsFirecracker(pid) {
			continue
		}
		id := sandboxIDFromCmdline(pid)
		if id == "" {
			continue
		}
		out[pid] = id
	}
	return out
}

// sandboxIDFromCmdline reads /proc/<pid>/cmdline and extracts the sandbox
// id from the `--id <sb_id>` argument. Returns "" on miss.
//
// Historical bug: the previous implementation parsed the id out of the
// `--api-sock=<dir>/fc-<id>.sock` argument by `LastIndex("/fc-")`. That
// worked for the legacy `/tmp/fc-<id>.sock` layout, but the current
// per-VM runtime layout is `/var/lib/createos/runtime/<id>/fc.sock` —
// where `LastIndex("/fc-")` matches `/createos` at the *start* of the
// path. The resulting "id" was `spawn/runtime/<id>/fc`, which never
// matched any DB row, so reconcile() concluded the firecracker was
// orphaned and marked every running tenant VM destroyed across each
// `systemctl restart createos-serve`. Parsing `--id` directly is the
// fix: firecracker is always launched with `--id sb-<ulid>` (or
// `--id template-<key>` for prewarms).
func sandboxIDFromCmdline(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	for i := 0; i < len(args); i++ {
		var id string
		switch {
		case args[i] == "--id" && i+1 < len(args):
			id = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--id="):
			id = strings.TrimPrefix(args[i], "--id=")
		default:
			continue
		}
		// Skip prewarm template firecrackers — they're not sandboxes.
		// ReapOrphanedPrewarmTemplates owns their lifecycle.
		if strings.HasPrefix(id, "template-") {
			continue
		}
		if !strings.HasPrefix(id, "sb-") {
			continue
		}
		return id
	}
	return ""
}

func findLivePidByID(live map[int]string, id string) (int, bool) {
	for pid, lid := range live {
		if lid == id {
			return pid, true
		}
	}
	return 0, false
}

// killFirecracker SIGTERMs the PID (assumed to be firecracker; caller
// verified) and waits up to 3s for exit, then SIGKILLs.
func killFirecracker(pid int) {
	if pid <= 0 {
		return
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = p.Signal(os.Interrupt)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := p.Signal(syscall.Signal(0)); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = p.Kill()
	_, _ = p.Wait()
}

// pidIsFirecracker mirrors vm.pidIsFirecracker. Duplicated here to avoid
// exporting the helper; the cost is a few lines.
func pidIsFirecracker(pid int) bool {
	if pid <= 0 {
		return false
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(string(b)), "firecracker")
}

// vmIPRouted returns true iff the host kernel still has a route to vmIP
// via an fcp* interface — our proxy for "the netns is intact and the VM
// is likely still serving requests". Uses `ip route get` (not `show`)
// because the on-link route is /31, so an exact /32 lookup would miss it.
func vmIPRouted(vmIP string) bool {
	out, err := exec.Command("ip", "-o", "route", "get", vmIP).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "dev fcp")
}
