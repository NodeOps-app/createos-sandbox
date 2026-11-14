package hosts

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/hosts/api"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/controlclient"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/service"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/vm"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// reconcileTickLoop is the host's periodic DB↔memory drift fixer. The
// startup reconcile only catches drift that existed before this process
// ran; this ticker catches drift that develops *during* a run — e.g. a
// user-initiated Destroy whose MarkDestroyed failed (context cancel, DB
// blip), leaving the row stuck as `running` even though the VM is gone.
//
// Three directions per tick:
//   - forward: a 'running' DB row not in the manager is phantom → MarkDestroyed.
//   - reverse: a VM live on this host whose DB row is in a terminal state
//     gets killed locally. Transient pause/resume states are excluded so a
//     tick landing mid-pause doesn't rip the VM out from under the pause
//     goroutine — ListLiveIDs returns running+creating+pausing+resuming.
//   - destroying: a 'destroying' DB row whose eager DestroyOnHost from
//     control never landed (host overload, network blip, control crash
//     between MarkDestroying and the goroutine firing). Runs Mgr.Destroy
//     if still tracked, else CleanupOrphan with the DB row's fields, then
//     MarkDestroyed. Without this sweep destroying rows live forever.
//
// Runs until ctx cancels.
func reconcileTickLoop(ctx context.Context, repo *controlclient.Client, mgr *vm.Manager, svc *service.Service, hostname string) {
	// 5s cadence (was 30s) so the poll-driven pause/resume triggers feel
	// snappy when an HTTP wake-up drops. Most ticks are no-ops (the host
	// owns few rows in transitional states), so the extra DB load is
	// proportional to drain/pause activity rather than fleet size.
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			bg, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			runIDs, err := repo.ListRunningIDs(bg, hostname)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[reconcile-tick] list err: %v\n", err)
				cancel()
				continue
			}
			cleared := 0
			for _, id := range runIDs {
				if _, live := mgr.Lookup(id); live {
					continue
				}
				reconcileNote := "reconcile: not in manager"
				if err := repo.MarkDestroyed(bg, id, time.Now().UTC(), &reconcileNote); err == nil {
					cleared++
				}
			}
			// Only compare VMs that existed before the control-plane read.
			candidates := mgr.LiveIDs()
			liveIDs, err := repo.ListLiveIDs(bg, hostname)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[reconcile-tick] live-list err: %v\n", err)
				cancel()
				continue
			}
			liveSet := make(map[string]struct{}, len(liveIDs))
			for _, id := range liveIDs {
				liveSet[id] = struct{}{}
			}
			killed := 0
			for _, id := range candidates {
				if _, ok := liveSet[id]; ok {
					continue
				}
				// Absence from a list is not a delete instruction: the list
				// may predate creation or reflect replication lag. Require an
				// explicit terminal/destroying state still assigned to us.
				rec, err := repo.Get(bg, id)
				if err != nil || rec == nil || rec.HostID == nil || *rec.HostID != hostname {
					continue
				}
				switch rec.Status {
				case models.StatusDestroying, models.StatusDestroyed, models.StatusFailed:
				default:
					continue
				}
				if err := mgr.Destroy(id); err == nil {
					killed++
					// Idempotent CAS — no-op if the row is already destroyed
					// (it was destroyed externally by another path). Required
					// for the new async-delete flow: control flips the row to
					// `destroying` and returns; this tick runs the actual VM
					// teardown and is responsible for the final → `destroyed`
					// transition.
					destroyingNote := "destroyed by reconcile-tick (was destroying)"
					if err := repo.MarkDestroyed(bg, id, time.Now().UTC(), &destroyingNote); err == nil {
						mgr.ReleaseSlot(id)
					}
				} else {
					fmt.Fprintf(os.Stderr, "[reconcile-tick] destroy id=%s: %v\n", id, err)
				}
			}
			// ── Destroying sweep: rows the user asked to destroy that
			// control's eager DestroyOnHost either never reached or failed
			// to complete. Without this sweep the row sits in `destroying`
			// until the host process restarts.
			destroyingRecs, err := repo.List(bg, hostname, "", string(models.StatusDestroying), 500)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[reconcile-tick] destroying list err: %v\n", err)
			}
			destroyed := 0
			for _, r := range destroyingRecs {
				containerID := ""
				if r.ContainerID != nil {
					containerID = *r.ContainerID
				}
				// Always scrub per-VM artifacts first (idempotent: fc
				// kill, BPF detach, iptables teardown, file removals).
				// Catches anything the original Destroy missed, without
				// touching the slot's netns/veth.
				scrubSpec := vm.OrphanCleanupSpec{ID: r.ID, FCPid: r.FCPid}
				if r.IP != nil {
					scrubSpec.IP = *r.IP
				}
				if r.OverlayPath != nil {
					scrubSpec.OverlayPath = *r.OverlayPath
				}
				if r.APISock != nil {
					scrubSpec.APISock = *r.APISock
				}
				vm.CleanupVMArtifacts(scrubSpec)

				switch {
				case mgr.IsPendingRelease(r.ID):
					// Slot was already torn down by Mgr.Destroy and is
					// waiting in pendingRelease. Skip teardown — just
					// flip the row and release.
				case mgrHasLive(mgr, r.ID):
					if err := mgr.Destroy(r.ID); err != nil {
						fmt.Fprintf(os.Stderr, "[reconcile-tick] destroying %s: %v\n", r.ID, err)
						continue
					}
				case mgr.Pool != nil && mgr.Pool.IsOwned(containerID):
					// Slot already returned to the pool (a previous
					// destroy completed but MarkDestroyed failed and
					// the slot got returned anyway pre-pendingRelease,
					// OR this is a stale row whose slot was reused).
					// Don't touch the slot — pool owns it. Just flip
					// the DB row.
				default:
					// Manager doesn't know it, slot isn't in the pool,
					// not pending release — host restarted mid-flight,
					// firecracker died externally, etc. Best-effort
					// clean up whatever local state survived using the
					// DB row's fields.
					spec := vm.OrphanCleanupSpec{ID: r.ID, FCPid: r.FCPid}
					if r.IP != nil {
						spec.IP = *r.IP
					}
					if containerID != "" {
						spec.ContainerID = containerID
					}
					if r.APISock != nil {
						spec.APISock = *r.APISock
					}
					if r.OverlayPath != nil {
						spec.OverlayPath = *r.OverlayPath
					}
					vm.CleanupOrphan(spec)
				}
				note := "reconcile-tick: destroying → destroyed"
				if err := repo.MarkDestroyed(bg, r.ID, time.Now().UTC(), &note); err == nil {
					destroyed++
					mgr.ReleaseSlot(r.ID)
				}
			}

			// ── Pending-release drain: any slot Mgr.Destroy retained
			// because MarkDestroyed failed at the moment of teardown.
			// Re-check the row's status; once it's durably `destroyed`
			// (or `failed`), the slot can finally go back to NetPool.
			released := 0
			for _, id := range mgr.PendingReleaseIDs() {
				rec, err := repo.Get(bg, id)
				if err != nil {
					continue
				}
				if rec == nil || rec.Status == models.StatusDestroyed || rec.Status == models.StatusFailed {
					mgr.ReleaseSlot(id)
					released++
				}
			}
			// ── Orphan-netns sweep: any /var/run/netns/fcpN slot that
			// neither the NetPool owns, nor a live VM is using, nor a
			// pending-release slot references gets reaped. Final safety
			// net for any prior cleanup path that failed mid-flight,
			// ensuring IPAM range + iptables + veth + tap are returned
			// and no slot leaks across host restarts.
			liveCIDs := []string{}
			for _, id := range mgr.LiveIDs() {
				if sb, ok := mgr.Lookup(id); ok && sb.Net.ContainerID != "" {
					liveCIDs = append(liveCIDs, sb.Net.ContainerID)
				}
			}
			// Include pending-release slots so the reaper doesn't tear
			// down a netns the Manager is holding for an in-flight
			// destroy/MarkDestroyed handshake.
			for _, id := range mgr.PendingReleaseIDs() {
				if cid, ok := mgr.PendingReleaseContainerID(id); ok && cid != "" {
					liveCIDs = append(liveCIDs, cid)
				}
			}
			reapedSlots := 0
			if mgr.Pool != nil {
				reapedSlots = mgr.Pool.ReapOrphans(liveCIDs)
			}
			// ── Pause/Resume poll: rows assigned to me in transitional
			// states whose HTTP wake-up never arrived (control crashed,
			// network blip, sweep handed off a drain). Spawning runPause
			// /runResume is cheap: the in-process transitionInflight set
			// makes the second goroutine a no-op when HTTP already won.
			if svc != nil {
				go svc.ReconcileSnapshots(ctx)
				if rows, err := repo.List(bg, hostname, "", string(models.StatusPausing), 500); err == nil {
					for _, r := range rows {
						svc.RunPauseAsync(context.Background(), r.ID)
					}
				}
				if rows, err := repo.List(bg, hostname, "", string(models.StatusResuming), 500); err == nil {
					for _, r := range rows {
						svc.RunResumeAsync(context.Background(), r)
					}
				}
			}
			cancel()
			if cleared > 0 {
				fmt.Fprintf(os.Stderr, "[reconcile-tick] cleared %d phantom DB rows (of %d running)\n", cleared, len(runIDs))
			}
			if killed > 0 {
				fmt.Fprintf(os.Stderr, "[reconcile-tick] killed %d VM(s) marked destroyed externally\n", killed)
			}
			if destroyed > 0 {
				fmt.Fprintf(os.Stderr, "[reconcile-tick] cleared %d stuck destroying row(s)\n", destroyed)
			}
			if reapedSlots > 0 {
				fmt.Fprintf(os.Stderr, "[reconcile-tick] reaped %d orphan netns slot(s)\n", reapedSlots)
			}
		}
	}
}

// mgrHasLive reports whether the manager's Sandboxes map currently
// tracks this id. Wraps Lookup so the switch statement reads cleanly.
func mgrHasLive(mgr *vm.Manager, id string) bool {
	_, ok := mgr.Lookup(id)
	return ok
}

// cordonPollLoop refreshes the host's own cordon flag from the durable
// record every 5s, so handleCreate refuses creates locally even before
// the scheduler has seen the cordon flip on its next hydrate. Both the
// operator-set bit and a draining lifecycle state mean "no new VMs".
//
// Runs until ctx cancels.
func cordonPollLoop(ctx context.Context, repo *controlclient.Client, srv *api.Server, hostname string) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h, err := repo.GetHost(ctx, hostname)
			if err != nil || h == nil {
				continue
			}
			srv.SetCordoned(h.SchedulingDisabled || h.Status == models.HostStatusDraining)
		}
	}
}
