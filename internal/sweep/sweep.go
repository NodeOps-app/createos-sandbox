// Package sweep runs a one-shot maintenance pass, normally from a CronJob.
// It handles idle pause, stale lifecycle transitions, host heartbeat reaping,
// optional dead-host eviction, drain migration, and expired metadata cleanup.
// Asynchronous host work can continue after the pass exits; later runs observe
// persisted state and retry or advance the operation.
package sweep

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/NodeOps-app/createos-sandbox/database"
	"github.com/NodeOps-app/createos-sandbox/internal/audit"
	"github.com/NodeOps-app/createos-sandbox/internal/auditemit"
	"github.com/NodeOps-app/createos-sandbox/internal/billingemit"
	"github.com/NodeOps-app/createos-sandbox/internal/hostrpc"
	"github.com/NodeOps-app/createos-sandbox/internal/idlepause"
	"github.com/NodeOps-app/createos-sandbox/internal/sandboxlifecycle"
	schedclient "github.com/NodeOps-app/createos-sandbox/internal/scheduler/client"
	"github.com/NodeOps-app/createos-sandbox/internal/storage"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// Config is the resolved runtime configuration for a single sweep.
type Config struct {
	PostgresDSN string

	// Per-sweep cutoffs. Nonpositive values use defaults (5m / 15m / 5m).
	OrphanCreatingAge   time.Duration
	StuckTransitionAge  time.Duration
	OrphanDestroyingAge time.Duration

	// DeadHostEvictAfter ≤ 0 disables the dead-host eviction pass.
	DeadHostEvictAfter time.Duration

	// HostStaleAfter is the heartbeat freshness budget — hosts whose
	// last_seen is older than this get flipped to status=dead so the
	// scheduler stops placing on them. Nonpositive values use
	// models.HostHeartbeatStaleAfter; they do not disable reaping.
	HostStaleAfter time.Duration

	// Storage is the object-storage backend used to clean pause bundles for
	// orphan-destroying rows. Nil is valid for rows without a bundle.
	Storage storage.Storage

	// Drain runs when both clients are non-nil. Region selects the hosts
	// owned by this sweep. HTTPClient needs the control-role mTLS transport
	// when host listeners require client certificates.
	SchedulerClient *schedclient.Client
	HTTPClient      *http.Client
	Region          string

	DryRun bool
}

// Result is returned from Run with per-pass counts for telemetry.
type Result struct {
	OrphanCreating          int
	IdlePaused              int
	StuckPausing            int
	StuckResuming           int
	StuckForking            int
	OrphanDestroying        int
	HostsReaped             int // host rows flipped to dead by heartbeat staleness
	DeadHostEvicted         int
	DrainPaused             int // running→pause kicks during drain
	DrainResumed            int // paused→resume kicks during drain
	DrainBlocked            int // running sandboxes held after exhausting pause retries
	ScheduledRevokes        int // issued_certs rows whose grace window elapsed
	ExpiredSessions         int // device_sessions past TTL
	StaleNetworkMemberships int // terminal sandbox / deleted-network join rows
}

// drainPauseMaxAttempts is the per-sandbox pause-retry budget during
// drain. After this many consecutive failed pause-trigger attempts,
// sweep leaves the sandbox intact and reports the blocked drain for operator
// recovery. Exhausting retries must never authorize workload destruction.
const drainPauseMaxAttempts = 5

// classifyDrainRows separates actionable states from asynchronous states that
// must merely be waited on. A non-zero pending count prevents a slow pause (or
// another in-flight lifecycle transition) from completing the host drain.
func classifyDrainRows(rows []models.Sandbox) (running, paused []models.Sandbox, pending int) {
	for _, r := range rows {
		switch r.Status {
		case models.StatusRunning:
			running = append(running, r)
		case models.StatusPaused:
			paused = append(paused, r)
		case models.StatusCreating, models.StatusPausing,
			models.StatusResuming, models.StatusDestroying:
			pending++
		}
	}
	return running, paused, pending
}

func (c *Config) defaults() {
	if c.OrphanCreatingAge <= 0 {
		c.OrphanCreatingAge = 5 * time.Minute
	}
	if c.StuckTransitionAge <= 0 {
		c.StuckTransitionAge = 15 * time.Minute
	}
	if c.OrphanDestroyingAge <= 0 {
		c.OrphanDestroyingAge = 5 * time.Minute
	}
	if c.HostStaleAfter <= 0 {
		c.HostStaleAfter = models.HostHeartbeatStaleAfter
	}
}

// Run executes every sweep pass once and returns aggregate counts.
// Initialization failures are returned. Later failures do not abort subsequent
// passes; some are logged, so a nil error does not prove every action succeeded.
func Run(ctx context.Context, cfg Config, log func(string, ...any)) (Result, error) {
	if log == nil {
		log = func(string, ...any) {}
	}
	cfg.defaults()
	if cfg.PostgresDSN == "" {
		return Result{}, fmt.Errorf("postgres-dsn required")
	}

	db, err := database.OpenDb(ctx, cfg.PostgresDSN)
	if err != nil {
		return Result{}, fmt.Errorf("open db: %w", err)
	}
	defer db.Close()
	repo := &models.Repo{DB: db}
	// Pass the billing emitter into lifecycle updates that support atomic
	// status/event writes. With no shape provider, CPU allocation falls back
	// to vCPU * 1000 rather than a shape-specific fractional quota.
	emitter := billingemit.New(db, nil)
	auditEmitter := auditemit.New(db, 90*24*time.Hour)

	res := Result{}
	now := time.Now()

	// --- 0. idle auto-pause -----------------------------------------------
	if idle, err := idlepause.RunOnce(ctx, db, cfg.Region, cfg.DryRun); err != nil {
		log("idle-pause: %v", err)
	} else if cfg.DryRun && len(idle.Candidates) > 0 {
		log("idle-pause: DRY-RUN would flip %d rows to pausing: %v", len(idle.Candidates), idle.Candidates)
	} else if len(idle.Flipped) > 0 {
		res.IdlePaused = len(idle.Flipped)
		log("idle-pause: flipped %d rows to pausing: %v", len(idle.Flipped), idle.Flipped)
	}

	// --- 1. orphan-creating -----------------------------------------------
	if cfg.DryRun {
		log("orphan-creating: dry-run, skipping (no read-only query yet)")
	} else if ids, err := repo.FailOrphanCreating(ctx, now.Add(-cfg.OrphanCreatingAge), cfg.Region, emitter); err != nil {
		log("orphan-creating: %v", err)
	} else if len(ids) > 0 {
		res.OrphanCreating = len(ids)
		log("orphan-creating: flipped %d rows to failed: %v", len(ids), ids)
	}

	// --- 2. stuck pausing -------------------------------------------------
	transitionCutoff := now.Add(-cfg.StuckTransitionAge)
	if rows, err := repo.ListStuckPausing(ctx, transitionCutoff, cfg.Region); err != nil {
		log("stuck-pausing: list: %v", err)
	} else {
		for _, r := range rows {
			if cfg.DryRun {
				log("stuck-pausing: DRY-RUN would flip %s", r.ID)
				continue
			}
			msg := fmt.Sprintf("pause exceeded %s; sweep flipped to error", cfg.StuckTransitionAge)
			if st, err := repo.MarkStuckPauseFailed(ctx, r.ID, &msg, emitter); err == nil && st != "" {
				res.StuckPausing++
				log("stuck-pausing: flipped %s → error", r.ID)
			}
		}
	}

	// --- 3. stuck resuming ------------------------------------------------
	if rows, err := repo.ListStuckResuming(ctx, transitionCutoff, cfg.Region); err != nil {
		log("stuck-resuming: list: %v", err)
	} else {
		for _, r := range rows {
			if cfg.DryRun {
				log("stuck-resuming: DRY-RUN would flip %s", r.ID)
				continue
			}
			msg := fmt.Sprintf("resume exceeded %s; sweep rolled back to paused", cfg.StuckTransitionAge)
			if st, err := repo.MarkResumeExhausted(ctx, r.ID, &msg); err == nil && st != "" {
				res.StuckResuming++
				log("stuck-resuming: rolled back %s → paused", r.ID)
			}
		}
	}

	// --- 3b. stuck forking ------------------------------------------------
	// A fork's background goroutine (handlers.runForkBackground) may die
	// silently — process restart between MarkForking and MarkForkPaused,
	// an object-storage outage longer than the in-process retry budget, or a panic
	// in the goroutine. No host owns the row (host = '' until MarkForkPaused
	// + auto-resume schedule it), so no reconciler will ever claim it.
	// Flip the row to 'failed' once it exceeds the transition cutoff so
	// the user sees the failure + can retry the fork.
	if rows, err := repo.ListStuckForking(ctx, transitionCutoff, cfg.Region); err != nil {
		log("stuck-forking: list: %v", err)
	} else {
		for _, r := range rows {
			if cfg.DryRun {
				log("stuck-forking: DRY-RUN would flip %s", r.ID)
				continue
			}
			msg := fmt.Sprintf("fork exceeded %s; sweep flipped to error", cfg.StuckTransitionAge)
			if st, err := repo.MarkForkFailed(ctx, r.ID, &msg, emitter); err == nil && st != "" {
				res.StuckForking++
				log("stuck-forking: flipped %s → failed", r.ID)
				// The terminal child releases its source bundle lease. A lost
				// worker may have copied only some objects before exiting.
				if cfg.Storage != nil {
					cleanupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
					for _, name := range []string{storage.ArtifactMemfile, storage.ArtifactVMState, storage.ArtifactOverlay, storage.ArtifactManifest} {
						if err := cfg.Storage.Delete(cleanupCtx, storage.BundlePrefix(r.ID)+name); err != nil {
							log("stuck-forking: cleanup %s artifact=%s: %v", r.ID, name, err)
						}
					}
					cancel()
				}
			}
		}
	}

	// --- 4. orphan destroying (no host stamped) ---------------------------
	if rows, err := repo.ListStuckOrphanDestroying(ctx, now.Add(-cfg.OrphanDestroyingAge), cfg.Region); err != nil {
		log("orphan-destroying: list: %v", err)
	} else {
		for _, r := range rows {
			if cfg.DryRun {
				log("orphan-destroying: DRY-RUN would clean %s (uri=%s)", r.ID, r.SnapshotURI)
				continue
			}
			deleteFailed := false
			if cfg.Storage == nil && r.SnapshotURI != "" {
				log("orphan-destroying: storage unavailable for %s; retaining destroying state", r.ID)
				continue
			}
			if cfg.Storage != nil && r.SnapshotURI != "" {
				prefix := storage.BundlePrefix(r.ID)
				for _, art := range []string{storage.ArtifactMemfile, storage.ArtifactVMState, storage.ArtifactOverlay, storage.ArtifactManifest} {
					if err := cfg.Storage.Delete(ctx, prefix+art); err != nil {
						deleteFailed = true
						log("orphan-destroying: delete %s artifact=%s: %v", r.ID, art, err)
					}
				}
			}
			if deleteFailed {
				// Keep the row in destroying so the next sweep retries. Publishing
				// destroyed here would orphan a partially deleted snapshot bundle.
				continue
			}
			transitioned, err := repo.MarkDestroyedFromDestroyingCAS(ctx, r.ID, time.Now().UTC(), nil, emitter)
			if err != nil {
				log("orphan-destroying: finalize %s: %v", r.ID, err)
				continue
			}
			if !transitioned {
				continue
			}
			// This pass only finalizes a destroy initiated elsewhere. The
			// initiator (user, TTL, host-death, drain, etc.) owns the one
			// logical sandbox.destroy audit event. Emitting another event here
			// makes a recovered paused delete look like two separate destroys.
			// Billing remains exactly-once in the status CAS above.
			res.OrphanDestroying++
			log("orphan-destroying: flipped %s → destroyed", r.ID)
		}
	}

	// --- 5. heartbeat reap (host last_seen staleness) ---------------------
	if !cfg.DryRun {
		if n, err := repo.MarkStaleHosts(ctx, now.Add(-cfg.HostStaleAfter), cfg.Region); err != nil {
			log("reap: %v", err)
		} else if n > 0 {
			res.HostsReaped = n
			log("reap: marked %d host(s) dead", n)
		}
	}

	// Retention is region-scoped and bounded so event history cannot grow forever.
	if !cfg.DryRun {
		if n, err := repo.SweepExpiredEvents(ctx, cfg.Region, now); err != nil {
			log("events retention: %v", err)
		} else if n > 0 {
			log("events retention: removed %d expired events", n)
		}
	}

	// --- 6. dead-host eviction --------------------------------------------
	if cfg.DeadHostEvictAfter > 0 && cfg.Region != "" {
		hosts, err := repo.ListHosts(ctx)
		if err != nil {
			log("dead-host-evict: list hosts: %v", err)
		} else {
			hostCutoff := now.Add(-cfg.DeadHostEvictAfter)
			for _, h := range hosts {
				if h.Region != cfg.Region || h.Status != models.HostStatusDead || !h.LastSeen.Before(hostCutoff) {
					continue
				}
				recs, err := repo.List(ctx, h.ID, "", "", 10000)
				if err != nil {
					log("dead-host-evict: list sandboxes for host=%s: %v", h.ID, err)
					continue
				}
				note := fmt.Sprintf("host %s offline > %s (sweep)", h.ID, cfg.DeadHostEvictAfter)
				for _, r := range recs {
					// `destroying` is included on purpose: a destroy
					// kick that landed before the host went dead leaves
					// the row pinned forever — control's eager destroy
					// never returned, and the host-side reconcile-tick
					// can't drain because the host is gone. Paused rows
					// are NOT evicted — their durable pause bundle can be restored
					// on a different host via /resume.
					if r.Status != models.StatusRunning &&
						r.Status != models.StatusCreating &&
						r.Status != models.StatusDestroying {
						continue
					}
					if cfg.DryRun {
						log("dead-host-evict: DRY-RUN would destroy %s on dead host %s", r.ID, h.ID)
						continue
					}
					changed, err := repo.MarkDestroyedOnDeadHost(ctx, r.ID, h.ID, cfg.Region, hostCutoff, time.Now().UTC(), &note, emitter)
					if err != nil {
						log("dead-host-evict: sandbox=%s host=%s: %v", r.ID, h.ID, err)
						continue
					}
					if changed {
						res.DeadHostEvicted++
						auditEmitter.Emit(ctx, audit.Context{
							UserID: r.CreatedBy, Actor: "sweeper",
							SubjectType: "sandbox", SubjectID: r.ID,
						}, audit.ActionSandboxDestroy, audit.OperationRemove,
							audit.BuildSandboxDestroy(&r, "host_dead", models.StatusDestroyed))
					}
				}
			}
		}
	}

	// --- 7. drain orchestration -------------------------------------------
	// Hosts marked draining are advanced by runDrain. It requests pauses for
	// running rows and resumes paused rows associated with the source host.
	// Accepted pause responses acknowledge the request, not completed capture;
	// subsequent passes wait for lifecycle state to advance.
	if cfg.SchedulerClient != nil && cfg.HTTPClient != nil {
		runDrain(ctx, repo, cfg, &res, log)
	}

	// --- 8. scheduled cert revocations ------------------------------------
	// Host cert rotations stamp scheduled_revoke_at = now()+grace on the
	// predecessor; this pass flips revoked_at once the grace elapsed so
	// the CRL surfaces the tombstone.
	if !cfg.DryRun {
		if n, err := models.ApplyScheduledRevocations(ctx, db, now); err != nil {
			log("scheduled-revokes: %v", err)
		} else if n > 0 {
			res.ScheduledRevokes = n
			log("scheduled-revokes: tombstoned %d cert(s)", n)
		}
	}

	// --- 9. expired device sessions ---------------------------------------
	// EU removes expired device-session rows. Relay and host reconciliation
	// subsequently remove peers and routes no longer authorized by those rows.
	if !cfg.DryRun && cfg.Region == models.EuropeRegion {
		if devIDs, err := repo.ExpireDeviceSessions(ctx); err != nil {
			log("expired-sessions: %v", err)
		} else if len(devIDs) > 0 {
			res.ExpiredSessions = len(devIDs)
			log("expired-sessions: dropped %d row(s)", len(devIDs))
		}
	}

	// --- 10. stale sandbox-network memberships ----------------------------
	// Destroy normally removes memberships transactionally, but failed
	// sandboxes and soft-deleted networks can leave historical join rows.
	// Remove only those joins; never destroy a VM as a side effect of GC.
	if cfg.DryRun {
		if n, err := repo.CountStaleNetworkMemberships(ctx, cfg.Region); err != nil {
			log("stale-network-memberships: count: %v", err)
		} else if n > 0 {
			log("stale-network-memberships: DRY-RUN would remove %d row(s)", n)
		}
	} else if n, err := repo.SweepStaleNetworkMemberships(ctx, cfg.Region); err != nil {
		log("stale-network-memberships: %v", err)
	} else if n > 0 {
		res.StaleNetworkMemberships = n
		log("stale-network-memberships: removed %d row(s)", n)
	}

	log("summary orphan_creating=%d stuck_pausing=%d stuck_resuming=%d stuck_forking=%d orphan_destroying=%d hosts_reaped=%d dead_host_evicted=%d drain_paused=%d drain_resumed=%d drain_blocked=%d scheduled_revokes=%d expired_sessions=%d stale_network_memberships=%d dry_run=%v",
		res.OrphanCreating, res.StuckPausing, res.StuckResuming, res.StuckForking, res.OrphanDestroying,
		res.HostsReaped, res.DeadHostEvicted,
		res.DrainPaused, res.DrainResumed, res.DrainBlocked, res.ScheduledRevokes, res.ExpiredSessions,
		res.StaleNetworkMemberships, cfg.DryRun)
	return res, nil
}

// runDrain advances drain migration once per sweep. Failed pause triggers
// increment the persisted DrainPauseAttempts counter across runs. At the
// retry limit the sandbox is preserved and the drain requires operator recovery.
// Accepted triggers reset that counter; later runs observe pause completion
// and start resume placement. The sweeper does not wait for the VM to run.
func runDrain(ctx context.Context, repo *models.Repo, cfg Config, res *Result, log func(string, ...any)) {
	hosts, err := repo.ListHosts(ctx)
	if err != nil {
		log("drain: list hosts: %v", err)
		return
	}
	resumeDeps := sandboxlifecycle.ResumeDeps{
		Repo:     repo,
		Client:   cfg.SchedulerClient,
		HostHTTP: cfg.HTTPClient,
		Region:   cfg.Region,
	}
	for _, h := range hosts {
		if h.Region != cfg.Region || h.Status != models.HostStatusDraining {
			continue
		}
		// ListPinnedToHost: matches `host_id = h.ID` OR (paused AND
		// `cached_host_id = h.ID`). The second branch is what catches
		// VMs paused during earlier drain passes — MarkPaused wipes
		// host_id but keeps cached_host_id so locality scoring on
		// resume can prefer the original host. We rely on that same
		// breadcrumb to know what's still pending migration.
		rows, err := repo.ListPinnedToHost(ctx, h.ID, 1000)
		if err != nil {
			log("drain: host=%s list: %v", h.ID, err)
			continue
		}
		running, paused, pendingTransitions := classifyDrainRows(rows)
		if len(running) == 0 && len(paused) == 0 && pendingTransitions == 0 {
			if _, err := repo.SetHostStatus(ctx, h.ID, models.HostStatusActive); err != nil {
				log("drain: host=%s reset status: %v", h.ID, err)
				continue
			}
			log("drain: host=%s complete; status=active scheduling_disabled=true", h.ID)
			continue
		}
		log("drain: host=%s running=%d paused=%d transitioning=%d (migrating)",
			h.ID, len(running), len(paused), pendingTransitions)
		if cfg.DryRun {
			continue
		}
		for _, r := range running {
			// Keep the workload intact when pause cannot be started. This running
			// row continues to prevent drain completion on subsequent passes.
			if r.DrainPauseAttempts >= drainPauseMaxAttempts {
				log("drain: host=%s sandbox=%s: blocked after %d failed pauses; sandbox preserved; operator recovery required", h.ID, r.ID, r.DrainPauseAttempts)
				res.DrainBlocked++
				continue
			}
			response, err := hostrpc.Pause(ctx, cfg.HTTPClient, h, r.ID, r.CreatedBy)
			if err != nil {
				n, _ := repo.IncDrainPauseAttempts(ctx, r.ID)
				log("drain: host=%s sandbox=%s: pause failed (attempt %d/%d): %v", h.ID, r.ID, n, drainPauseMaxAttempts, err)
				continue
			}
			response.Body.Close()
			if !hostrpc.PauseAccepted(response) {
				n, _ := repo.IncDrainPauseAttempts(ctx, r.ID)
				log("drain: host=%s sandbox=%s: pause returned %d (attempt %d/%d)", h.ID, r.ID, response.StatusCode, n, drainPauseMaxAttempts)
				continue
			}
			// Pause trigger succeeded — clear the counter so a later
			// cordon/uncordon/recordon cycle starts fresh.
			_ = repo.ResetDrainPauseAttempts(ctx, r.ID)
			res.DrainPaused++
		}
		for _, r := range paused {
			if err := sandboxlifecycle.KickoffResume(ctx, resumeDeps, r.ID); err != nil {
				log("drain: host=%s sandbox=%s: resume kickoff failed: %v", h.ID, r.ID, err)
				continue
			}
			res.DrainResumed++
		}
	}
}
