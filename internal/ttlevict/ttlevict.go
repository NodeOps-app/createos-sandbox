// Package ttlevict runs a one-shot, region-scoped sweep of running sandboxes
// past their default or per-owner TTL. Age is measured from running_at, falling
// back to created_at; resume starts a new running window. Paused sandboxes and
// unclaimed pool inventory are excluded, and unfinished snapshot capture blocks
// eviction until capture completes.
//
// The evictor marks eligible rows destroyed in Postgres without calling hosts.
// Host reconciliation subsequently tears down local VMs; a database transition
// does not mean the VM process has already stopped.
package ttlevict

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/NodeOps-app/createos-sandbox/database"
	"github.com/NodeOps-app/createos-sandbox/internal/audit"
	"github.com/NodeOps-app/createos-sandbox/internal/auditemit"
	"github.com/NodeOps-app/createos-sandbox/internal/billingemit"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// Config is the resolved runtime configuration for a single sweep.
type Config struct {
	PostgresDSN string                   // same DSN the control plane uses
	MaxAge      time.Duration            // default running-window TTL
	UserMaxAge  map[string]time.Duration // per-owner running-window overrides
	Region      string                   // scope this sweep to sandboxes in this region
	DryRun      bool                     // SELECT only, no UPDATE
}

// Result is returned from Run for callers (tests, the CLI) to inspect.
type Result struct {
	Aged      int // rows that would or did flip to destroyed
	Destroyed int // rows actually updated (0 when DryRun)
}

// Run executes one TTL sweep. Validation, database, query, transaction, and
// billing failures are returned. Billing events commit with the state changes;
// audit emission happens afterward and does not determine the returned counts.
func Run(ctx context.Context, cfg Config, log func(string, ...any)) (Result, error) {
	if log == nil {
		log = func(string, ...any) {}
	}
	if cfg.PostgresDSN == "" {
		return Result{}, fmt.Errorf("postgres-dsn required")
	}
	if cfg.MaxAge <= 0 {
		return Result{}, fmt.Errorf("max-age must be > 0")
	}
	if cfg.Region == "" {
		return Result{}, fmt.Errorf("region required (would otherwise sweep every region's sandboxes)")
	}

	now := time.Now().UTC()
	userCutoffs := make(map[string]time.Time, len(cfg.UserMaxAge))
	for user, maxAge := range cfg.UserMaxAge {
		if strings.TrimSpace(user) == "" || user != strings.TrimSpace(user) || user == "pool" || maxAge <= 0 {
			return Result{}, fmt.Errorf("user_max_age requires a nonempty non-pool user and positive duration")
		}
		userCutoffs[user] = now.Add(-maxAge)
	}

	// OpenDb connects to Postgres and loads the queries.sql catalog.
	// The evictor uses the same named queries the control plane does,
	// so it reuses the same loading path — one place to update SQL.
	db, err := database.OpenDb(ctx, cfg.PostgresDSN)
	if err != nil {
		return Result{}, fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	cutoff := now.Add(-cfg.MaxAge)
	log("cutoff=%s max_age=%s user_overrides=%d dry_run=%v",
		cutoff.Format(time.RFC3339), cfg.MaxAge, len(userCutoffs), cfg.DryRun)

	res := Result{}

	if cfg.DryRun {
		// Dry-run path: SELECT only, no UPDATE — bypass the model
		// function (which always writes inside a tx) and use the raw
		// listAgedRunning query.
		sql, ok := db.GetQuery("listAgedRunning")
		if !ok {
			return Result{}, fmt.Errorf("query %q not found in queries.sql", "listAgedRunning")
		}
		var rows pgx.Rows
		rows, err = db.Con.Query(ctx, sql, cutoff, cfg.Region, userCutoffs)
		if err != nil {
			return Result{}, fmt.Errorf("sweep query: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var id, host string
			var createdAt time.Time
			if err := rows.Scan(&id, &host, &createdAt); err != nil {
				return res, fmt.Errorf("scan: %w", err)
			}
			res.Aged++
			age := time.Since(createdAt).Truncate(time.Second)
			log("DRY-RUN would destroy id=%s host=%s age=%s", id, host, age)
		}
		if err := rows.Err(); err != nil {
			return res, fmt.Errorf("iterate: %w", err)
		}
		log("summary aged=%d destroyed=%d dry_run=%v", res.Aged, res.Destroyed, cfg.DryRun)
		return res, nil
	}

	// Non-dry path: go through models.MarkAgedRunningDestroyed so each
	// flipped row emits a sandbox.destroyed billing event atomically
	// with its status update. The model locks candidates and rechecks state,
	// TTL, and active capture reservations before updating them.
	emitter := billingemit.New(db, nil)
	auditEmitter := auditemit.New(db, 90*24*time.Hour)
	note := "ttl-evict: running lifetime exceeded"
	flipped, err := models.MarkAgedRunningDestroyed(ctx, db, cutoff, now, note, cfg.Region, userCutoffs, emitter)
	if err != nil {
		return Result{}, fmt.Errorf("sweep query: %w", err)
	}
	for _, r := range flipped {
		res.Aged++
		res.Destroyed++
		age := time.Since(r.CreatedAt).Truncate(time.Second)
		log("destroyed id=%s host=%s age=%s", r.ID, r.HostID, age)
		if rec, getErr := models.GetSandbox(ctx, db, r.ID); getErr == nil && rec != nil {
			auditEmitter.Emit(ctx, audit.Context{
				UserID: rec.CreatedBy, Actor: "ttl-evictor",
				SubjectType: "sandbox", SubjectID: r.ID,
			}, audit.ActionSandboxDestroy, audit.OperationRemove,
				audit.BuildSandboxDestroy(rec, "ttl", models.StatusDestroyed))
		}
	}
	log("summary aged=%d destroyed=%d dry_run=%v", res.Aged, res.Destroyed, cfg.DryRun)
	return res, nil
}
