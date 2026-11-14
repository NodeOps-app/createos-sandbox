// Package idlepause implements the idle-pause sweep pass. It flips running
// sandboxes with auto_pause_after_seconds to 'pausing' once
// they've been inactive long enough. The host's existing reconcile loop
// (internal/hosts/loops.go) picks up 'pausing' rows and calls RunPauseAsync —
// no HTTP call from the sweeper is needed.
package idlepause

import (
	"context"
	"fmt"

	"github.com/NodeOps-app/createos-sandbox/database"
	"github.com/NodeOps-app/createos-sandbox/models"
)

const (
	// idleThresholdBytes is the exclusive upper bound for the metered-byte
	// delta since the last baseline update. The allowance tolerates small
	// amounts of background traffic; it does not distinguish user traffic
	// from liveness probes or measure CPU activity. The time window depends
	// on sweep cadence and whether prior baseline updates succeeded.
	idleThresholdBytes = 24 * 1024
)

// Result describes one region-scoped idle-pause pass.
type Result struct {
	Candidates []string
	Flipped    []string
}

// RunOnce performs one region-scoped idle-pause pass. In dry-run mode it only
// reports candidates and leaves both status and metering baselines unchanged.
func RunOnce(ctx context.Context, db *database.Db, region string, dryRun bool) (Result, error) {
	// Step 1: find sandboxes whose activity window has expired AND whose
	// bandwidth delta since the last sweep is below the idle threshold.
	candidates, err := models.ListIdleSandboxes(ctx, db, idleThresholdBytes, region)
	if err != nil {
		return Result{}, fmt.Errorf("list idle sandboxes: %w", err)
	}
	result := Result{Candidates: make([]string, 0, len(candidates))}
	for _, sb := range candidates {
		result.Candidates = append(result.Candidates, sb.ID)
	}
	if dryRun {
		return result, nil
	}

	// Step 2: lock candidates and skip active snapshot captures. Recheck state
	// and idle settings before flipping; skipped rows are reconsidered next sweep.
	// The byte-delta predicate is checked during candidate selection above.
	if len(result.Candidates) > 0 {
		flipped, ferr := models.MarkIdlePausing(ctx, db, result.Candidates)
		if ferr != nil {
			return result, fmt.Errorf("mark idle pausing: %w", ferr)
		}
		result.Flipped = flipped
	}

	// Step 3: snapshot current metered bytes for ALL running auto-pause
	// sandboxes in this region so the NEXT sweep measures the delta from here,
	// not the accumulated total since the last user API call. Without this,
	// long-running VMs accumulate enough liveness-probe traffic to exceed
	// the threshold and never get paused.
	if err := models.SnapshotMeteredBytes(ctx, db, region); err != nil {
		return result, fmt.Errorf("snapshot metered bytes: %w", err)
	}

	return result, nil
}
