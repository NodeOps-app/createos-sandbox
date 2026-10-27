// Package idlepause implements the idle-pause sweep pass. It flips running
// sandboxes with auto_pause_after_seconds to 'pausing' once
// they've been inactive long enough. The host's existing reconcile loop
// (internal/hosts/loops.go) picks up 'pausing' rows and calls RunPauseAsync —
// no HTTP call from the sweeper is needed.
package idlepause

import (
	"context"
	"fmt"

	"github.com/NodeOps-app/sandbox/database"
	"github.com/NodeOps-app/sandbox/models"
)

const (
	// idleThresholdBytes is the maximum metered-byte delta over one sweep
	// interval that we treat as "no real activity".
	//
	// Baseline: the host's liveness probe opens a TCP connection to the VM
	// every 5 s — roughly 80 B/s combined egress + ingress, or ~2.4-4.8 KB
	// at the expected 30-60 s sweep cadence. The 24 KB allowance keeps that
	// incidental TCP overhead from preventing a pause, while real user traffic
	// normally exceeds it.
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

	// Step 2: flip idle candidates to 'pausing'. CAS on status='running'
	// prevents racing with user-initiated pause or destroy.
	if len(result.Candidates) > 0 {
		flipped, ferr := models.MarkIdlePausing(ctx, db, result.Candidates)
		if ferr != nil {
			return result, fmt.Errorf("mark idle pausing: %w", ferr)
		}
		result.Flipped = flipped
	}

	// Step 3: snapshot current metered bytes for ALL running auto-pause
	// sandboxes so the NEXT sweep measures the delta over one sweep interval,
	// not the accumulated total since the last user API call. Without this,
	// long-running VMs accumulate enough liveness-probe traffic to exceed
	// the threshold and never get paused.
	if err := models.SnapshotMeteredBytes(ctx, db, region); err != nil {
		return result, fmt.Errorf("snapshot metered bytes: %w", err)
	}

	return result, nil
}
