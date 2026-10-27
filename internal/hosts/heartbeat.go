// heartbeat.go — the recurring host→control heartbeat loop. Registration
// is done synchronously up-front by Serve (see register.go); this file
// owns just the ticker + the final draining beat on shutdown.
package hosts

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/hosts/controlclient"
	"github.com/NodeOps-app/sandbox/internal/hosts/vm"
	"github.com/NodeOps-app/sandbox/internal/proto"
	"github.com/NodeOps-app/sandbox/models"
)

// HeartbeatConfig controls the heartbeat loop.
type HeartbeatConfig struct {
	HostID   string        // hostname
	Interval time.Duration // heartbeat interval, default 5s
	// DiskPath is statfs'd at heartbeat time to report disk usage to
	// control. Typically the snapshot or overlay directory.
	DiskPath string
}

// HeartbeatStater supplies dynamic metrics for the heartbeat body.
type HeartbeatStater interface {
	// Snapshot returns (inUseMib, vmCount).
	Snapshot() (inUseMib int, vmCount int)
}

// ShapeApplier installs a fresh shape catalog pushed by control on each
// heartbeat. *vm.Manager satisfies it via SetShapes. The kicker callback
// is invoked AFTER a successful swap so the host can rebuild prewarmed
// snapshots for newly-added shapes.
type ShapeApplier interface {
	SetShapes(s []vm.Shape) bool
}

// runHeartbeat heartbeats until ctx is cancelled. On ctx.Done it sends one
// final best-effort status=draining heartbeat and returns.
//
// applier (optional, nil-safe) receives the catalog from each heartbeat
// response. kickPrewarm (optional) fires after a successful swap so the
// host rebuilds snapshots for any shapes the new catalog added.
func runHeartbeat(ctx context.Context, cfg HeartbeatConfig, repo *controlclient.Client, state HeartbeatStater, applier ShapeApplier, kickPrewarm func()) error {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	if repo == nil {
		return fmt.Errorf("heartbeat: controlclient is required")
	}

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	var consecutiveFailures int
	backoff := time.Second

	for {
		select {
		case <-ctx.Done():
			drainCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			inUse, vmCount := state.Snapshot()
			_, _ = repo.Heartbeat(drainCtx, proto.ControlHostHeartbeatReq{
				ID: cfg.HostID, InUseMib: inUse, VMCount: vmCount, Status: models.HostStatusDraining,
			})
			cancel()
			log.WithContext(ctx).Info("[hostagent] sent draining heartbeat, exiting")
			return nil

		case <-ticker.C:
			inUse, vmCount := state.Snapshot()
			resp, err := repo.Heartbeat(ctx, proto.ControlHostHeartbeatReq{
				ID: cfg.HostID, InUseMib: inUse, VMCount: vmCount, Status: models.HostStatusActive,
				DiskUsedMib: CollectHardware(cfg.DiskPath).DiskUsedMib,
			})
			if err != nil {
				consecutiveFailures++
				log.WithContext(ctx).Warnf("[hostagent] heartbeat failed (%d consecutive): %v", consecutiveFailures, err)
				if consecutiveFailures >= 3 {
					backoff *= 2
					if backoff > 30*time.Second {
						backoff = 30 * time.Second
					}
					select {
					case <-ctx.Done():
					case <-time.After(backoff):
					}
				}
				continue
			}
			consecutiveFailures = 0
			backoff = time.Second
			// Apply the control-pushed shape catalog, if any. Empty
			// resp.Shapes (legacy control plane or no change announced)
			// → leave the current catalog alone. A genuine change kicks
			// prewarm so newly-added shapes build snapshots.
			if applier != nil && len(resp.Shapes) > 0 {
				if applier.SetShapes(resp.Shapes) {
					log.WithContext(ctx).Infof("[hostagent] applied %d shape catalog from control", len(resp.Shapes))
					if kickPrewarm != nil {
						kickPrewarm()
					}
				}
			}
		}
	}
}
