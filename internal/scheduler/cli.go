package scheduler

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/urfave/cli/v2"

	"github.com/NodeOps-app/sandbox/config"
	"github.com/NodeOps-app/sandbox/database"
	"github.com/NodeOps-app/sandbox/internal/leader"
	"github.com/NodeOps-app/sandbox/models"
)

// Cli is the urfave/cli Action for `control scheduler`.
func Cli(c *cli.Context) error {
	cfg, err := config.SchedulerFromContext(c)
	if err != nil {
		return err
	}
	database.SetTraceEnabled(cfg.TraceDB)
	repo, err := models.OpenRepo(context.Background(), cfg.PostgresDSN)
	if err != nil {
		return err
	}
	defer repo.Close()
	leaderID := cfg.LeaderID
	if leaderID == "" {
		if h, err := os.Hostname(); err == nil {
			leaderID = h
		} else {
			leaderID = "scheduler"
		}
	}
	inst, err := NewInstance(Config{
		LeaderID:                leaderID,
		WarmingPeriod:           cfg.WarmingPeriod,
		ReservationTTL:          cfg.ReservationTTL,
		HydrateInterval:         cfg.HydrateInterval,
		ReservationGracePeriod:  cfg.ReservationGracePeriod,
		PendingCap:              cfg.PendingCap,
		DiskSafetyPercent:       cfg.DiskSafetyPercent,
		DiskTransientReserveMiB: cfg.DiskTransientReserveMiB,
		DiskHeadroomConfigured:  true,
		Repo:                    repo,
	})
	if err != nil {
		return err
	}
	defer inst.Stop()

	// Open a separate pgxpool just for the leader's held conn so we don't
	// starve the repo's pool of a worker.
	leaderPool, err := pgxpool.New(context.Background(), cfg.PostgresDSN)
	if err != nil {
		return fmt.Errorf("leader pool: %w", err)
	}
	defer leaderPool.Close()

	elector := leader.New(leader.Config{
		Pool: leaderPool,
		Key:  cfg.LeaderKey,
	}, leader.Callbacks{
		OnAcquire: func(ctx context.Context) error {
			inst.SetEpoch(0) // reset; the leader's own epoch will increment
			return inst.LeaderCallbacks().OnAcquire(ctx)
		},
		OnLose: inst.LeaderCallbacks().OnLose,
	})

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		// Mirror the elector's epoch into the instance so /readyz reports
		// the same fencing token.
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-t.C:
				inst.SetEpoch(elector.Epoch())
			}
		}
	}()
	go func() { _ = elector.Run(runCtx) }()

	// Scheduler runs unauthenticated on its cluster-internal port —
	// see internal/scheduler/http.go for the rationale (no external
	// exposure, no inbound auth gate).
	httpSrv := NewHTTPServer(inst, ServerConfig{
		Addr:        cfg.Addr,
		TLSCertPath: cfg.TLSCertPath,
		TLSKeyPath:  cfg.TLSKeyPath,
		TLSCAPath:   cfg.TLSCAPath,
	})
	return httpSrv.Run(runCtx)
}
