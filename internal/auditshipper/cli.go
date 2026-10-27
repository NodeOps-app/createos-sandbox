package auditshipper

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/NodeOps-app/sandbox/config"
	"github.com/NodeOps-app/sandbox/database"
)

func Cli(c *cli.Context) error {
	cfg, err := config.AuditWorkerFromContext(c)
	if err != nil {
		return err
	}
	if cfg.PostgresDSN == "" {
		return fmt.Errorf("audit-worker: postgres-dsn required")
	}
	if cfg.AuditLogURL == "" {
		return fmt.Errorf("audit-worker: audit-log-url required")
	}
	if cfg.WebhookSecret == "" {
		return fmt.Errorf("audit-worker: webhook-secret required (typically BILLING_WEBHOOK_SECRET)")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := database.OpenDb(ctx, cfg.PostgresDSN)
	if err != nil {
		return fmt.Errorf("audit-worker: open db: %w", err)
	}
	defer db.Close()

	w := &Worker{
		DB:         db,
		BackendURL: cfg.AuditLogURL,
		Secret:     []byte(cfg.WebhookSecret),
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Info("[audit-worker] shutdown signal received")
		cancel()
	}()

	log.Infof("[audit-worker] starting (url=%s)", cfg.AuditLogURL)
	w.Run(ctx)
	log.Info("[audit-worker] stopped")
	time.Sleep(50 * time.Millisecond)
	return nil
}
