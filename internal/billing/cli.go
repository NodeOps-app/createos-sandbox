package billing

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/NodeOps-app/createos-sandbox/config"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// Cli runs the `control billing-worker` subcommand. Single goroutine
// draining billing_events; multi-replica safe via FOR UPDATE SKIP
// LOCKED at the SQL layer.
func Cli(c *cli.Context) error {
	cfg, err := config.BillingWorkerFromContext(c)
	if err != nil {
		return err
	}
	if cfg.PostgresDSN == "" {
		return fmt.Errorf("billing-worker: postgres-dsn required")
	}
	if cfg.BillingWebhookURL == "" {
		return fmt.Errorf("billing-worker: billing-webhook-url required")
	}
	if cfg.BillingWebhookSecret == "" {
		return fmt.Errorf("billing-worker: billing-webhook-secret required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	repo, err := models.OpenRepo(ctx, cfg.PostgresDSN)
	if err != nil {
		return fmt.Errorf("billing-worker: open repo: %w", err)
	}
	defer repo.Close()

	w := &Worker{
		Repo:    repo,
		Webhook: New(cfg.BillingWebhookURL, cfg.BillingWebhookSecret),
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Info("[billing-worker] shutdown signal received")
		cancel()
	}()

	log.Infof("[billing-worker] starting (url=%s)", cfg.BillingWebhookURL)
	w.Run(ctx)
	log.Info("[billing-worker] stopped")
	time.Sleep(50 * time.Millisecond)
	return nil
}
