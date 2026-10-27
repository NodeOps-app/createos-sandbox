//go:build control

package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"

	"github.com/NodeOps-app/sandbox/config"
	"github.com/NodeOps-app/sandbox/internal/apiserver"
	"github.com/NodeOps-app/sandbox/internal/auditshipper"
	"github.com/NodeOps-app/sandbox/internal/billing"
	"github.com/NodeOps-app/sandbox/internal/builder"
	"github.com/NodeOps-app/sandbox/internal/gateway"
	"github.com/NodeOps-app/sandbox/internal/ingress"
	"github.com/NodeOps-app/sandbox/internal/logging"
	"github.com/NodeOps-app/sandbox/internal/relay"
	"github.com/NodeOps-app/sandbox/internal/scheduler"
	"github.com/NodeOps-app/sandbox/internal/sweep"
	"github.com/NodeOps-app/sandbox/internal/ttlevict"
)

func main() {
	app := &cli.App{
		Name:  "control",
		Usage: "Run CreateOS control-plane services",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "log-format", Value: "text", Usage: "log output format: text or json", EnvVars: []string{"LOG_FORMAT"}},
		},
		Before: func(c *cli.Context) error {
			component := c.Args().First()
			if component == "api-server" {
				component = "control"
			}
			logging.Setup(c.String("log-format"), component)
			return nil
		},
		Commands: []*cli.Command{
			apiServerCommand(),
			schedulerCommand(),
			gatewayCommand(),
			relayCommand(),
			ingressCommand(),
			builderCommand(),
			billingWorkerCommand(),
			auditWorkerCommand(),
			ttlEvictCommand(),
			sweepCommand(),
		},
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func apiServerCommand() *cli.Command {
	return &cli.Command{
		Name:   "api-server",
		Usage:  "run the CreateOS control-plane API server",
		Flags:  config.ControlFlags(),
		Action: apiserver.Cli,
	}
}

func schedulerCommand() *cli.Command {
	return &cli.Command{Name: "scheduler", Usage: "run the standalone scheduler service", Flags: config.SchedulerFlags(), Action: scheduler.Cli}
}

func gatewayCommand() *cli.Command {
	return &cli.Command{Name: "gateway", Usage: "run the SSH port-forwarding gateway", Flags: config.GatewayFlags(), Action: gateway.Cli}
}

func relayCommand() *cli.Command {
	return &cli.Command{Name: "relay", Usage: "run the user-device WireGuard relay", Flags: config.RelayFlags(), Action: relay.Cli}
}

func ingressCommand() *cli.Command {
	return &cli.Command{Name: "ingress", Usage: "run the public sandbox HTTP ingress", Flags: config.IngressFlags(), Action: ingress.Cli}
}

func builderCommand() *cli.Command {
	return &cli.Command{Name: "builder", Usage: "run the template build dispatcher", Flags: config.BuilderFlags(), Action: builder.Cli}
}

func billingWorkerCommand() *cli.Command {
	return &cli.Command{Name: "billing-worker", Usage: "deliver the billing event outbox", Flags: config.BillingWorkerFlags(), Action: billing.Cli}
}

func auditWorkerCommand() *cli.Command {
	return &cli.Command{Name: "audit-worker", Usage: "deliver the audit event outbox", Flags: config.AuditWorkerFlags(), Action: auditshipper.Cli}
}

func ttlEvictCommand() *cli.Command {
	return &cli.Command{Name: "ttl-evict", Usage: "evict sandboxes older than the configured maximum age", Flags: config.TTLEvictFlags(), Action: ttlevict.Cli}
}

func sweepCommand() *cli.Command {
	return &cli.Command{Name: "sweep", Usage: "repair stale lifecycle state and evict dead-host sandboxes", Flags: config.SweepFlags(), Action: sweep.Cli}
}
