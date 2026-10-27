//go:build machine

package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"

	"github.com/NodeOps-app/sandbox/config"
	"github.com/NodeOps-app/sandbox/internal/hostproxy"
	"github.com/NodeOps-app/sandbox/internal/hosts"
	"github.com/NodeOps-app/sandbox/internal/logging"
)

func main() {
	app := &cli.App{
		Name:  "machine",
		Usage: "Run and maintain a CreateOS machine",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "log-format", Value: "text", Usage: "log output format: text or json", EnvVars: []string{"LOG_FORMAT"}},
		},
		Before: func(c *cli.Context) error {
			component := c.Args().First()
			if component == "host" {
				component = "host"
			}
			logging.Setup(c.String("log-format"), component)
			return nil
		},
		Commands: []*cli.Command{
			hostCommand(),
			proxyCommand(),
		},
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func hostCommand() *cli.Command {
	return &cli.Command{Name: "host", Usage: "run the sandbox machine service", Flags: config.ServeFlags(), Action: hosts.Serve}
}

func proxyCommand() *cli.Command {
	return &cli.Command{Name: "proxy", Usage: "run the transparent egress proxy", Flags: config.ProxyFlags(), Action: hostproxy.Cli}
}
