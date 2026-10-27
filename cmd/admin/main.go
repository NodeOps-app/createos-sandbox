//go:build admin

package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"

	cacli "github.com/NodeOps-app/sandbox/internal/ca/cli"
	"github.com/NodeOps-app/sandbox/internal/logging"
)

func main() {
	app := &cli.App{
		Name:  "admin",
		Usage: "Run privileged CreateOS operator commands",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "log-format", Value: "text", Usage: "log output format: text or json", EnvVars: []string{"LOG_FORMAT"}},
		},
		Before: func(c *cli.Context) error {
			logging.Setup(c.String("log-format"), "admin")
			return nil
		},
		Commands: []*cli.Command{
			cacli.Commands(),
		},
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
