//go:build image

package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"

	"github.com/NodeOps-app/sandbox/internal/bake"
	"github.com/NodeOps-app/sandbox/internal/logging"
)

func main() {
	app := &cli.App{
		Name:  "image",
		Usage: "Build CreateOS guest image artifacts",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "log-format", Value: "text", Usage: "log output format: text or json", EnvVars: []string{"LOG_FORMAT"}},
		},
		Before: func(c *cli.Context) error {
			logging.Setup(c.String("log-format"), "image")
			return nil
		},
		Commands: []*cli.Command{
			rootfsCommand(),
			initrdCommand(),
		},
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootfsCommand() *cli.Command {
	return &cli.Command{
		Name:      "rootfs",
		Usage:     "convert a Docker or OCI image to a Firecracker rootfs",
		ArgsUsage: "<container-image>",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "out", Aliases: []string{"o"}, Usage: "output rootfs path"},
			&cli.Int64Flag{Name: "size", Value: 0, Usage: "rootfs size in MB (0 = auto)"},
			&cli.StringFlag{Name: "agent", Value: "./bin/agent", Usage: "path to the agent binary to embed in the initrd", EnvVars: []string{"AGENT_BIN"}},
		},
		Action: bake.Cli,
	}
}

func initrdCommand() *cli.Command {
	return &cli.Command{
		Name:  "initrd",
		Usage: "build images/initrd.gz from the current agent binary",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "agent", Value: "./bin/agent", Usage: "path to the agent binary", EnvVars: []string{"AGENT_BIN"}},
		},
		Action: bake.CliInitrd,
	}
}
