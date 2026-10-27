package bake

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

// Cli is the urfave/cli Action for the `image rootfs` subcommand.
func Cli(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("usage: image rootfs <container-image>")
	}
	return Run(c.Args().First(), c.String("out"), c.Int64("size"), c.String("agent"))
}

// CliInitrd is the urfave/cli Action for `image initrd` — rebuilds
// images/initrd.gz from the current agent binary. It shares the image-building
// package with rootfs construction because both produce guest artifacts.
func CliInitrd(c *cli.Context) error {
	if err := BuildInitrd(c.String("agent")); err != nil {
		return err
	}
	fmt.Println("initrd rebuilt: images/initrd.gz")
	return nil
}
