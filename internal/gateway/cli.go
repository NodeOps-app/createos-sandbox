package gateway

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v2"

	"github.com/NodeOps-app/createos-sandbox/config"
)

// Cli is the urfave/cli Action for `control gateway`.
func Cli(c *cli.Context) error {
	cfg, err := config.GatewayFromContext(c)
	if err != nil {
		return err
	}
	// Outbound auth to control is mTLS via cfg.TLS*; no JWT path remains.
	gw := New(Config{
		Addr:        cfg.Addr,
		ControlURL:  cfg.ControlURL,
		TLSCertPath: cfg.TLSCertPath,
		TLSKeyPath:  cfg.TLSKeyPath,
		TLSCAPath:   cfg.TLSCAPath,
	})
	if cfg.HostKey != "" {
		if err := gw.SetHostKeyFromFile(cfg.HostKey); err != nil {
			return fmt.Errorf("host key: %w", err)
		}
	}
	return gw.Run(context.Background())
}
