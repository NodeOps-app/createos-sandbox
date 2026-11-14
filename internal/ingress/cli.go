package ingress

import (
	"context"

	"github.com/urfave/cli/v2"

	"github.com/NodeOps-app/createos-sandbox/config"
)

// Cli is the urfave/cli Action for `control ingress`.
func Cli(c *cli.Context) error {
	cfg, err := config.IngressFromContext(c)
	if err != nil {
		return err
	}
	// Outbound auth to host is mTLS via cfg.TLS*; no JWT path remains.
	srv, err := New(Config{
		Addr:          cfg.Addr,
		DomainSuffix:  cfg.DomainSuffix,
		MaxConcurrent: cfg.MaxConcurrent,
		PositiveTTL:   cfg.PositiveTTL,
		NegativeTTL:   cfg.NegativeTTL,
		TLSCertPath:   cfg.TLSCertPath,
		TLSKeyPath:    cfg.TLSKeyPath,
		TLSCAPath:     cfg.TLSCAPath,
		ControlURLs:   cfg.ControlURLs,
	})
	if err != nil {
		return err
	}
	return srv.Run(context.Background())
}
