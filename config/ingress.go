package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
)

// IngressConfig is the resolved configuration for the `ingress` subcommand.
type IngressConfig struct {
	Addr          string
	DomainSuffix  string
	MaxConcurrent int
	PositiveTTL   time.Duration
	NegativeTTL   time.Duration
	TLSCertPath   string
	TLSKeyPath    string
	TLSCAPath     string
	// ControlURLs maps region name → that region's control internal mTLS
	// base URL (e.g. us: https://control-us:8443). Wake-on-request POSTs
	// .../v1/internal/sandboxes/:id/wake to the URL for the sandbox's OWN
	// region (route.Region), so the owning region's control resumes it —
	// no control→control hop. Mirrors control's peer_controls, but points
	// at the internal :8443 listener (the ingress dials with role=ingress).
	// Empty disables the feature (paused sandboxes just 503 as before).
	ControlURLs map[string]string
}

// IngressFile is the YAML schema for the ingress subcommand.
type IngressFile struct {
	Addr          *string           `yaml:"addr"`
	DomainSuffix  *string           `yaml:"domain_suffix"`
	MaxConcurrent *int              `yaml:"max_concurrent"`
	PositiveTTL   *string           `yaml:"positive_ttl"`
	NegativeTTL   *string           `yaml:"negative_ttl"`
	TLSCert       *string           `yaml:"tls_cert"`
	TLSKey        *string           `yaml:"tls_key"`
	TLSCA         *string           `yaml:"tls_ca"`
	ControlURLs   map[string]string `yaml:"control_urls"`
}

// IngressFlags returns the urfave/cli flags for the `ingress` subcommand.
func IngressFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "config", Usage: "path to YAML config file"},
		&cli.StringFlag{Name: "addr", Value: ":8090", EnvVars: []string{"INGRESS_ADDR"}},
		&cli.StringFlag{Name: "domain-suffix", Value: "eu.example.com", Usage: "wildcard domain suffix (e.g. eu.example.com)", EnvVars: []string{"INGRESS_DOMAIN_SUFFIX"}},
		&cli.IntFlag{Name: "max-concurrent", Value: 64, Usage: "per-sandbox concurrent tunnel cap", EnvVars: []string{"INGRESS_MAX_CONCURRENT"}},
		&cli.DurationFlag{Name: "positive-ttl", Value: 30 * time.Second, Usage: "positive cache TTL", EnvVars: []string{"INGRESS_POSITIVE_TTL"}},
		&cli.DurationFlag{Name: "negative-ttl", Value: 5 * time.Second, Usage: "negative cache TTL", EnvVars: []string{"INGRESS_NEGATIVE_TTL"}},
		&cli.StringFlag{Name: "tls-cert", Value: "", Usage: "path to TLS server cert (PEM)", EnvVars: []string{"TLS_CERT"}},
		&cli.StringFlag{Name: "tls-key", Value: "", Usage: "path to TLS server private key (PEM)", EnvVars: []string{"TLS_KEY"}},
		&cli.StringFlag{Name: "tls-ca", Value: "", Usage: "path to TLS CA bundle for client cert verification (PEM)", EnvVars: []string{"TLS_CA"}},
		// control_urls (region → control internal mTLS URL) for
		// wake-on-request is YAML-only — a map doesn't fit a CLI flag,
		// matching control's peer_controls.
	}
}

// IngressFromContext resolves the final IngressConfig.
func IngressFromContext(c *cli.Context) (IngressConfig, error) {
	var f IngressFile
	if err := loadYAML(c.String("config"), &f); err != nil {
		return IngressConfig{}, err
	}
	cfg := IngressConfig{
		Addr: pickStr(c, "addr", f.Addr),
	}
	cfg.DomainSuffix = c.String("domain-suffix")
	if f.DomainSuffix != nil && !c.IsSet("domain-suffix") {
		cfg.DomainSuffix = *f.DomainSuffix
	}
	cfg.MaxConcurrent = c.Int("max-concurrent")
	if f.MaxConcurrent != nil && !c.IsSet("max-concurrent") {
		cfg.MaxConcurrent = *f.MaxConcurrent
	}
	cfg.PositiveTTL = c.Duration("positive-ttl")
	if f.PositiveTTL != nil && !c.IsSet("positive-ttl") {
		d, err := time.ParseDuration(*f.PositiveTTL)
		if err != nil {
			return IngressConfig{}, err
		}
		cfg.PositiveTTL = d
	}
	cfg.NegativeTTL = c.Duration("negative-ttl")
	if f.NegativeTTL != nil && !c.IsSet("negative-ttl") {
		d, err := time.ParseDuration(*f.NegativeTTL)
		if err != nil {
			return IngressConfig{}, err
		}
		cfg.NegativeTTL = d
	}
	if strings.TrimSpace(cfg.DomainSuffix) == "" {
		return IngressConfig{}, fmt.Errorf("domain-suffix must be set")
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 64
	}
	cfg.TLSCertPath = c.String("tls-cert")
	if f.TLSCert != nil && !c.IsSet("tls-cert") {
		cfg.TLSCertPath = *f.TLSCert
	}
	cfg.TLSKeyPath = c.String("tls-key")
	if f.TLSKey != nil && !c.IsSet("tls-key") {
		cfg.TLSKeyPath = *f.TLSKey
	}
	cfg.TLSCAPath = c.String("tls-ca")
	if f.TLSCA != nil && !c.IsSet("tls-ca") {
		cfg.TLSCAPath = *f.TLSCA
	}
	if f.ControlURLs != nil {
		cfg.ControlURLs = f.ControlURLs
	}
	return cfg, nil
}
