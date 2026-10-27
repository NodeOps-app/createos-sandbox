package config

import (
	"time"

	"github.com/urfave/cli/v2"
)

// HostProxyConfig holds the resolved configuration for the `host-proxy` subcommand.
type HostProxyConfig struct {
	HTTP     string // bind address for HTTP intercept, e.g. ":8081"
	HTTPS    string // bind address for HTTPS intercept (SNI sniff), e.g. ":8443"
	API      string // control-plane URL for the by-ip sandbox lookup
	CacheTTL time.Duration

	// TLS bundle for the outbound mTLS client to control's by-ip route.
	// The proxy presents the host's SPIFFE URI client cert (role=host).
	// Inbound sandbox traffic is inspected and forwarded without TLS
	// termination. Without this bundle, control rejects by-ip lookups.
	TLSCertPath string
	TLSKeyPath  string
	TLSCAPath   string
}

// ProxyFile is the YAML schema for the `host-proxy` subcommand.
type ProxyFile struct {
	HTTP     *string `yaml:"http"`
	HTTPS    *string `yaml:"https"`
	API      *string `yaml:"api"`
	CacheTTL *string `yaml:"cache_ttl"` // Go duration string, e.g. "30s"
	TLSCert  *string `yaml:"tls_cert"`
	TLSKey   *string `yaml:"tls_key"`
	TLSCA    *string `yaml:"tls_ca"`
}

// ProxyFlags returns the urfave/cli flags for the `host-proxy` subcommand.
func ProxyFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "config", Usage: "path to YAML config file"},
		&cli.StringFlag{Name: "http", Value: ":8081", EnvVars: []string{"PROXY_HTTP"}},
		&cli.StringFlag{Name: "https", Value: ":8443", EnvVars: []string{"PROXY_HTTPS"}},
		&cli.StringFlag{Name: "api", Value: "http://localhost:8080", EnvVars: []string{"PROXY_API"}},
		&cli.DurationFlag{Name: "cache-ttl", Value: 30 * time.Second, EnvVars: []string{"PROXY_CACHE_TTL"}},
		&cli.StringFlag{Name: "tls-cert", Usage: "path to TLS cert (PEM) for outbound mTLS to control", EnvVars: []string{"TLS_CERT"}},
		&cli.StringFlag{Name: "tls-key", Usage: "path to TLS private key (PEM)", EnvVars: []string{"TLS_KEY"}},
		&cli.StringFlag{Name: "tls-ca", Usage: "path to CA bundle (PEM)", EnvVars: []string{"TLS_CA"}},
	}
}

// HostProxyFromContext resolves the final HostProxyConfig.
// Precedence: flag/env > YAML > default.
func HostProxyFromContext(c *cli.Context) (HostProxyConfig, error) {
	var f ProxyFile
	if err := loadYAML(c.String("config"), &f); err != nil {
		return HostProxyConfig{}, err
	}
	cfg := HostProxyConfig{
		HTTP:        pickStr(c, "http", f.HTTP),
		HTTPS:       pickStr(c, "https", f.HTTPS),
		API:         pickStr(c, "api", f.API),
		CacheTTL:    c.Duration("cache-ttl"),
		TLSCertPath: pickStr(c, "tls-cert", f.TLSCert),
		TLSKeyPath:  pickStr(c, "tls-key", f.TLSKey),
		TLSCAPath:   pickStr(c, "tls-ca", f.TLSCA),
	}
	if f.CacheTTL != nil && !c.IsSet("cache-ttl") {
		d, err := time.ParseDuration(*f.CacheTTL)
		if err != nil {
			return HostProxyConfig{}, err
		}
		cfg.CacheTTL = d
	}
	return cfg, nil
}
