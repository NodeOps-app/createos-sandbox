package config

import (
	"github.com/urfave/cli/v2"
)

// GatewayConfig holds the resolved configuration for the `gateway` subcommand.
type GatewayConfig struct {
	Addr       string
	ControlURL string
	HostKey    string

	// TLS server config — listener wraps in TLS 1.3 + RequireAndVerifyClientCert
	// when all three paths are set; empty paths leave it plain (dev only).
	TLSCertPath string
	TLSKeyPath  string
	TLSCAPath   string
}

// GatewayFile is the YAML schema for the `gateway` subcommand.
type GatewayFile struct {
	Addr        *string `yaml:"addr"`
	ControlURL  *string `yaml:"control_url"`
	HostKey     *string `yaml:"host_key"`
	TLSCertPath *string `yaml:"tls_cert"`
	TLSKeyPath  *string `yaml:"tls_key"`
	TLSCAPath   *string `yaml:"tls_ca"`
}

// GatewayFlags returns the urfave/cli flags for the `gateway` subcommand.
func GatewayFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "config", Usage: "path to YAML config file"},
		&cli.StringFlag{Name: "addr", Value: ":2222", EnvVars: []string{"GATEWAY_ADDR"}},
		&cli.StringFlag{Name: "control-url", Value: "http://localhost:8080", EnvVars: []string{"GATEWAY_CONTROL_URL"}},
		&cli.StringFlag{Name: "host-key", Value: "", Usage: "path to ed25519 host key (empty = ephemeral)", EnvVars: []string{"GATEWAY_HOST_KEY"}},
		&cli.StringFlag{Name: "tls-cert", Value: "", Usage: "path to gateway's outbound mTLS client cert (PEM)", EnvVars: []string{"GATEWAY_TLS_CERT"}},
		&cli.StringFlag{Name: "tls-key", Value: "", Usage: "path to gateway's outbound mTLS private key (PEM)", EnvVars: []string{"GATEWAY_TLS_KEY"}},
		&cli.StringFlag{Name: "tls-ca", Value: "", Usage: "path to CA bundle used to verify control plane TLS cert (PEM)", EnvVars: []string{"GATEWAY_TLS_CA"}},
	}
}

// GatewayFromContext resolves the final GatewayConfig.
// Precedence: flag/env > YAML > default.
func GatewayFromContext(c *cli.Context) (GatewayConfig, error) {
	var f GatewayFile
	if err := loadYAML(c.String("config"), &f); err != nil {
		return GatewayConfig{}, err
	}
	cfg := GatewayConfig{
		Addr:       pickStr(c, "addr", f.Addr),
		ControlURL: pickStr(c, "control-url", f.ControlURL),
		HostKey:    pickStr(c, "host-key", f.HostKey),
	}
	cfg.TLSCertPath = pickStr(c, "tls-cert", f.TLSCertPath)
	cfg.TLSKeyPath = pickStr(c, "tls-key", f.TLSKeyPath)
	cfg.TLSCAPath = pickStr(c, "tls-ca", f.TLSCAPath)
	return cfg, nil
}
