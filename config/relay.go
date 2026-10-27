package config

import (
	"github.com/urfave/cli/v2"
)

// RelayConfig holds the resolved configuration for `control relay`.
type RelayConfig struct {
	HostID             string // self-identifier; registered in hosts table with role='relay'
	Region             string
	ControlURL         string // public URL for first-issue CSR (bootstrap-token auth)
	InternalControlURL string // internal mTLS URL for db / hosts calls — defaults to ControlURL
	BootstrapToken     string // for first-time CSR — prefer BootstrapTokenFile in prod
	BootstrapTokenFile string // path to file holding the token (mode 0600); takes precedence over BootstrapToken
	PublicEndpoint     string // e.g. "relay-1.example.com:51820" — baked into client wg-quick configs
	WGDevicesPort      int    // public UDP listen port for wg-devices iface (default 51820)
	WGDevicesPrivKey   string // path to base64 wireguard privkey for wg-devices iface
	WGHostsPrivKey     string // path to ed25519-style wg privkey for the host-mesh leg (wg-hosts)
	TLSCertPath        string
	TLSKeyPath         string
	TLSCAPath          string
}

// RelayFile is the YAML schema for `control relay`.
type RelayFile struct {
	HostID             *string `yaml:"host_id"`
	Region             *string `yaml:"region"`
	ControlURL         *string `yaml:"control_url"`
	InternalControlURL *string `yaml:"internal_control_url"`
	BootstrapToken     *string `yaml:"bootstrap_token"`
	BootstrapTokenFile *string `yaml:"bootstrap_token_file"`
	PublicEndpoint     *string `yaml:"public_endpoint"`
	WGDevicesPort      *int    `yaml:"wg_devices_port"`
	WGDevicesPrivKey   *string `yaml:"wg_devices_priv_key"`
	WGHostsPrivKey     *string `yaml:"wg_hosts_priv_key"`
	TLSCertPath        *string `yaml:"tls_cert"`
	TLSKeyPath         *string `yaml:"tls_key"`
	TLSCAPath          *string `yaml:"tls_ca"`
}

func RelayFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "config", Usage: "path to YAML config file"},
		&cli.StringFlag{Name: "host-id", Value: "", Usage: "self-identifier (registers as role=relay)", EnvVars: []string{"RELAY_HOST_ID"}},
		&cli.StringFlag{Name: "region", Value: "", EnvVars: []string{"RELAY_REGION"}},
		&cli.StringFlag{Name: "control-url", Value: "http://localhost:8080", EnvVars: []string{"RELAY_CONTROL_URL"}},
		&cli.StringFlag{Name: "internal-control-url", Value: "", Usage: "internal mTLS URL for DB calls (defaults to control-url)", EnvVars: []string{"RELAY_INTERNAL_CONTROL_URL"}},
		&cli.StringFlag{Name: "bootstrap-token", Value: "", Usage: "bootstrap token (prefer --bootstrap-token-file; this flag leaks via /proc/<pid>/cmdline)", EnvVars: []string{"RELAY_BOOTSTRAP_TOKEN"}},
		&cli.StringFlag{Name: "bootstrap-token-file", Value: "", Usage: "path to file (mode 0600) holding the bootstrap token; takes precedence over --bootstrap-token", EnvVars: []string{"RELAY_BOOTSTRAP_TOKEN_FILE"}},
		&cli.StringFlag{Name: "public-endpoint", Value: "", Usage: "public addr:port for client configs (e.g. relay-1.example.com:51820)", EnvVars: []string{"RELAY_PUBLIC_ENDPOINT"}},
		// wg-hosts (internal mesh) uses 51820 — the cluster-wide
		// convention every compute host listens on. wg-devices (public
		// client-facing) must bind a DIFFERENT UDP port since both run
		// on the same node when hostNetwork=true.
		&cli.IntFlag{Name: "wg-devices-port", Value: 51821, EnvVars: []string{"RELAY_WG_DEVICES_PORT"}},
		&cli.StringFlag{Name: "wg-devices-priv-key", Value: "/etc/createos/wg_devices.key", EnvVars: []string{"RELAY_WG_DEVICES_PRIV_KEY"}},
		&cli.StringFlag{Name: "wg-hosts-priv-key", Value: "/etc/createos/wg_signing.key", EnvVars: []string{"RELAY_WG_HOSTS_PRIV_KEY"}},
		&cli.StringFlag{Name: "tls-cert", Value: "", EnvVars: []string{"RELAY_TLS_CERT"}},
		&cli.StringFlag{Name: "tls-key", Value: "", EnvVars: []string{"RELAY_TLS_KEY"}},
		&cli.StringFlag{Name: "tls-ca", Value: "", EnvVars: []string{"RELAY_TLS_CA"}},
	}
}

func RelayFromContext(c *cli.Context) (RelayConfig, error) {
	var f RelayFile
	if err := loadYAML(c.String("config"), &f); err != nil {
		return RelayConfig{}, err
	}
	return RelayConfig{
		HostID:             pickStr(c, "host-id", f.HostID),
		Region:             pickStr(c, "region", f.Region),
		ControlURL:         pickStr(c, "control-url", f.ControlURL),
		InternalControlURL: pickStr(c, "internal-control-url", f.InternalControlURL),
		BootstrapToken:     pickStr(c, "bootstrap-token", f.BootstrapToken),
		BootstrapTokenFile: pickStr(c, "bootstrap-token-file", f.BootstrapTokenFile),
		PublicEndpoint:     pickStr(c, "public-endpoint", f.PublicEndpoint),
		WGDevicesPort:      pickInt(c, "wg-devices-port", f.WGDevicesPort),
		WGDevicesPrivKey:   pickStr(c, "wg-devices-priv-key", f.WGDevicesPrivKey),
		WGHostsPrivKey:     pickStr(c, "wg-hosts-priv-key", f.WGHostsPrivKey),
		TLSCertPath:        pickStr(c, "tls-cert", f.TLSCertPath),
		TLSKeyPath:         pickStr(c, "tls-key", f.TLSKeyPath),
		TLSCAPath:          pickStr(c, "tls-ca", f.TLSCAPath),
	}, nil
}
