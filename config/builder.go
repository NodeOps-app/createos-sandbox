package config

import (
	"fmt"
	"time"

	"github.com/urfave/cli/v2"
)

// BuilderConfig holds the resolved configuration for the `builder` subcommand.
type BuilderConfig struct {
	PostgresDSN string

	// SigningKeyPath is the path to the builder's Ed25519 seed file.
	// Auto-generated on first start. The builder mints per-build JWTs
	// (sub=tpl_<id>, aud=control, ~15 min) so build sandboxes can PATCH
	// only their own templates row.
	SigningKeyPath string

	// BuilderID is the iss claim on minted JWTs (e.g. "builder:eu-1").
	BuilderID string

	// ControlURL is where build sandboxes PATCH /v1/internal/templates/:id.
	ControlURL string

	// R2 bucket configuration. Builder uses these to mint pre-signed
	// PUT URLs the build sandbox uploads to. Hosts use their own R2 creds
	// elsewhere; the runner never sees raw access keys.
	R2Bucket    string
	R2Endpoint  string
	R2AccessKey string
	R2SecretKey string
	R2Region    string
	R2Secure    bool

	// AllowedBases overrides the canonical base allowlist. Empty = use
	// builder.AllowedBases default.
	AllowedBases []string

	// SandboxAPIURL and SandboxAPIKeyFile let the builder create disposable
	// build sandboxes without embedding the API key in YAML or guest state.
	SandboxAPIURL     string
	SandboxAPIKeyFile string
	SandboxRootfs     string
	SandboxShape      string
	SandboxDiskMiB    int64
	SandboxRegion     string

	// BuildTimeout caps the sandbox build. Builder reaps rows after it plus 5m.
	BuildTimeout time.Duration

	// GlobalConcurrency caps total in-flight builds across all users.
	GlobalConcurrency int

	// PerUserConcurrency caps in-flight builds per user.
	PerUserConcurrency int

	// PollInterval is how often the builder polls Postgres for new jobs.
	PollInterval time.Duration

	// JanitorInterval is how often the stuck-build reaper runs.
	JanitorInterval time.Duration

	// SizeCapMiB rejects builds whose final ext4 exceeds this.
	SizeCapMiB int64
}

// BuilderFile is the YAML schema for the `builder` subcommand.
type BuilderFile struct {
	PostgresDSN        *string  `yaml:"postgres_dsn"`
	SigningKey         *string  `yaml:"signing_key"`
	BuilderID          *string  `yaml:"builder_id"`
	ControlURL         *string  `yaml:"control_url"`
	R2Bucket           *string  `yaml:"r2_bucket"`
	R2Endpoint         *string  `yaml:"r2_endpoint"`
	R2AccessKey        *string  `yaml:"r2_access_key"`
	R2SecretKey        *string  `yaml:"r2_secret_key"`
	R2Region           *string  `yaml:"r2_region"`
	R2Secure           *bool    `yaml:"r2_secure"`
	AllowedBases       []string `yaml:"allowed_bases"`
	SandboxAPIURL      *string  `yaml:"sandbox_api_url"`
	SandboxAPIKeyFile  *string  `yaml:"sandbox_api_key_file"`
	SandboxRootfs      *string  `yaml:"sandbox_rootfs"`
	SandboxShape       *string  `yaml:"sandbox_shape"`
	SandboxDiskMiB     *int64   `yaml:"sandbox_disk_mib"`
	SandboxRegion      *string  `yaml:"sandbox_region"`
	BuildTimeout       *string  `yaml:"build_timeout"`
	GlobalConcurrency  *int     `yaml:"global_concurrency"`
	PerUserConcurrency *int     `yaml:"per_user_concurrency"`
	PollInterval       *string  `yaml:"poll_interval"`
	JanitorInterval    *string  `yaml:"janitor_interval"`
	SizeCapMiB         *int64   `yaml:"size_cap_mib"`
}

// BuilderFlags returns the urfave/cli flags for the `builder` subcommand.
func BuilderFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "config", Usage: "path to YAML config"},
		&cli.StringFlag{Name: "postgres-dsn", Value: "postgres://createos:createos@localhost:5432/createos?sslmode=disable", EnvVars: []string{"POSTGRES_DSN"}},
		&cli.StringFlag{Name: "signing-key", Value: "", Usage: "path to builder Ed25519 seed (default: ./builder_signing.key)", EnvVars: []string{"SIGNING_KEY"}},
		&cli.StringFlag{Name: "builder-id", Value: "builder-1", Usage: "iss claim on minted JWTs", EnvVars: []string{"BUILDER_ID"}},
		&cli.StringFlag{Name: "control-url", Value: "", Usage: "control plane base URL the build sandbox PATCHes (e.g. https://control.example.com)", EnvVars: []string{"CONTROL_URL"}},
		&cli.StringFlag{Name: "r2-bucket", Value: "", EnvVars: []string{"R2_BUCKET"}},
		&cli.StringFlag{Name: "r2-endpoint", Value: "", EnvVars: []string{"R2_ENDPOINT"}},
		&cli.StringFlag{Name: "r2-access-key", Value: "", EnvVars: []string{"R2_ACCESS_KEY_ID"}},
		&cli.StringFlag{Name: "r2-secret-key", Value: "", EnvVars: []string{"R2_SECRET_ACCESS_KEY"}},
		&cli.StringFlag{Name: "r2-region", Value: "auto", EnvVars: []string{"R2_REGION"}},
		&cli.BoolFlag{Name: "r2-secure", Value: true, EnvVars: []string{"R2_SECURE"}},
		&cli.StringSliceFlag{Name: "allowed-base", Usage: "repeatable; overrides default base allowlist", EnvVars: []string{"ALLOWED_BASES"}},
		&cli.StringFlag{Name: "sandbox-api-url", Value: "", Usage: "CreateOS API base URL used to launch build sandboxes"},
		&cli.StringFlag{Name: "sandbox-api-key-file", Value: "", Usage: "path to the dedicated build API key"},
		&cli.StringFlag{Name: "sandbox-rootfs", Value: "devbox:1", Usage: "rootfs used for build sandboxes"},
		&cli.StringFlag{Name: "sandbox-shape", Value: "s-2vcpu-4gb", Usage: "shape used for build sandboxes"},
		&cli.Int64Flag{Name: "sandbox-disk-mib", Value: 20480, Usage: "ephemeral build sandbox disk size"},
		&cli.StringFlag{Name: "sandbox-region", Value: "", Usage: "optional region pin for build sandboxes"},
		&cli.DurationFlag{Name: "build-timeout", Value: 10 * time.Minute, EnvVars: []string{"BUILD_TIMEOUT"}},
		&cli.IntFlag{Name: "global-concurrency", Value: 6, EnvVars: []string{"GLOBAL_CONCURRENCY"}},
		&cli.IntFlag{Name: "per-user-concurrency", Value: 2, EnvVars: []string{"PER_USER_CONCURRENCY"}},
		&cli.DurationFlag{Name: "poll-interval", Value: 2 * time.Second, EnvVars: []string{"POLL_INTERVAL"}},
		&cli.DurationFlag{Name: "janitor-interval", Value: 60 * time.Second, EnvVars: []string{"JANITOR_INTERVAL"}},
		&cli.Int64Flag{Name: "size-cap-mib", Value: 5120, EnvVars: []string{"SIZE_CAP_MIB"}},
	}
}

// BuilderFromContext resolves the BuilderConfig with flag/env > YAML > default.
func BuilderFromContext(c *cli.Context) (BuilderConfig, error) {
	var f BuilderFile
	if err := loadYAML(c.String("config"), &f); err != nil {
		return BuilderConfig{}, err
	}
	cfg := BuilderConfig{
		PostgresDSN:        pickStr(c, "postgres-dsn", f.PostgresDSN),
		SigningKeyPath:     pickStr(c, "signing-key", f.SigningKey),
		BuilderID:          pickStr(c, "builder-id", f.BuilderID),
		ControlURL:         pickStr(c, "control-url", f.ControlURL),
		R2Bucket:           pickStr(c, "r2-bucket", f.R2Bucket),
		R2Endpoint:         pickStr(c, "r2-endpoint", f.R2Endpoint),
		R2AccessKey:        pickStr(c, "r2-access-key", f.R2AccessKey),
		R2SecretKey:        pickStr(c, "r2-secret-key", f.R2SecretKey),
		R2Region:           pickStr(c, "r2-region", f.R2Region),
		SandboxAPIURL:      pickStr(c, "sandbox-api-url", f.SandboxAPIURL),
		SandboxAPIKeyFile:  pickStr(c, "sandbox-api-key-file", f.SandboxAPIKeyFile),
		SandboxRootfs:      pickStr(c, "sandbox-rootfs", f.SandboxRootfs),
		SandboxShape:       pickStr(c, "sandbox-shape", f.SandboxShape),
		SandboxRegion:      pickStr(c, "sandbox-region", f.SandboxRegion),
		SandboxDiskMiB:     c.Int64("sandbox-disk-mib"),
		BuildTimeout:       c.Duration("build-timeout"),
		GlobalConcurrency:  c.Int("global-concurrency"),
		PerUserConcurrency: c.Int("per-user-concurrency"),
		PollInterval:       c.Duration("poll-interval"),
		JanitorInterval:    c.Duration("janitor-interval"),
		SizeCapMiB:         c.Int64("size-cap-mib"),
	}
	if c.IsSet("r2-secure") {
		cfg.R2Secure = c.Bool("r2-secure")
	} else if f.R2Secure != nil {
		cfg.R2Secure = *f.R2Secure
	} else {
		cfg.R2Secure = true
	}
	if cfg.SigningKeyPath == "" {
		cfg.SigningKeyPath = "./builder_signing.key"
	}
	if bases := c.StringSlice("allowed-base"); len(bases) > 0 {
		cfg.AllowedBases = bases
	} else if len(f.AllowedBases) > 0 {
		cfg.AllowedBases = f.AllowedBases
	}
	if f.BuildTimeout != nil && !c.IsSet("build-timeout") {
		d, err := time.ParseDuration(*f.BuildTimeout)
		if err != nil {
			return BuilderConfig{}, fmt.Errorf("build_timeout: %w", err)
		}
		cfg.BuildTimeout = d
	}
	if f.PollInterval != nil && !c.IsSet("poll-interval") {
		d, err := time.ParseDuration(*f.PollInterval)
		if err != nil {
			return BuilderConfig{}, fmt.Errorf("poll_interval: %w", err)
		}
		cfg.PollInterval = d
	}
	if f.JanitorInterval != nil && !c.IsSet("janitor-interval") {
		d, err := time.ParseDuration(*f.JanitorInterval)
		if err != nil {
			return BuilderConfig{}, fmt.Errorf("janitor_interval: %w", err)
		}
		cfg.JanitorInterval = d
	}
	if f.GlobalConcurrency != nil && !c.IsSet("global-concurrency") {
		cfg.GlobalConcurrency = *f.GlobalConcurrency
	}
	if f.PerUserConcurrency != nil && !c.IsSet("per-user-concurrency") {
		cfg.PerUserConcurrency = *f.PerUserConcurrency
	}
	if f.SizeCapMiB != nil && !c.IsSet("size-cap-mib") {
		cfg.SizeCapMiB = *f.SizeCapMiB
	}
	if f.SandboxDiskMiB != nil && !c.IsSet("sandbox-disk-mib") {
		cfg.SandboxDiskMiB = *f.SandboxDiskMiB
	}
	return cfg, nil
}

// Validate fails fast on missing-required fields.
func (cfg BuilderConfig) Validate() error {
	if cfg.PostgresDSN == "" {
		return fmt.Errorf("postgres-dsn required")
	}
	if cfg.ControlURL == "" {
		return fmt.Errorf("control-url required")
	}
	if cfg.R2Bucket == "" || cfg.R2Endpoint == "" || cfg.R2AccessKey == "" || cfg.R2SecretKey == "" {
		return fmt.Errorf("r2-bucket, r2-endpoint, r2-access-key, r2-secret-key all required")
	}
	if cfg.SandboxAPIURL == "" || cfg.SandboxAPIKeyFile == "" {
		return fmt.Errorf("sandbox-api-url and sandbox-api-key-file required")
	}
	if cfg.SandboxRootfs == "" || cfg.SandboxShape == "" {
		return fmt.Errorf("sandbox-rootfs and sandbox-shape required")
	}
	if cfg.SandboxDiskMiB <= cfg.SizeCapMiB+200 {
		return fmt.Errorf("sandbox-disk-mib must exceed size-cap-mib by more than 200 MiB")
	}
	return nil
}
