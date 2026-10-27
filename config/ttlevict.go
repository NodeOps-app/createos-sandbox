package config

import (
	"time"

	"github.com/urfave/cli/v2"
)

// TTLEvictConfig is the resolved config for `control ttl-evict`. This
// job is deliberately tiny: connect to Postgres, mark sandboxes older
// than --max-age as destroyed, exit. No control-plane surface at all.
type TTLEvictConfig struct {
	PostgresDSN           string
	Region                string // scope this sweep to sandboxes/hosts in this region
	MaxAge                time.Duration
	DiskCredentialKeyPath string
	DryRun                bool
}

// TTLEvictFile is the YAML schema for `ttlevict.yaml`. It deliberately carries
// only this job's operational settings rather than sharing the full control
// schema.
type TTLEvictFile struct {
	PostgresDSN       *string        `yaml:"postgres_dsn"`
	Region            *string        `yaml:"region"`
	MaxAge            *time.Duration `yaml:"max_age"`
	DiskCredentialKey *string        `yaml:"disk_credential_key"`
	DryRun            *bool          `yaml:"dry_run"`
}

// TTLEvictFlags returns the urfave/cli flags for `control ttl-evict`.
func TTLEvictFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "config", Usage: "path to YAML config file (ttlevict.yaml)"},
		&cli.StringFlag{Name: "postgres-dsn", Value: "postgres://createos:createos@localhost:5432/createos?sslmode=disable", EnvVars: []string{"POSTGRES_DSN"}},
		&cli.StringFlag{Name: "region", Usage: "region this evictor operates on (required; only sandboxes with matching region are considered)", EnvVars: []string{"REGION"}},
		&cli.DurationFlag{Name: "max-age", Value: time.Hour, Usage: "destroy sandboxes older than this", EnvVars: []string{"MAX_AGE"}},
		&cli.StringFlag{Name: "disk-credential-key", Value: "", Usage: "path to disk credential key (needed to decrypt envs on sandbox rows with encrypted disks)", EnvVars: []string{"DISK_CREDENTIAL_KEY"}},
		&cli.BoolFlag{Name: "dry-run", Usage: "list aged sandboxes, don't flip them", EnvVars: []string{"DRY_RUN"}},
	}
}

// TTLEvictFromContext resolves the final TTLEvictConfig. Precedence:
// flag/env > YAML > default. Uses strict YAML — a typo in ttlevict.yaml
// fails fast.
func TTLEvictFromContext(c *cli.Context) (TTLEvictConfig, error) {
	var f TTLEvictFile
	if err := loadYAML(c.String("config"), &f); err != nil {
		return TTLEvictConfig{}, err
	}
	return TTLEvictConfig{
		PostgresDSN:           pickStr(c, "postgres-dsn", f.PostgresDSN),
		Region:                pickStr(c, "region", f.Region),
		MaxAge:                pickDur(c, "max-age", f.MaxAge),
		DiskCredentialKeyPath: pickStr(c, "disk-credential-key", f.DiskCredentialKey),
		DryRun:                pickBool(c, "dry-run", f.DryRun),
	}, nil
}
