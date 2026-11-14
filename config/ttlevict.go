package config

import (
	"fmt"
	"strings"
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
	UserMaxAge            map[string]time.Duration // running-window overrides keyed by durable sandbox owner
	DiskCredentialKeyPath string
	DryRun                bool
}

// TTLEvictFile is the YAML schema for `ttlevict.yaml`. It deliberately carries
// only this job's operational settings rather than sharing the full control
// schema.
type TTLEvictFile struct {
	PostgresDSN       *string                  `yaml:"postgres_dsn"`
	Region            *string                  `yaml:"region"`
	MaxAge            *time.Duration           `yaml:"max_age"`
	UserMaxAge        map[string]time.Duration `yaml:"user_max_age"`
	DiskCredentialKey *string                  `yaml:"disk_credential_key"`
	DryRun            *bool                    `yaml:"dry_run"`
}

// TTLEvictFlags returns the urfave/cli flags for `control ttl-evict`.
func TTLEvictFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "config", Usage: "path to YAML config file (ttlevict.yaml)"},
		&cli.StringFlag{Name: "postgres-dsn", Value: "postgres://createos:createos@localhost:5432/createos?sslmode=disable", EnvVars: []string{"POSTGRES_DSN"}},
		&cli.StringFlag{Name: "region", Usage: "region this evictor operates on (required; only sandboxes with matching region are considered)", EnvVars: []string{"REGION"}},
		&cli.DurationFlag{Name: "max-age", Value: time.Hour, Usage: "destroy sandboxes older than this", EnvVars: []string{"MAX_AGE"}},
		&cli.StringSliceFlag{Name: "user-max-age", Usage: "per-user running TTL (user-id=24h); repeat for multiple users", EnvVars: []string{"USER_MAX_AGE"}},
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
	overrides := f.UserMaxAge
	if c.IsSet("user-max-age") {
		overrides = make(map[string]time.Duration)
		for _, value := range c.StringSlice("user-max-age") {
			user, raw, ok := strings.Cut(value, "=")
			if !ok {
				return TTLEvictConfig{}, fmt.Errorf("user-max-age: expected user-id=duration")
			}
			duration, err := time.ParseDuration(raw)
			if err != nil {
				return TTLEvictConfig{}, fmt.Errorf("user-max-age for %q: %w", user, err)
			}
			if _, exists := overrides[user]; exists {
				return TTLEvictConfig{}, fmt.Errorf("user-max-age: duplicate user %q", user)
			}
			overrides[user] = duration
		}
	}
	for user, duration := range overrides {
		if strings.TrimSpace(user) == "" || user != strings.TrimSpace(user) || user == "pool" || duration <= 0 {
			return TTLEvictConfig{}, fmt.Errorf("user_max_age: user must be nonempty, not pool, and duration must be positive")
		}
	}
	return TTLEvictConfig{
		UserMaxAge:            overrides,
		PostgresDSN:           pickStr(c, "postgres-dsn", f.PostgresDSN),
		Region:                pickStr(c, "region", f.Region),
		MaxAge:                pickDur(c, "max-age", f.MaxAge),
		DiskCredentialKeyPath: pickStr(c, "disk-credential-key", f.DiskCredentialKey),
		DryRun:                pickBool(c, "dry-run", f.DryRun),
	}, nil
}
