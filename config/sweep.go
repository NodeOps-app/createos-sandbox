package config

import (
	"time"

	"github.com/urfave/cli/v2"
)

// SweepConfig is the resolved config for the `control sweep` cron. Only
// carries the fields the janitor actually touches: DB, dead-host TTL,
// region, storage creds (for stale-bundle purge), host mTLS bundle,
// scheduler URL (for drain-time resume kickoff). Deliberately does NOT
// share ControlFile — sweep is a maintenance job, and adding/removing
// tuning knobs to control shouldn't crash the janitor via strict YAML.
type SweepConfig struct {
	PostgresDSN         string
	DeadHostEvictAfter  time.Duration
	Region              string
	SchedulerURL        string
	InternalTLSCertPath string
	InternalTLSKeyPath  string
	InternalTLSCAPath   string
	Storage             StorageConfig
	PlacementPolicies   map[string]PlacementPolicy
	DryRun              bool
	StuckTransitionAge  time.Duration
}

// SweepFile is the YAML schema for `sweep.yaml`. All operational
// plumbing sweep needs, nothing more. Kept intentionally minimal so
// operators don't accidentally over-share control-plane secrets with a
// maintenance CronJob.
type SweepFile struct {
	PostgresDSN        *string                    `yaml:"postgres_dsn"`
	DeadHostEvictAfter *time.Duration             `yaml:"dead_host_evict_after"`
	Region             *string                    `yaml:"region"`
	SchedulerURL       *string                    `yaml:"scheduler_url"`
	InternalTLSCert    *string                    `yaml:"internal_tls_cert"`
	InternalTLSKey     *string                    `yaml:"internal_tls_key"`
	InternalTLSCA      *string                    `yaml:"internal_tls_ca"`
	Storage            *StorageFile               `yaml:"storage"`
	PlacementPolicies  map[string]PlacementPolicy `yaml:"placement_policies"`
	DryRun             *bool                      `yaml:"dry_run"`
	StuckTransitionAge *time.Duration             `yaml:"stuck_transition_age"`
}

// SweepFlags returns the urfave/cli flags for `control sweep`. Scalar
// tunables are reachable via flag, env, and YAML. The placement-policies map
// remains YAML-only because it is structured deployment policy.
func SweepFlags() []cli.Flag {
	flags := []cli.Flag{
		&cli.StringFlag{Name: "config", Usage: "path to YAML config file (sweep.yaml)"},
		&cli.StringFlag{Name: "postgres-dsn", Value: "postgres://createos:createos@localhost:5432/createos?sslmode=disable", EnvVars: []string{"POSTGRES_DSN"}},
		&cli.DurationFlag{Name: "dead-host-evict-after", Value: 0, Usage: "mark sandboxes destroyed after their host has been dead this long; 0 = disabled", EnvVars: []string{"DEAD_HOST_EVICT_AFTER"}},
		&cli.StringFlag{Name: "region", EnvVars: []string{"REGION"}},
		&cli.StringFlag{Name: "scheduler-url", EnvVars: []string{"SCHEDULER_URL"}, Usage: "base URL for the standalone scheduler; empty = drain pass skips resume kickoff"},
		&cli.StringFlag{Name: "internal-tls-cert", EnvVars: []string{"INTERNAL_TLS_CERT"}, Usage: "path to leaf cert for mTLS to hosts (drain pass)"},
		&cli.StringFlag{Name: "internal-tls-key", EnvVars: []string{"INTERNAL_TLS_KEY"}},
		&cli.StringFlag{Name: "internal-tls-ca", EnvVars: []string{"INTERNAL_TLS_CA"}},
		&cli.BoolFlag{Name: "dry-run", Usage: "list candidates, don't mutate", EnvVars: []string{"DRY_RUN"}},
		&cli.DurationFlag{Name: "stuck-transition-age", Value: 15 * time.Minute, Usage: "rows stuck in pausing/resuming/forking past this duration get rolled back", EnvVars: []string{"STUCK_TRANSITION_AGE"}},
	}
	return append(flags, StorageFlags()...)
}

// SweepFromContext resolves the final SweepConfig. Precedence: flag/env
// > YAML > default. Uses strict YAML — a typo in sweep.yaml fails fast.
func SweepFromContext(c *cli.Context) (SweepConfig, error) {
	var f SweepFile
	if err := loadYAML(c.String("config"), &f); err != nil {
		return SweepConfig{}, err
	}
	cfg := SweepConfig{
		PostgresDSN:         pickStr(c, "postgres-dsn", f.PostgresDSN),
		DeadHostEvictAfter:  pickDur(c, "dead-host-evict-after", f.DeadHostEvictAfter),
		Region:              pickStr(c, "region", f.Region),
		SchedulerURL:        pickStr(c, "scheduler-url", f.SchedulerURL),
		InternalTLSCertPath: pickStr(c, "internal-tls-cert", f.InternalTLSCert),
		InternalTLSKeyPath:  pickStr(c, "internal-tls-key", f.InternalTLSKey),
		InternalTLSCAPath:   pickStr(c, "internal-tls-ca", f.InternalTLSCA),
		DryRun:              pickBool(c, "dry-run", f.DryRun),
		StuckTransitionAge:  pickDur(c, "stuck-transition-age", f.StuckTransitionAge),
		PlacementPolicies:   f.PlacementPolicies,
	}
	cfg.Storage = resolveStorage(c, f.Storage)
	return cfg, nil
}

// resolveStorage folds CLI flags over an optional YAML block. Shared by
// SweepFromContext + TTLEvictFromContext (if the latter ever grows a
// storage dependency).
func resolveStorage(c *cli.Context, f *StorageFile) StorageConfig {
	sc := StorageConfig{
		Bucket:          c.String("storage-bucket"),
		Endpoint:        c.String("storage-endpoint"),
		Region:          c.String("storage-region"),
		AccessKeyID:     c.String("storage-access-key-id"),
		SecretAccessKey: c.String("storage-secret-access-key"),
		Secure:          c.Bool("storage-secure"),
	}
	if f == nil {
		return sc
	}
	if !c.IsSet("storage-bucket") && f.Bucket != nil {
		sc.Bucket = *f.Bucket
	}
	if !c.IsSet("storage-endpoint") && f.Endpoint != nil {
		sc.Endpoint = *f.Endpoint
	}
	if !c.IsSet("storage-region") && f.Region != nil {
		sc.Region = *f.Region
	}
	if !c.IsSet("storage-access-key-id") && f.AccessKeyID != nil {
		sc.AccessKeyID = *f.AccessKeyID
	}
	if !c.IsSet("storage-secret-access-key") && f.SecretAccessKey != nil {
		sc.SecretAccessKey = *f.SecretAccessKey
	}
	if !c.IsSet("storage-secure") && f.Secure != nil {
		sc.Secure = *f.Secure
	}
	return sc
}
