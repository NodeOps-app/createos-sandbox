package config

import (
	"fmt"
	"time"

	"github.com/urfave/cli/v2"
)

// SchedulerConfig is the resolved configuration for the `scheduler` subcommand.
type SchedulerConfig struct {
	Addr                   string
	PostgresDSN            string
	LeaderID               string
	LeaderKey              int64
	WarmingPeriod          time.Duration
	ReservationTTL         time.Duration
	HydrateInterval        time.Duration
	ReservationGracePeriod time.Duration
	// PendingCap is the hard ceiling for in-flight (reserved-but-not-yet-
	// durable) sandboxes per host. The PendingCapFilter rejects placement
	// on hosts at or above this cap so a tight burst spreads across the
	// fleet instead of dumping into one host's queue. 0 disables the cap.
	PendingCap int
	// DiskSafetyPercent reserves a fraction of each host filesystem for
	// snapshots, cached templates, filesystem metadata, and emergency room.
	DiskSafetyPercent int
	// DiskTransientReserveMiB reserves fixed working space for concurrent
	// template downloads/decompression and snapshot generation.
	DiskTransientReserveMiB int64
	TraceDB                 bool

	// TLS server config — listener wraps in TLS 1.3 + RequireAndVerifyClientCert
	// when all three paths are set; empty paths leave it plain (dev only).
	TLSCertPath string
	TLSKeyPath  string
	TLSCAPath   string
}

// SchedulerFile is the YAML schema for the scheduler.
type SchedulerFile struct {
	Addr                    *string `yaml:"addr"`
	PostgresDSN             *string `yaml:"postgres_dsn"`
	LeaderID                *string `yaml:"leader_id"`
	LeaderKey               *int64  `yaml:"leader_key"`
	WarmingPeriod           *string `yaml:"warming_period"`
	ReservationTTL          *string `yaml:"reservation_ttl"`
	HydrateInterval         *string `yaml:"hydrate_interval"`
	ReservationGracePeriod  *string `yaml:"reservation_grace_period"`
	PendingCap              *int    `yaml:"pending_cap"`
	DiskSafetyPercent       *int    `yaml:"disk_safety_percent"`
	DiskTransientReserveMiB *int64  `yaml:"disk_transient_reserve_mib"`
	TraceDB                 *bool   `yaml:"trace_db"`
	TLSCertPath             *string `yaml:"tls_cert"`
	TLSKeyPath              *string `yaml:"tls_key"`
	TLSCAPath               *string `yaml:"tls_ca"`
}

// SchedulerFlags returns the urfave/cli flags for the `scheduler` subcommand.
func SchedulerFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "config", Usage: "path to YAML config file"},
		&cli.StringFlag{Name: "addr", Value: ":9100", EnvVars: []string{"SCHEDULER_ADDR"}},
		&cli.StringFlag{Name: "postgres-dsn", Value: "postgres://createos:createos@localhost:5432/createos?sslmode=disable", EnvVars: []string{"POSTGRES_DSN"}},
		&cli.StringFlag{Name: "leader-id", Value: "", Usage: "identifier reported in /readyz; defaults to host name", EnvVars: []string{"SCHEDULER_LEADER_ID"}},
		&cli.Int64Flag{Name: "leader-key", Value: 0xFC5C5CED, Usage: "Postgres advisory-lock key (unique per role)", EnvVars: []string{"SCHEDULER_LEADER_KEY"}},
		&cli.DurationFlag{Name: "warming-period", Value: 10 * time.Second, Usage: "delay between hydration and accepting Schedule traffic", EnvVars: []string{"SCHEDULER_WARMING_PERIOD"}},
		&cli.DurationFlag{Name: "reservation-ttl", Value: 30 * time.Second, Usage: "lifetime of a Schedule reservation token (TTL sweeper + published ExpiresAtMs)", EnvVars: []string{"SCHEDULER_RESERVATION_TTL"}},
		&cli.DurationFlag{Name: "hydrate-interval", Value: 5 * time.Second, Usage: "how often the scheduler re-reads sandboxes table to refresh host cache + reconcile in-mem reservations", EnvVars: []string{"SCHEDULER_HYDRATE_INTERVAL"}},
		&cli.DurationFlag{Name: "reservation-grace-period", Value: 60 * time.Second, Usage: "how long an in-mem reservation can survive without a matching durable row before being dropped (catches mid-flight control crashes)", EnvVars: []string{"SCHEDULER_RESERVATION_GRACE_PERIOD"}},
		&cli.IntFlag{Name: "pending-cap", Value: 100, Usage: "max in-flight placements per host before scheduler 503s (combined with host-side boot semaphore for end-to-end back-pressure). 0 disables.", EnvVars: []string{"SCHEDULER_PENDING_CAP"}},
		&cli.IntFlag{Name: "disk-safety-percent", Value: 10, Usage: "percent of each host disk withheld from VM scheduling for snapshots, templates, metadata, and emergency headroom", EnvVars: []string{"SCHEDULER_DISK_SAFETY_PERCENT"}},
		&cli.Int64Flag{Name: "disk-transient-reserve-mib", Value: 20 * 1024, Usage: "fixed MiB withheld per host for template download/decompression and snapshot-generation working space", EnvVars: []string{"SCHEDULER_DISK_TRANSIENT_RESERVE_MIB"}},
		&cli.BoolFlag{Name: "trace-db", Value: false, Usage: "log every DB call's duration", EnvVars: []string{"TRACE_DB"}},
		&cli.StringFlag{Name: "tls-cert", Value: "", Usage: "path to TLS server certificate (PEM)", EnvVars: []string{"TLS_CERT"}},
		&cli.StringFlag{Name: "tls-key", Value: "", Usage: "path to TLS server private key (PEM)", EnvVars: []string{"TLS_KEY"}},
		&cli.StringFlag{Name: "tls-ca", Value: "", Usage: "path to CA bundle used to verify peer client certs (PEM)", EnvVars: []string{"TLS_CA"}},
	}
}

// SchedulerFromContext resolves the final config. Precedence: flag/env > YAML > default.
func SchedulerFromContext(c *cli.Context) (SchedulerConfig, error) {
	var f SchedulerFile
	if err := loadYAML(c.String("config"), &f); err != nil {
		return SchedulerConfig{}, err
	}
	cfg := SchedulerConfig{
		Addr:        pickStr(c, "addr", f.Addr),
		PostgresDSN: pickStr(c, "postgres-dsn", f.PostgresDSN),
	}
	cfg.LeaderID = c.String("leader-id")
	if f.LeaderID != nil && !c.IsSet("leader-id") {
		cfg.LeaderID = *f.LeaderID
	}
	cfg.LeaderKey = c.Int64("leader-key")
	if f.LeaderKey != nil && !c.IsSet("leader-key") {
		cfg.LeaderKey = *f.LeaderKey
	}
	cfg.WarmingPeriod = c.Duration("warming-period")
	if f.WarmingPeriod != nil && !c.IsSet("warming-period") {
		d, err := time.ParseDuration(*f.WarmingPeriod)
		if err != nil {
			return SchedulerConfig{}, err
		}
		cfg.WarmingPeriod = d
	}
	cfg.ReservationTTL = c.Duration("reservation-ttl")
	if f.ReservationTTL != nil && !c.IsSet("reservation-ttl") {
		d, err := time.ParseDuration(*f.ReservationTTL)
		if err != nil {
			return SchedulerConfig{}, err
		}
		cfg.ReservationTTL = d
	}
	cfg.HydrateInterval = c.Duration("hydrate-interval")
	if f.HydrateInterval != nil && !c.IsSet("hydrate-interval") {
		d, err := time.ParseDuration(*f.HydrateInterval)
		if err != nil {
			return SchedulerConfig{}, err
		}
		cfg.HydrateInterval = d
	}
	cfg.ReservationGracePeriod = c.Duration("reservation-grace-period")
	if f.ReservationGracePeriod != nil && !c.IsSet("reservation-grace-period") {
		d, err := time.ParseDuration(*f.ReservationGracePeriod)
		if err != nil {
			return SchedulerConfig{}, err
		}
		cfg.ReservationGracePeriod = d
	}
	cfg.PendingCap = pickInt(c, "pending-cap", f.PendingCap)
	cfg.DiskSafetyPercent = pickInt(c, "disk-safety-percent", f.DiskSafetyPercent)
	cfg.DiskTransientReserveMiB = c.Int64("disk-transient-reserve-mib")
	if f.DiskTransientReserveMiB != nil && !c.IsSet("disk-transient-reserve-mib") {
		cfg.DiskTransientReserveMiB = *f.DiskTransientReserveMiB
	}
	if cfg.DiskSafetyPercent < 0 || cfg.DiskSafetyPercent > 100 {
		return SchedulerConfig{}, fmt.Errorf("disk_safety_percent must be between 0 and 100")
	}
	if cfg.DiskTransientReserveMiB < 0 {
		return SchedulerConfig{}, fmt.Errorf("disk_transient_reserve_mib must be non-negative")
	}
	cfg.TraceDB = c.Bool("trace-db")
	if f.TraceDB != nil && !c.IsSet("trace-db") {
		cfg.TraceDB = *f.TraceDB
	}
	cfg.TLSCertPath = pickStr(c, "tls-cert", f.TLSCertPath)
	cfg.TLSKeyPath = pickStr(c, "tls-key", f.TLSKeyPath)
	cfg.TLSCAPath = pickStr(c, "tls-ca", f.TLSCAPath)
	return cfg, nil
}
