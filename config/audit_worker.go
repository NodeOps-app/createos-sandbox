package config

import "github.com/urfave/cli/v2"

type AuditWorkerConfig struct {
	PostgresDSN   string
	AuditLogURL   string
	WebhookSecret string
}

type AuditWorkerFile struct {
	PostgresDSN   *string `yaml:"postgres_dsn"`
	AuditLogURL   *string `yaml:"audit_log_url"`
	WebhookSecret *string `yaml:"webhook_secret"`
}

func AuditWorkerFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "config", Usage: "path to YAML config"},
		&cli.StringFlag{Name: "postgres-dsn", Value: "postgres://createos:createos@localhost:5432/createos?sslmode=disable", EnvVars: []string{"POSTGRES_DSN"}},
		&cli.StringFlag{Name: "audit-log-url", Usage: "backend destination URL", EnvVars: []string{"AUDIT_LOG_URL"}},
		// Env fallback to BILLING_WEBHOOK_SECRET so deployments that
		// already mount the billing secret don't need a second one.
		&cli.StringFlag{Name: "webhook-secret", Usage: "HMAC-SHA256 signing key", EnvVars: []string{"WEBHOOK_SECRET", "BILLING_WEBHOOK_SECRET"}},
	}
}

func AuditWorkerFromContext(c *cli.Context) (AuditWorkerConfig, error) {
	var f AuditWorkerFile
	if err := loadYAML(c.String("config"), &f); err != nil {
		return AuditWorkerConfig{}, err
	}
	return AuditWorkerConfig{
		PostgresDSN:   pickStr(c, "postgres-dsn", f.PostgresDSN),
		AuditLogURL:   pickStr(c, "audit-log-url", f.AuditLogURL),
		WebhookSecret: pickStr(c, "webhook-secret", f.WebhookSecret),
	}, nil
}
