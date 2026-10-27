package config

import "github.com/urfave/cli/v2"

type BillingWorkerConfig struct {
	PostgresDSN          string
	BillingWebhookURL    string
	BillingWebhookSecret string
}

type BillingWorkerFile struct {
	PostgresDSN          *string `yaml:"postgres_dsn"`
	BillingWebhookURL    *string `yaml:"billing_webhook_url"`
	BillingWebhookSecret *string `yaml:"billing_webhook_secret"`
}

func BillingWorkerFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "config", Usage: "path to YAML config"},
		&cli.StringFlag{Name: "postgres-dsn", Value: "postgres://createos:createos@localhost:5432/createos?sslmode=disable", EnvVars: []string{"POSTGRES_DSN"}},
		&cli.StringFlag{Name: "billing-webhook-url", Usage: "destination URL for sandbox lifecycle events", EnvVars: []string{"BILLING_WEBHOOK_URL"}},
		&cli.StringFlag{Name: "billing-webhook-secret", Usage: "HMAC-SHA256 signing key", EnvVars: []string{"BILLING_WEBHOOK_SECRET"}},
	}
}

func BillingWorkerFromContext(c *cli.Context) (BillingWorkerConfig, error) {
	var f BillingWorkerFile
	if err := loadYAML(c.String("config"), &f); err != nil {
		return BillingWorkerConfig{}, err
	}
	return BillingWorkerConfig{
		PostgresDSN:          pickStr(c, "postgres-dsn", f.PostgresDSN),
		BillingWebhookURL:    pickStr(c, "billing-webhook-url", f.BillingWebhookURL),
		BillingWebhookSecret: pickStr(c, "billing-webhook-secret", f.BillingWebhookSecret),
	}, nil
}
