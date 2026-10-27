package builder

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/minio/minio-go/v7"
	miniocreds "github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/urfave/cli/v2"

	"github.com/NodeOps-app/sandbox/config"
	"github.com/NodeOps-app/sandbox/internal/buildqueue/pgqueue"
	authjwt "github.com/NodeOps-app/sandbox/internal/jwt"
	"github.com/NodeOps-app/sandbox/models"
)

// Cli is the urfave/cli Action for `control builder`.
func Cli(c *cli.Context) error {
	cfg, err := config.BuilderFromContext(c)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	repo, err := models.OpenRepo(context.Background(), cfg.PostgresDSN)
	if err != nil {
		return err
	}
	defer repo.Close()

	priv, err := authjwt.LoadOrGenerateSeed(cfg.SigningKeyPath)
	if err != nil {
		return fmt.Errorf("builder signing key: %w", err)
	}
	signer := authjwt.NewSigner(priv, "builder:"+cfg.BuilderID)
	fmt.Fprintf(os.Stderr, "[builder] signing-key kid=%s pub=%x\n",
		signer.KID(), signer.PublicKey())

	// R2 client for pre-signing PUT URLs.
	r2cli, err := newMinioClient(cfg)
	if err != nil {
		return fmt.Errorf("init R2 client: %w", err)
	}
	grants := NewGrantIssuer(signer, r2cli, cfg.R2Bucket)
	queue := pgqueue.New(repo)
	keyBytes, err := os.ReadFile(cfg.SandboxAPIKeyFile)
	if err != nil {
		return fmt.Errorf("read sandbox api key: %w", err)
	}
	apiKey := strings.TrimSpace(string(keyBytes))
	if apiKey == "" {
		return fmt.Errorf("sandbox api key file is empty")
	}
	executor := NewSandboxExecutor(SandboxExecutorConfig{
		APIURL: cfg.SandboxAPIURL, APIKey: apiKey, Rootfs: cfg.SandboxRootfs,
		Shape: cfg.SandboxShape, DiskMiB: cfg.SandboxDiskMiB, Region: cfg.SandboxRegion,
	}, nil)

	svc := NewService(Config{
		BuilderID:          cfg.BuilderID,
		ControlURL:         cfg.ControlURL,
		BuildTimeout:       cfg.BuildTimeout,
		GlobalConcurrency:  cfg.GlobalConcurrency,
		PerUserConcurrency: cfg.PerUserConcurrency,
		PollInterval:       cfg.PollInterval,
		JanitorInterval:    cfg.JanitorInterval,
		SizeCapMiB:         cfg.SizeCapMiB,
		AllowedBases:       cfg.AllowedBases,
	}, queue, grants, executor)
	return svc.Run(context.Background())
}

// newMinioClient constructs the raw minio-go client the builder uses to
// mint pre-signed PUT URLs. We don't reuse storage.R2 because that type
// encapsulates Put/Get/Copy on the bucket; the builder needs the
// underlying client for PresignedPutObject.
func newMinioClient(cfg config.BuilderConfig) (*minio.Client, error) {
	endpoint := cfg.R2Endpoint
	for _, p := range []string{"https://", "http://"} {
		if strings.HasPrefix(endpoint, p) {
			endpoint = endpoint[len(p):]
			break
		}
	}
	return minio.New(endpoint, &minio.Options{
		Creds:  miniocreds.NewStaticV4(cfg.R2AccessKey, cfg.R2SecretKey, ""),
		Secure: cfg.R2Secure,
		Region: cfg.R2Region,
	})
}
