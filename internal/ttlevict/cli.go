package ttlevict

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"

	"github.com/NodeOps-app/createos-sandbox/config"
	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/diskcrypto"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// Cli starts the one-shot TTL evictor with its dedicated configuration:
// database, region, default and per-user TTLs, dry-run mode, and environment
// decryption key. It does not load the API server's control configuration.
func Cli(c *cli.Context) error {
	tcfg, err := config.TTLEvictFromContext(c)
	if err != nil {
		return err
	}
	// Wire the disk credential cipher into models so sandbox rows with
	// encrypted envs (AES-GCM envelope written by control) decode cleanly
	// when this sweep loads them for billing emit. Without this, every
	// row with an encrypted envs column fails to unmarshal and the whole
	// sweep query aborts.
	if tcfg.DiskCredentialKeyPath != "" {
		key, kerr := diskcrypto.LoadKeyFromFile(tcfg.DiskCredentialKeyPath)
		if kerr != nil {
			return fmt.Errorf("ttl-evict disk credential key: %w", kerr)
		}
		cipher, kerr := diskcrypto.New(key)
		if kerr != nil {
			return fmt.Errorf("ttl-evict disk credential key: %w", kerr)
		}
		models.SetEnvCipher(cipher)
		fmt.Fprintf(os.Stderr, "[ttl-evict] disk credential cipher loaded; envs decryption wired\n")
	} else {
		fmt.Fprintf(os.Stderr, "[ttl-evict] WARN: disk_credential_key not set; envs decryption DISABLED — sweep will fail on AES-GCM envelope rows\n")
	}
	cfg := Config{
		PostgresDSN: tcfg.PostgresDSN,
		Region:      tcfg.Region,
		MaxAge:      tcfg.MaxAge,
		UserMaxAge:  tcfg.UserMaxAge,
		DryRun:      tcfg.DryRun,
	}
	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "[ttl-evict] "+format+"\n", args...)
	}
	_, err = Run(c.Context, cfg, logf)
	return err
}
