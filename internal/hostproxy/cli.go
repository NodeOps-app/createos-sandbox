package hostproxy

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/NodeOps-app/sandbox/config"
	"github.com/NodeOps-app/sandbox/internal/mtlsclient"
)

// Cli is the urfave/cli Action for `machine proxy`.
func Cli(c *cli.Context) error {
	cfg, err := config.HostProxyFromContext(c)
	if err != nil {
		return err
	}
	// Outbound mTLS to control's by-ip endpoint. The proxy presents the
	// host's own client cert (SPIFFE URI spiffe://createos/host/<id>);
	// control's route accepts role=host on that endpoint.
	var apiClient *http.Client
	apiURL := cfg.API
	if cfg.TLSCertPath != "" && cfg.TLSKeyPath != "" && cfg.TLSCAPath != "" {
		tr, err := mtlsclient.NewTransport(cfg.TLSCertPath, cfg.TLSKeyPath, cfg.TLSCAPath, nil)
		if err != nil {
			return fmt.Errorf("proxy mTLS transport: %w", err)
		}
		apiClient = &http.Client{Timeout: 3 * time.Second, Transport: tr}
		if strings.HasPrefix(apiURL, "http://") {
			apiURL = "https://" + strings.TrimPrefix(apiURL, "http://")
		}
		fmt.Fprintf(os.Stderr, "[proxy] outbound mTLS to control enabled cert=%s api=%s\n", cfg.TLSCertPath, apiURL)
	} else {
		fmt.Fprintf(os.Stderr, "[proxy] outbound plain HTTP to control (dev mode) api=%s\n", apiURL)
	}
	p := New(cfg.HTTP, cfg.HTTPS, apiURL, apiClient, cfg.CacheTTL)
	return p.Run(context.Background())
}
