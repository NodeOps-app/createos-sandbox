package sweep

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/NodeOps-app/createos-sandbox/config"
	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/diskcrypto"
	"github.com/NodeOps-app/createos-sandbox/internal/hostrpc"
	"github.com/NodeOps-app/createos-sandbox/internal/mtlsclient"
	"github.com/NodeOps-app/createos-sandbox/internal/placementpolicy"
	schedclient "github.com/NodeOps-app/createos-sandbox/internal/scheduler/client"
	"github.com/NodeOps-app/createos-sandbox/internal/storage"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// Cli is the urfave/cli Action for `control sweep`. Reads its own
// dedicated config surface (sweep.yaml) — never shares the control
// plane's ControlFile. Same operational plumbing (DSN, region, host
// mTLS bundle, storage creds, scheduler URL), independent lifecycle.
func Cli(c *cli.Context) error {
	scfg, err := config.SweepFromContext(c)
	if err != nil {
		return err
	}
	// Sandbox row decoding needs the same environment cipher as control.
	// Without it, encrypted envelopes abort the entire drain-host query.
	if scfg.DiskCredentialKeyPath != "" {
		key, err := diskcrypto.LoadKeyFromFile(scfg.DiskCredentialKeyPath)
		if err != nil {
			return fmt.Errorf("sweep disk credential key: %w", err)
		}
		cipher, err := diskcrypto.New(key)
		if err != nil {
			return fmt.Errorf("sweep disk credential key: %w", err)
		}
		models.SetEnvCipher(cipher)
	}
	// Sweep runs separately from the API server, so it must load placement
	// policies itself to apply user placement rules during drain resumes.
	configuredPolicies := make(map[string]placementpolicy.Policy, len(scfg.PlacementPolicies))
	for userID, policy := range scfg.PlacementPolicies {
		configuredPolicies[userID] = placementpolicy.Policy{
			Region: policy.Region, Shapes: policy.Shapes, PreferredHostIDs: policy.PreferredHostIDs,
		}
	}
	placementpolicy.Configure(configuredPolicies)
	if scfg.Region == "" {
		return fmt.Errorf("sweep: region required (would otherwise sweep every region's rows)")
	}
	cfg := Config{
		PostgresDSN:        scfg.PostgresDSN,
		DeadHostEvictAfter: scfg.DeadHostEvictAfter,
		Region:             scfg.Region,
		DryRun:             scfg.DryRun,
		StuckTransitionAge: scfg.StuckTransitionAge,
	}
	// Hosts run mTLS-only when TLS is configured. The sweep dials hosts
	// directly during drain for pause and resume,
	// so flip the package-level scheme to https when the internal TLS
	// bundle is wired — otherwise plain http hits the host's TLS listener
	// and fails.
	if scfg.InternalTLSCertPath != "" {
		hostrpc.SetHostScheme("https")
	}
	if bucket := scfg.Storage.Bucket; bucket != "" {
		st, err := storage.NewR2(storage.R2Config{
			Endpoint:        scfg.Storage.Endpoint,
			Region:          scfg.Storage.Region,
			AccessKeyID:     scfg.Storage.AccessKeyID,
			SecretAccessKey: scfg.Storage.SecretAccessKey,
			Bucket:          bucket,
			Secure:          scfg.Storage.Secure,
		})
		if err != nil {
			return fmt.Errorf("sweep: init R2 storage: %w", err)
		}
		cfg.Storage = st
	}
	// Drain pass needs the scheduler client + mTLS-wired HTTP client so
	// it can Schedule() resume placements and authenticate to hosts.
	// Missing scheduler URL disables drain — the other sweep passes
	// still run.
	if scfg.SchedulerURL != "" {
		var hostTr *http.Transport
		if scfg.InternalTLSCertPath != "" {
			// Drain calls hosts directly for pause and resume; those
			// endpoints require a control-role client certificate. Configure the
			// control leaf certificate here; this loads it without issuing a
			// separate sweeper certificate. Database-only
			// cleanup does not need this transport.
			tr, err := mtlsclient.NewTransport(
				scfg.InternalTLSCertPath,
				scfg.InternalTLSKeyPath,
				scfg.InternalTLSCAPath,
				nil,
			)
			if err != nil {
				return fmt.Errorf("sweep: host mTLS transport: %w", err)
			}
			hostTr = tr
		}
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second, Transport: hostTr}
		cfg.SchedulerClient = schedclient.New(schedclient.Config{
			BaseURL: scfg.SchedulerURL,
		}, func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "[sweep.sched] "+format+"\n", args...)
		})
		// Sweep is short-lived so wait synchronously for the first probe
		// instead of relying on control's background ticker. If it fails
		// resume scheduling sees ErrSchedulerUnavailable. Drain may still
		// trigger pauses, and the other sweep passes still run.
		probeCtx, probeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		ok := cfg.SchedulerClient.ProbeSync(probeCtx)
		probeCancel()
		if !ok {
			fmt.Fprintf(os.Stderr, "[sweep.sched] initial probe failed; drain pass will skip resume kickoff this tick\n")
		}
	}
	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "[sweep] "+format+"\n", args...)
	}
	_, err = Run(c.Context, cfg, logf)
	return err
}
