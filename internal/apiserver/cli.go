package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/NodeOps-app/sandbox/config"
	"github.com/NodeOps-app/sandbox/database"
	"github.com/NodeOps-app/sandbox/internal/apiserver/cache"
	"github.com/NodeOps-app/sandbox/internal/apiserver/diskcrypto"
	"github.com/NodeOps-app/sandbox/internal/apiserver/handlers"
	"github.com/NodeOps-app/sandbox/internal/apiserver/metrics"
	"github.com/NodeOps-app/sandbox/internal/apiserver/userapikey"
	"github.com/NodeOps-app/sandbox/internal/ca"
	"github.com/NodeOps-app/sandbox/internal/clickhouse"
	"github.com/NodeOps-app/sandbox/internal/createos"
	authjwt "github.com/NodeOps-app/sandbox/internal/jwt"
	"github.com/NodeOps-app/sandbox/internal/placementpolicy"
	schedclient "github.com/NodeOps-app/sandbox/internal/scheduler/client"
	"github.com/NodeOps-app/sandbox/internal/storage"
	"github.com/NodeOps-app/sandbox/models"
)

// Cli is the urfave/cli Action for `control api-server`.
func Cli(c *cli.Context) error {
	cfg, err := config.ControlFromContext(c)
	if err != nil {
		return err
	}
	configuredPolicies := make(map[string]placementpolicy.Policy, len(cfg.PlacementPolicies))
	for userID, policy := range cfg.PlacementPolicies {
		configuredPolicies[userID] = placementpolicy.Policy{
			Region: policy.Region, Shapes: policy.Shapes, PreferredHostIDs: policy.PreferredHostIDs,
		}
	}
	placementpolicy.Configure(configuredPolicies)
	placementpolicy.ConfigureCrossRegionUsers(cfg.EnabledCrossRegionUsers)
	// Populate the process-wide GeoIP reader. Missing/unreadable file
	// is a soft failure: control still starts, the country label just
	// reads "unknown".
	metrics.LoadGeoIPDB(cfg.GeoIPDBPath)
	database.SetTraceEnabled(cfg.TraceDB)
	repo, err := models.OpenRepoWithPoolConfig(context.Background(), cfg.PostgresDSN, database.PoolConfig{
		// Keep enough backends alive for an idle-to-100 burst. The generic
		// repository defaults stay small for scheduler, ingress and workers.
		MinConns:  40,
		MaxConns:  120,
		WarmConns: 40,
	})
	if err != nil {
		return err
	}
	defer repo.Close()
	// Per-host pubkey cache feeds InternalJWTMiddleware. Looks up
	// hosts.public_key + hosts.status; the verifier closure inside
	// control.Server uses status to refuse JWTs from dead hosts.
	hostPubkeys := cache.NewHostPubkeys(repo, 30*time.Second)

	// Static actor pubkeys for inbound JWT verification. Post-mTLS, only
	// builder (build sandboxes → template PATCH/log ingest) and billing
	// (external service → reconcile API) still authenticate via JWT;
	// every other internal hop uses mTLS.
	ctrlActors := authjwt.NewPubkeyMap()
	// Builder pubkey verifies template-PATCH JWTs (sub=tpl_<id>). Optional
	// in dev — when empty, the PATCH route 401s on every request, which is
	// the correct fail-closed behaviour.
	if cfg.VerifyBuilderPubkey != "" {
		if err := ctrlActors.LoadAndSet("builder:builder-1", cfg.VerifyBuilderPubkey); err != nil {
			return err
		}
	}
	// Billing pubkey verifies GET /v1/internal/billing/sandboxes/:id JWTs.
	// Optional — when empty the route 401s, which is the correct
	// fail-closed behaviour when no billing system is integrated.
	if cfg.VerifyBillingPubkey != "" {
		if err := ctrlActors.LoadAndSet("billing:billing-1", cfg.VerifyBillingPubkey); err != nil {
			return err
		}
	}

	var buildLogs *clickhouse.Client
	if cfg.ClickHouseURL != "" {
		buildLogs = clickhouse.New(clickhouse.Config{
			URL:      cfg.ClickHouseURL,
			Username: cfg.ClickHouseUsername,
			Password: cfg.ClickHousePassword,
			Database: cfg.ClickHouseDatabase,
		})
		// Schema is operator-managed via the standalone goose CLI; the
		// binary never touches migrations. Operators run `make migrate-ch-up`
		// before deploying control.
		fmt.Fprintf(os.Stderr, "[control] build logs ClickHouse %s db=%s\n",
			cfg.ClickHouseURL, cfg.ClickHouseDatabase)
	}

	// Disk credential cipher: optional, but if a key path is given we
	// MUST be able to construct a valid 32-byte AES key, or startup
	// fails fast. Empty path → disks API stays disabled (handler 503s).
	var diskCipher *diskcrypto.Cipher
	if cfg.DiskCredentialKeyPath != "" {
		key, kerr := diskcrypto.LoadKeyFromFile(cfg.DiskCredentialKeyPath)
		if kerr != nil {
			return fmt.Errorf("control disk credential key: %w", kerr)
		}
		diskCipher, kerr = diskcrypto.New(key)
		if kerr != nil {
			return fmt.Errorf("control disk credential key: %w", kerr)
		}
		// Same cipher transparently encrypts sandboxes.envs at rest.
		// User-supplied env values (potentially secrets) become AES-256-
		// GCM-wrapped JSON envelopes in the DB; legacy plaintext rows
		// continue to load via the dual-read path in unmarshalEnvs.
		models.SetEnvCipher(diskCipher)
		fmt.Fprintf(os.Stderr, "[control] disk credential cipher loaded (AES-256-GCM); also wired for sandboxes.envs\n")
	}

	// API-key HMAC pepper: optional during phase A (empty → control falls
	// back to plaintext lookups against api_keys.key for backwards
	// compatibility). When set, every inbound user token is HMAC'd with
	// the pepper before hitting Postgres. Reuses diskcrypto's loader so
	// raw / hex / base64 are all accepted.
	var apiKeyPepper []byte
	if cfg.APIKeyHMACKeyPath != "" {
		key, kerr := diskcrypto.LoadKeyFromFile(cfg.APIKeyHMACKeyPath)
		if kerr != nil {
			return fmt.Errorf("control api-key pepper: %w", kerr)
		}
		apiKeyPepper = key
		fmt.Fprintf(os.Stderr, "[control] api-key pepper loaded (HMAC-SHA256, %d bytes)\n", len(key))
	}

	// Optional in-process CA. Both paths set → load (or auto-create
	// on first run). Empty → mTLS bootstrap endpoints stay 503.
	var caObj *ca.CA
	if cfg.CAKeyPath != "" && cfg.CACertPath != "" {
		obj, err := ca.LoadOrCreateCA(cfg.CAKeyPath, cfg.CACertPath)
		if err != nil {
			return fmt.Errorf("control CA: %w", err)
		}
		caObj = obj
		fp := sha256.Sum256(obj.Cert.Raw)
		fmt.Fprintf(os.Stderr, "[control] CA loaded fingerprint=%s\n", hex.EncodeToString(fp[:]))
	} else {
		fmt.Fprintf(os.Stderr, "[control] mTLS disabled (no --ca-key/--ca-cert)\n")
	}

	deps := Deps{
		Repo:                       repo,
		BuildLogs:                  buildLogs,
		Addr:                       cfg.Addr,
		PanicMode:                  cfg.PanicMode,
		DisableDeviceRegistration:  !cfg.DeviceRegistrationEnabled,
		Resolver:                   resolverFromRepo(repo, apiKeyPepper, cfg.AuthCacheTTL, cfg.ExternalAuthURL, cfg.ExternalAuthTTL),
		AdminToken:                 cfg.AdminToken,
		PromSDToken:                loadPromSDTokenOrDie(cfg.PromSDTokenFile),
		BootstrapToken:             cfg.BootstrapToken,
		RelayBootstrapToken:        cfg.RelayBootstrapToken,
		StaticActors:               ctrlActors,
		HostPubkeys:                hostPubkeys,
		Region:                     cfg.Region,
		RelayCrossRegionFallback:   cfg.RelayCrossRegionFallback,
		MaxSandboxConcurrent:       cfg.MaxSandboxConcurrent,
		MaxSandboxPerDay:           cfg.MaxSandboxPerDay,
		MaxNetworkConcurrent:       cfg.MaxNetworkConcurrent,
		MaxNetworkPerDay:           cfg.MaxNetworkPerDay,
		MaxDiskConcurrent:          cfg.MaxDiskConcurrent,
		MaxDiskPerDay:              cfg.MaxDiskPerDay,
		MaxTemplateConcurrent:      cfg.MaxTemplateConcurrent,
		MaxTemplatePerDay:          cfg.MaxTemplatePerDay,
		IngressDomainSuffix:        cfg.IngressDomainSuffix,
		DiskCipher:                 diskCipher,
		APIKeyHasher:               userapikey.NewHasher(apiKeyPepper),
		DefaultBandwidthQuotaBytes: cfg.DefaultBandwidthQuotaBytes,
		Pool:                       cfg.Pool,
		ReplMonitorEnabled:         cfg.ReplMonitorEnabled,
		InfraAlertURL:              cfg.InfraAlertURL,
		AutoTopupThresholdBytes:    cfg.AutoTopupThresholdBytes,
		AutoTopupGiB:               cfg.AutoTopupGiB,
		CA:                         caObj,
		InternalAddr:               cfg.InternalAddr,
		InternalTLSCertPath:        cfg.InternalTLSCertPath,
		InternalTLSKeyPath:         cfg.InternalTLSKeyPath,
		InternalTLSCAPath:          cfg.InternalTLSCAPath,
		CORSAllowedOrigins:         cfg.CORSAllowedOrigins,
	}
	if cfg.CreateosBaseURL != "" {
		// Webhook secret is shared with the credit API by design — both
		// directions sign with the same value so the receiver verifies
		// the same way regardless of who initiated the call.
		secret, err := os.ReadFile(cfg.BillingWebhookSecretPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[control] createos auto-topup disabled — secret read failed: %v\n", err)
		} else {
			deps.CreateosClient = createos.New(cfg.CreateosBaseURL, strings.TrimSpace(string(secret)))
			fmt.Fprintf(os.Stderr, "[control] createos auto-topup enabled url=%s threshold=%dMiB gib=%.2f\n",
				cfg.CreateosBaseURL, cfg.AutoTopupThresholdBytes/(1024*1024), cfg.AutoTopupGiB)
		}
	}
	if bucket := cfg.Storage.Bucket; bucket != "" {
		st, err := storage.NewR2(storage.R2Config{
			Endpoint:        cfg.Storage.Endpoint,
			Region:          cfg.Storage.Region,
			AccessKeyID:     cfg.Storage.AccessKeyID,
			SecretAccessKey: cfg.Storage.SecretAccessKey,
			Bucket:          bucket,
			Secure:          cfg.Storage.Secure,
		})
		if err != nil {
			return fmt.Errorf("control: init R2 storage: %w", err)
		}
		deps.Storage = st
		// Same config delivered to hosts at register time so they don't
		// need to carry credentials in serve.yaml. Rotation = update
		// control config + restart hosts.
		deps.HostStorage = cfg.Storage
		fmt.Fprintf(os.Stderr, "[control] fork storage enabled, bucket=%s\n", bucket)
	}
	if len(cfg.PeerControls) > 0 {
		deps.PeerControls = cfg.PeerControls
		for r, u := range cfg.PeerControls {
			fmt.Fprintf(os.Stderr, "[control] cross-region peer: region=%s url=%s\n", r, u)
		}
	}
	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	if cfg.SchedulerURL == "" {
		return fmt.Errorf("control requires --scheduler-url (the control scheduler service)")
	}
	// control→scheduler runs plain HTTP without auth. The scheduler is
	// ClusterIP-only and lives inside the createos namespace; every caller
	// inside the mesh is trusted to submit placement requests. If you
	// ever expose scheduler externally, restore the JWT or migrate to
	// mTLS — see internal/scheduler/http.go.
	schedCfg := schedclient.Config{
		BaseURL: cfg.SchedulerURL,
	}
	schedCli := schedclient.New(schedCfg, func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	})
	// Run starts only the scheduler client's background /readyz probe; the
	// scheduler remains a separate service. Handlers use this same client for
	// scheduling RPCs and its cached health state to fail fast during outages.
	go schedCli.Run(runCtx)
	deps.SchedulerClient = schedCli

	srv := New(deps)
	return srv.Run(runCtx)
}

// loadPromSDTokenOrDie reads the static Prometheus SD bearer token
// from disk and aborts startup on read errors. Empty path is fine —
// returns "" so the SD endpoint stays disabled.
func loadPromSDTokenOrDie(path string) string {
	tok, err := handlers.LoadPromSDToken(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[control] failed to load prom-sd token: %v\n", err)
		os.Exit(1)
	}
	return tok
}

// derefStr safely reads an optional *string column into a plain string.
// nil → "". Used by resolverFromRepo to unwrap the optional APIKey.Name.
func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// resolverFromRepo builds a userapikey.Cache wired to the models.Repo's
// hash-keyed lookup / upsert / delete primitives.
//
// pepper is the HMAC-SHA256 secret that turns inbound plaintext tokens
// into the (auth_type, key_hash) pair the DB indexes on. Empty pepper
// is permitted — Resolve will fail-closed (returns 401 on every
// request). Operators are expected to provide it via
// --api-key-hmac-key / api_key_hmac_key / API_KEY_HMAC_KEY.
//
// externalURL non-empty enables the upstream-validate fallback: on
// local miss / expired external-cache row, the resolver GETs
// <externalURL>/v1/users/me forwarding whichever header the user sent.
// On 200 the row is upserted with is_internal=false, expires_at=now+
// externalTTL; on 401/403/404 any local cache row is DELETEd inline.
func resolverFromRepo(
	repo *models.Repo, pepper []byte,
	ttlSeconds int, externalURL string, externalTTL time.Duration,
) *userapikey.Cache {
	lookup := userapikey.LookupByHashFunc(func(ctx context.Context, authType string, keyHash []byte) (string, string, bool, bool, *time.Time, bool, error) {
		rec, err := repo.LookupAPIKeyByHash(ctx, authType, keyHash)
		if err != nil {
			return "", "", false, false, nil, false, err
		}
		if rec == nil {
			return "", "", false, false, nil, false, nil
		}
		return rec.UserID, derefStr(rec.Name), rec.Revoked, rec.IsInternal, rec.ExpiresAt, true, nil
	})
	upsert := userapikey.UpsertWithHashFunc(func(ctx context.Context, _, userID, name string, isInternal bool, expiresAt *time.Time, authType string, keyHash []byte) error {
		var namePtr *string
		if name != "" {
			namePtr = &name
		}
		return repo.UpsertAPIKey(ctx, models.APIKey{
			UserID:     userID,
			Name:       namePtr,
			CreatedAt:  time.Now().UTC(),
			Revoked:    false,
			IsInternal: isInternal,
			ExpiresAt:  expiresAt,
			AuthType:   authType,
			KeyHash:    keyHash,
		})
	})
	del := userapikey.DeleteByHashFunc(func(ctx context.Context, authType string, keyHash []byte) error {
		return repo.DeleteAPIKeyByHash(ctx, authType, keyHash)
	})
	reg := userapikey.NewCache(userapikey.NewKeyStore(lookup, upsert, del), userapikey.NewHasher(pepper), time.Duration(ttlSeconds)*time.Second)
	if externalURL != "" {
		reg = reg.WithExternal(userapikey.NewHTTPExternalValidator(externalURL), externalTTL)
	}
	return reg
}
