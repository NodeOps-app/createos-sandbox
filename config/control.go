package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
)

// ControlConfig holds the resolved configuration for the `control` subcommand.
type ControlConfig struct {
	Addr        string
	PostgresDSN string
	// PanicMode is an emergency public-API kill switch. When enabled,
	// user-facing routes return 503 while health, host administration, and internal
	// service routes remain available for diagnosis and recovery.
	PanicMode bool
	// DeviceRegistrationEnabled controls only POST /v1/devices. Existing
	// devices, attachments, and VPN sessions remain available when false.
	DeviceRegistrationEnabled bool
	PlacementPolicies         map[string]PlacementPolicy
	EnabledCrossRegionUsers   []string // empty enables capacity fallback for all users

	AdminToken          string // protects host cordon/uncordon/drain and control pprof
	BootstrapToken      string // shared secret on /v1/internal/hosts/register for compute hosts; required at startup
	RelayBootstrapToken string // separate shared secret for role=relay registrations; empty disables relay onboarding
	AuthCacheTTL        int    // 0 = default

	// PromSDTokenFile is the path to a file holding the static bearer
	// token Prometheus uses to call /v1/internal/sd/hosts. Empty path
	// disables the SD endpoint (405). Same file format as the host
	// metrics token — operators can use one fleet-wide token for
	// both surfaces.
	PromSDTokenFile string

	// ExternalAuthURL is the upstream auth service. When set, every
	// user-supplied token that misses (or has an expired external-cache
	// row) in api_keys gets validated by GET <ExternalAuthURL>/v1/users/me,
	// forwarding the same custom header the user sent: X-Api-Key,
	// X-Access-Token, or X-Auth-Token. On 200 the returned user is
	// cached locally for ExternalAuthTTL. On 401/403/404 the local row
	// is deleted. Internal keys (is_internal=true) skip this entirely.
	// Empty = DB-only mode.
	ExternalAuthURL string
	// ExternalAuthTTL bounds how long an external validation result is
	// trusted before re-validation. Default 5 minutes when ExternalAuthURL
	// is set. Honors the upstream's expiredAt as an upper bound.
	ExternalAuthTTL time.Duration

	// VerifyBuilderPubkey is the path to the builder's public key. Used
	// to verify builder→control template-PATCH JWTs (sub=tpl_<id>).
	VerifyBuilderPubkey string

	// VerifyBillingPubkey is the path to the billing service's public
	// key. Used to verify GET /v1/internal/billing/sandboxes/:id JWTs
	// (the reconcile endpoint). Optional — empty means the route 401s,
	// the correct fail-closed default when no billing integration exists.
	VerifyBillingPubkey string

	// ClickHouseURL points at the ClickHouse HTTP interface. Required
	// for build log streaming; empty disables the templates log endpoints.
	ClickHouseURL      string
	ClickHouseUsername string
	ClickHousePassword string
	ClickHouseDatabase string

	// DeadHostEvictAfter: once a host has been dead (missing heartbeats)
	// for this long, mark every sandbox it owned as destroyed in the DB.
	// 0 = disabled (keep zombie rows indefinitely — default, so we don't
	// silently nuke users' VMs on transient control-plane outages).
	DeadHostEvictAfter time.Duration

	// SchedulerURL is the base URL of the external scheduler service.
	// Required; control delegates all placement to it.
	SchedulerURL string

	// TraceDB enables per-query log lines from the repository wrapper.
	// Off by default — one log line per DB call is noisy in production
	// but invaluable when debugging cross-cloud or schema regressions.
	TraceDB bool

	// RelayCrossRegionFallback lets device-session-create pick a relay
	// from ANY region when the caller's region has no active relay.
	// ON by default because not every active region runs its own relay
	// (e.g. region A serves user traffic but the relay lives in region B;
	// region A devices ride region B's relay). Flip off to fail-closed with 503
	// when in-region has none — appropriate once every active region
	// has its own local relay stable.
	RelayCrossRegionFallback bool

	// Storage is the cluster's S3-compatible object-storage wiring.
	// Control needs it for fork's server-side CopyObject and for
	// template lookups. Bucket required for prod.
	Storage StorageConfig

	// Per-user creation caps. Each is the cluster-wide ceiling for
	// external (api_keys.is_internal=false) users; internal keys
	// always bypass. 0 disables that specific cap.
	//   MaxSandboxConcurrent — any non-terminal status
	//   MaxSandboxPerDay     — DB rows in rolling 24h (incl. destroyed)
	//   MaxNetworkConcurrent — live networks (not soft-deleted)
	//   MaxDiskConcurrent    — live disks (not soft-deleted)
	//   MaxDiskPerDay        — DB rows in rolling 24h (incl. soft-deleted)
	MaxSandboxConcurrent  int
	MaxSandboxPerDay      int
	MaxNetworkConcurrent  int
	MaxNetworkPerDay      int
	MaxDiskConcurrent     int
	MaxDiskPerDay         int
	MaxTemplateConcurrent int
	MaxTemplatePerDay     int

	// IngressDomainSuffix is the public DNS suffix the cluster's
	// `control ingress` answers on. When set, the create response
	// includes a ready-to-share URL template the client can show the
	// user. Empty = control plane returns no URL hint (clients have
	// to know their cluster's domain out-of-band).
	IngressDomainSuffix string

	// Region is the operator-assigned region tag stamped onto every
	// sandbox row created by this control plane. The ingress subcommand
	// refuses to route a sandbox whose stored region doesn't match its
	// own — this is what enforces region pinning end-to-end. Required;
	// startup fails fast with a clear error when empty.
	Region string

	// GeoIPDBPath points at an mmdb country database (db-ip.com Lite by
	// default; MaxMind GeoLite2 also works — same format). Populates the
	// "country" label on createos_control_create_seconds. Empty = country
	// label always reads "unknown" (metric still works, just uncategorised).
	GeoIPDBPath string

	// DiskCredentialKeyPath is the path to control's 32-byte AES key used
	// only to encrypt/decrypt disks.credentials at rest in PostgreSQL. It
	// is not the control-to-host transport key: after database decryption,
	// cryptobox re-encrypts credentials to the selected host's public key.
	// Machine hosts never receive this AES key. The file may hold raw bytes,
	// hex, or base64 (whitespace-trimmed). Required when the disks API is
	// exposed; when empty, /v1/disks returns 503 and sandbox-create rejects
	// any `disks:` field.
	//
	// k8s deployments: mount the secret at a path under /run/secrets/
	// (tmpfs-backed) and point this flag at it. Avoids an env-vs-file
	// mismatch surface.
	DiskCredentialKeyPath string

	// APIKeyHMACKeyPath is the path to a 32-byte HMAC key used to hash
	// user API keys before storing in api_keys.key_hash. Same loader as
	// DiskCredentialKeyPath (raw / hex / base64). Empty path = legacy
	// plaintext lookups only (phase-A backwards compat).
	APIKeyHMACKeyPath string

	// DefaultBandwidthQuotaBytes is the per-sandbox byte cap applied when
	// a create request omits `bandwidth_quota_bytes` or sends 0. Source
	// of truth for the cluster's bandwidth-default policy — control
	// resolves this BEFORE forwarding to the host, so hosts never need
	// to know the policy. Negative values from clients are rejected at
	// the API (400). Default: 50 GiB.
	DefaultBandwidthQuotaBytes int64

	// PeerControls maps region name → peer control plane base URL for
	// cross-region create/resume/fork forwarding. The forwarder relays
	// the caller's API key + body + headers verbatim; the peer
	// authenticates the request via its normal user-auth path,
	// identical to the user dialing directly.
	//
	// Use a DIRECT ORIGIN URL (bypass any CDN in front of users' web
	// traffic). The peer's TLS cert just needs to be valid against
	// system root CAs (any public CA — Let's Encrypt, CF Origin CA
	// served direct, etc.). The peer's :8443 internal mTLS listener is
	// NOT a valid peer URL — it only serves /v1/internal/* routes.
	//
	// Empty = single-region (cross-region requests return 503 "no peer
	// configured"). Each region lists every OTHER region (not itself).
	//   peer_controls:
	//     us: "https://us-control-origin.example.com"
	//     ap: "https://ap-control-origin.example.com"
	PeerControls map[string]string

	// InternalAddr enables a SECOND listener bound to a separate port,
	// dedicated to service-to-service mTLS (host/ingress/gateway/proxy).
	// Empty disables. When set, control listens on Addr (public, plain or
	// terminated-at-LB HTTP) AND on InternalAddr (TLS with RequireAndVerifyClientCert).
	// Public listener carries user-facing routes plus narrow host administration; internal listener
	// carries /v1/internal/* + /healthz only. This mirrors
	// the Kubernetes apiserver split (kubelet port vs user API port) and
	// lets the public path stay terminated at Cloudflare/nginx without
	// breaking internal mTLS.
	InternalAddr        string
	InternalTLSCertPath string
	InternalTLSKeyPath  string
	InternalTLSCAPath   string

	// CAKeyPath / CACertPath point at the in-process certificate
	// authority's private key + cert. When both are set, control
	// loads (or auto-creates) the CA on startup and enables the host CSR
	// and CRL endpoints. Actor issue/revocation is performed offline by
	// the admin CA CLI. Empty paths disable mTLS bootstrap entirely.
	CAKeyPath  string
	CACertPath string

	// CreateosBaseURL points at the external credit/plan API. Empty
	// disables the auto-top-up trigger.
	CreateosBaseURL string
	// ReplMonitorEnabled controls replication health notifications. It
	// defaults to true; dev can disable alerts without disabling the
	// createos credit/auto-top-up client.
	ReplMonitorEnabled bool
	// InfraAlertURL receives infrastructure-monitor notifications. Empty
	// disables the monitor even when ReplMonitorEnabled is true.
	InfraAlertURL string
	// BillingWebhookSecretPath is the file containing the shared HMAC
	// secret used to sign both outbound webhook deliveries AND outbound
	// createos POSTs. Same value lives in the billing receiver's vault.
	BillingWebhookSecretPath string
	// AutoTopupThresholdBytes — remaining quota under this triggers a
	// recharge request. Default 500 MiB; 0 disables.
	AutoTopupThresholdBytes int64
	// AutoTopupGiB is the GiB of bandwidth purchased per trigger.
	// Default 1.0; 0 disables.
	AutoTopupGiB float64

	// CORSAllowedOrigins is the allowlist of browser origins permitted by
	// CORS preflight responses. Empty = no allowlist; the middleware then
	// permits all origins (legacy behaviour) and logs a one-time warning
	// at startup. Configure to a specific dashboard origin to lock down.
	CORSAllowedOrigins []string

	// Pool controls the predictive pre-warm sandbox pool. Pool VMs are
	// created under `created_by=OwnerID` and atomically re-assigned to
	// a user_id when a user create request exactly matches Spec. When
	// Enabled=false the whole surface is inert; when true Validate()
	// enforces every field below.
	Pool PoolConfig
}

// PoolConfig configures the predictive pre-warm sandbox pool.
type PoolConfig struct {
	Enabled bool
	// OwnerID is the sentinel user_id stamped on pool-owned rows
	// (sandboxes.created_by). Swapped to the real user_id on match.
	OwnerID string
	// PerHostGrowRate caps how many pool VMs a single host may accept
	// per refill tick.
	PerHostGrowRate int
	// MaxAge is the upper bound on how long an unclaimed pool VM lives
	// before it is destroyed.
	MaxAge time.Duration
	// Spec is what a pool VM looks like. A user create request must
	// match this exactly to be eligible for pool-swap.
	Spec PoolSpec
	// Buckets is the per-hour UTC target + refill cadence. Keys must be
	// the 24 two-digit hour strings "00" through "23". YAML-only surface
	// (nested map — no CLI/env analog).
	Buckets map[string]PoolBucket
	// WeeklyWindows override the hourly target during recurring local-time
	// windows. The matching hourly bucket still supplies the refill interval.
	WeeklyWindows []PoolWeeklyWindow
}

// PoolSpec is the exact shape a user create request must match to be
// swapped to a pool-owned VM.
type PoolSpec struct {
	Shape   string
	DiskMib int64
	Rootfs  string
}

// PoolBucket is the per-UTC-6h target size and refill cadence.
type PoolBucket struct {
	Target         int
	RefillInterval time.Duration
}

// PoolWeeklyWindow is a recurring target override. Start is inclusive and
// End is exclusive; windows cannot cross midnight.
type PoolWeeklyWindow struct {
	Weekday  time.Weekday
	Timezone *time.Location
	Start    time.Duration
	End      time.Duration
	Target   int
}

// ControlFile is the YAML schema for the `control` subcommand.
type ControlFile struct {
	EnabledCrossRegionUsers   []string                   `yaml:"enabled_cross_region_users"`
	Addr                      *string                    `yaml:"addr"`
	PostgresDSN               *string                    `yaml:"postgres_dsn"`
	PanicMode                 *bool                      `yaml:"panic_mode"`
	DeviceRegistrationEnabled *bool                      `yaml:"device_registration_enabled"`
	PlacementPolicies         map[string]PlacementPolicy `yaml:"placement_policies"`
	TraceDB                   *bool                      `yaml:"trace_db"`
	RelayCrossRegionFallback  *bool                      `yaml:"relay_cross_region_fallback"`
	Auth                      *AuthFile                  `yaml:"auth"`
	DeadHostEvictAfter        *string                    `yaml:"dead_host_evict_after"` // Go duration string, e.g. "5m"
	SchedulerURL              *string                    `yaml:"scheduler_url"`         // base URL of external scheduler
	Region                    *string                    `yaml:"region"`
	Storage                   *StorageFile               `yaml:"storage"`
	ExternalAuthURL           *string                    `yaml:"external_auth_url"`
	ExternalAuthTTL           *string                    `yaml:"external_auth_ttl"` // Go duration string
	MaxSandboxConcurrent      *int                       `yaml:"max_sandbox_concurrent"`
	MaxSandboxPerDay          *int                       `yaml:"max_sandbox_per_day"`
	MaxNetworkConcurrent      *int                       `yaml:"max_network_concurrent"`
	MaxNetworkPerDay          *int                       `yaml:"max_network_per_day"`
	MaxDiskConcurrent         *int                       `yaml:"max_disk_concurrent"`
	MaxDiskPerDay             *int                       `yaml:"max_disk_per_day"`
	MaxTemplateConcurrent     *int                       `yaml:"max_template_concurrent"`
	MaxTemplatePerDay         *int                       `yaml:"max_template_per_day"`

	IngressDomainSuffix *string `yaml:"ingress_domain_suffix"`
	GeoIPDBPath         *string `yaml:"geoip_db_path"`
	ClickHouseURL       *string `yaml:"clickhouse_url"`
	ClickHouseUsername  *string `yaml:"clickhouse_username"`
	ClickHousePassword  *string `yaml:"clickhouse_password"`
	ClickHouseDatabase  *string `yaml:"clickhouse_database"`
	PromSDTokenFile     *string `yaml:"prom_sd_token_file"`

	DiskCredentialKey *string `yaml:"disk_credential_key"`
	APIKeyHMACKey     *string `yaml:"api_key_hmac_key"`

	CAKey  *string `yaml:"ca_key"`
	CACert *string `yaml:"ca_cert"`

	InternalAddr    *string `yaml:"internal_addr"`
	InternalTLSCert *string `yaml:"internal_tls_cert"`
	InternalTLSKey  *string `yaml:"internal_tls_key"`
	InternalTLSCA   *string `yaml:"internal_tls_ca"`

	DefaultBandwidthQuotaBytes *int64            `yaml:"default_bandwidth_quota_bytes"`
	PeerControls               map[string]string `yaml:"peer_controls"`

	CreateosBaseURL          *string  `yaml:"createos_base_url"`
	ReplMonitorEnabled       *bool    `yaml:"repl_monitor_enabled"`
	InfraAlertURL            *string  `yaml:"infra_alert_url"`
	BillingWebhookSecretPath *string  `yaml:"billing_webhook_secret"`
	AutoTopupThresholdBytes  *int64   `yaml:"auto_topup_threshold_bytes"`
	AutoTopupGiB             *float64 `yaml:"auto_topup_gib"`

	CORSAllowedOrigins []string `yaml:"cors_allowed_origins"`

	Pool *PoolFile `yaml:"pool"`
}

// PlacementPolicy is an operator-owned per-user scheduling override.
type PlacementPolicy struct {
	Region           string   `yaml:"region"`
	Shapes           []string `yaml:"shapes"`
	PreferredHostIDs []string `yaml:"preferred_host_ids"`
}

// PoolFile is the YAML schema for the pool block.
type PoolFile struct {
	Enabled         *bool         `yaml:"enabled"`
	OwnerID         *string       `yaml:"owner_id"`
	PerHostGrowRate *int          `yaml:"per_host_grow_rate"`
	MaxAge          *string       `yaml:"max_age"` // Go duration string, e.g. "6h"
	Spec            *PoolSpecFile `yaml:"spec"`
	// Buckets is YAML-only (nested map — no CLI/env analog). Keys must be
	// the 24 two-digit hour strings "00" through "23" (UTC).
	Buckets map[string]PoolBucketFile `yaml:"buckets"`
	// WeeklyWindows optionally override targets for recurring weekday windows.
	WeeklyWindows []PoolWeeklyWindowFile `yaml:"weekly_windows"`
}

// PoolSpecFile is the YAML schema for the pool.spec block.
type PoolSpecFile struct {
	Shape   *string `yaml:"shape"`
	DiskMib *int64  `yaml:"disk_mib"`
	Rootfs  *string `yaml:"rootfs"`
}

// PoolBucketFile is the YAML schema for a single bucket entry.
type PoolBucketFile struct {
	Target         int    `yaml:"target"`
	RefillInterval string `yaml:"refill_interval"` // Go duration string, e.g. "5s"
}

// PoolWeeklyWindowFile is the YAML form of a recurring local-time override.
type PoolWeeklyWindowFile struct {
	Weekday  string `yaml:"weekday"`  // e.g. Friday
	Timezone string `yaml:"timezone"` // IANA name, e.g. Asia/Kolkata
	Start    string `yaml:"start"`    // HH:MM, inclusive
	End      string `yaml:"end"`      // HH:MM, exclusive; 24:00 allowed
	Target   int    `yaml:"target"`
}

// AuthFile-extension fields are merged into the existing AuthFile struct
// (defined in serve.go for now). The control subcommand reads them from
// the same `auth:` YAML block.

// ControlFlags returns the urfave/cli flags for the `control` subcommand.
func ControlFlags() []cli.Flag {
	flags := []cli.Flag{
		&cli.StringSliceFlag{Name: "enabled-cross-region-users", EnvVars: []string{"ENABLED_CROSS_REGION_USERS"}, Usage: "users enabled for cross-region capacity fallback; empty enables all users"},
		&cli.StringFlag{Name: "config", Usage: "path to YAML config file"},
		&cli.StringFlag{Name: "addr", Value: ":8080", EnvVars: []string{"CONTROL_ADDR"}},
		&cli.StringFlag{Name: "postgres-dsn", Value: "postgres://createos:createos@localhost:5432/createos?sslmode=disable", EnvVars: []string{"POSTGRES_DSN"}},
		&cli.BoolFlag{Name: "panic-mode", Value: false, Usage: "emergency kill switch: return 503 from user-facing API routes while keeping health, host administration, and internal routes available", EnvVars: []string{"PANIC_MODE"}},
		&cli.BoolFlag{Name: "device-registration-enabled", Value: true, Usage: "allow new device registrations through POST /v1/devices", EnvVars: []string{"DEVICE_REGISTRATION_ENABLED"}},
		&cli.StringFlag{Name: "admin-token", Value: "", Usage: "shared secret protecting host cordon, uncordon, drain, and control pprof; empty disables them", EnvVars: []string{"ADMIN_TOKEN"}},
		&cli.StringFlag{Name: "prom-sd-token-file", Value: "", Usage: "path to a file holding the static bearer token Prometheus uses for /v1/internal/sd/hosts; empty disables the endpoint", EnvVars: []string{"PROM_SD_TOKEN_FILE"}},
		&cli.StringFlag{Name: "bootstrap-token", Value: "", Usage: "compute bootstrap secret (prefer --bootstrap-token-file; flag leaks via /proc/<pid>/cmdline)", EnvVars: []string{"BOOTSTRAP_TOKEN"}},
		&cli.StringFlag{Name: "bootstrap-token-file", Value: "", Usage: "path to file (mode 0600) holding the compute bootstrap token", EnvVars: []string{"BOOTSTRAP_TOKEN_FILE"}},
		&cli.StringFlag{Name: "relay-bootstrap-token", Value: "", Usage: "relay bootstrap secret (prefer --relay-bootstrap-token-file)", EnvVars: []string{"RELAY_BOOTSTRAP_TOKEN"}},
		&cli.StringFlag{Name: "relay-bootstrap-token-file", Value: "", Usage: "path to file (mode 0600) holding the relay bootstrap token", EnvVars: []string{"RELAY_BOOTSTRAP_TOKEN_FILE"}},
		&cli.StringFlag{Name: "verify-builder-pubkey", Value: "", Usage: "path to builder's ed25519 public-key file (verifies template-PATCH JWTs)", EnvVars: []string{"VERIFY_BUILDER_PUBKEY"}},
		&cli.StringFlag{Name: "verify-billing-pubkey", Value: "", Usage: "path to billing service's ed25519 public-key file (verifies reconcile-API JWTs); empty = reconcile endpoint always 401s", EnvVars: []string{"VERIFY_BILLING_PUBKEY"}},
		&cli.StringFlag{Name: "clickhouse-url", Value: "", Usage: "ClickHouse HTTP base URL for build logs (empty = disabled)", EnvVars: []string{"CLICKHOUSE_URL"}},
		&cli.StringFlag{Name: "clickhouse-username", Value: "createos", EnvVars: []string{"CLICKHOUSE_USERNAME"}},
		&cli.StringFlag{Name: "clickhouse-password", Value: "", EnvVars: []string{"CLICKHOUSE_PASSWORD"}},
		&cli.StringFlag{Name: "clickhouse-database", Value: "createos", EnvVars: []string{"CLICKHOUSE_DATABASE"}},
		&cli.IntFlag{Name: "auth-cache-ttl", Value: 0, Usage: "auth registry cache TTL in seconds (0 = default 60)", EnvVars: []string{"AUTH_CACHE_TTL"}},
		&cli.DurationFlag{Name: "dead-host-evict-after", Value: 0, Usage: "mark sandboxes destroyed after their host has been dead this long; 0 = disabled", EnvVars: []string{"DEAD_HOST_EVICT_AFTER"}},
		&cli.StringFlag{Name: "scheduler-url", Value: "", Usage: "base URL of the control scheduler service (required)", EnvVars: []string{"SCHEDULER_URL"}},
		&cli.StringFlag{Name: "region", Value: "", Usage: "region tag stamped onto every sandbox (required); informational + used for cross-region forwarding inside control. Ingress is region-agnostic.", EnvVars: []string{"REGION"}},
		&cli.BoolFlag{Name: "trace-db", Value: false, Usage: "log every DB call's duration — ad-hoc latency inspection", EnvVars: []string{"TRACE_DB"}},
		&cli.BoolFlag{Name: "relay-cross-region-fallback", Value: true, Usage: "when this control's region has no active relay, fall back to picking a relay from any region; on by default because not every region runs its own relay (e.g. US devices ride the EU relay). Flip off to fail-closed and 503 instead.", EnvVars: []string{"RELAY_CROSS_REGION_FALLBACK"}},
		&cli.StringFlag{Name: "external-auth-url", Value: "", Usage: "upstream auth service base URL (empty = DB-only key validation)", EnvVars: []string{"EXTERNAL_AUTH_URL"}},
		&cli.DurationFlag{Name: "external-auth-ttl", Value: 0, Usage: "how long an external-validated key is cached locally (0 = 5m default)", EnvVars: []string{"EXTERNAL_AUTH_TTL"}},
		&cli.IntFlag{Name: "max-sandbox-concurrent", Value: 5, Usage: "max concurrent sandboxes per external user (any non-terminal status; 0 = unlimited; internal keys always exempt)", EnvVars: []string{"MAX_SANDBOX_CONCURRENT"}},
		&cli.IntFlag{Name: "max-sandbox-per-day", Value: 100, Usage: "max sandbox creations per external user per rolling 24h (0 = unlimited; counts destroyed rows too)", EnvVars: []string{"MAX_SANDBOX_PER_DAY"}},
		&cli.IntFlag{Name: "max-network-concurrent", Value: 5, Usage: "max live networks per external user (0 = unlimited)", EnvVars: []string{"MAX_NETWORK_CONCURRENT"}},
		&cli.IntFlag{Name: "max-network-per-day", Value: 100, Usage: "max network creations per external user per rolling 24h (0 = unlimited; counts soft-deleted rows too)", EnvVars: []string{"MAX_NETWORK_PER_DAY"}},
		&cli.IntFlag{Name: "max-disk-concurrent", Value: 5, Usage: "max live disks per external user (0 = unlimited)", EnvVars: []string{"MAX_DISK_CONCURRENT"}},
		&cli.IntFlag{Name: "max-disk-per-day", Value: 100, Usage: "max disk creations per external user per rolling 24h (0 = unlimited)", EnvVars: []string{"MAX_DISK_PER_DAY"}},
		&cli.IntFlag{Name: "max-template-concurrent", Value: 5, Usage: "max live templates per external user (0 = unlimited)", EnvVars: []string{"MAX_TEMPLATE_CONCURRENT"}},
		&cli.IntFlag{Name: "max-template-per-day", Value: 20, Usage: "max template submissions per external user per rolling 24h (0 = unlimited)", EnvVars: []string{"MAX_TEMPLATE_PER_DAY"}},
		&cli.StringFlag{Name: "ingress-domain-suffix", Value: "", Usage: "public DNS suffix the cluster's ingress answers on (e.g. 'eu.example.com'); used to advertise URL templates in create responses", EnvVars: []string{"INGRESS_DOMAIN_SUFFIX"}},
		&cli.StringFlag{Name: "geoip-db-path", Value: "", Usage: "path to an mmdb country database (db-ip.com Lite or MaxMind GeoLite2). Populates the country label on createos_control_create_seconds; empty = 'unknown'", EnvVars: []string{"GEOIP_DB_PATH"}},
		&cli.StringFlag{Name: "disk-credential-key", Value: "", Usage: "path to a file containing the 32-byte AES key (raw / hex / base64) used to encrypt disks.credentials at rest. Required when the disks API is exposed; empty = disks endpoints 503", EnvVars: []string{"DISK_CREDENTIAL_KEY"}},
		&cli.StringFlag{Name: "api-key-hmac-key", Value: "", Usage: "path to a file containing the 32-byte HMAC key used to hash api_keys.key_hash. Same loader as --disk-credential-key (raw / hex / base64). Empty disables user API-key resolution", EnvVars: []string{"API_KEY_HMAC_KEY"}},
		&cli.StringFlag{Name: "infra-alert-url", Value: "", Usage: "webhook URL for infrastructure-monitor alerts; empty disables alert delivery", EnvVars: []string{"INFRA_ALERT_URL"}},
		&cli.StringFlag{Name: "ca-key-path", Value: "", Usage: "path to the in-process CA private key (PEM). Empty disables mTLS bootstrap endpoints", EnvVars: []string{"CA_KEY_PATH"}},
		&cli.StringFlag{Name: "ca-cert-path", Value: "", Usage: "path to the in-process CA cert (PEM). Empty disables mTLS bootstrap endpoints", EnvVars: []string{"CA_CERT_PATH"}},
		&cli.Int64Flag{Name: "default-bandwidth-quota-bytes", Value: 50 * 1024 * 1024 * 1024, Usage: "default per-sandbox bandwidth byte cap when the create request omits it (or sends 0). Negative create values are rejected (400)", EnvVars: []string{"DEFAULT_BANDWIDTH_QUOTA_BYTES"}},
		&cli.StringFlag{Name: "cors-allowed-origins", Value: "", Usage: "comma-separated allowlist of CORS origins (e.g. https://dash.example.com,https://api.example.com); empty = permit all + log warning", EnvVars: []string{"CORS_ALLOWED_ORIGINS"}},
		// Predictive pre-warm sandbox pool. Scalar knobs only; the
		// per-UTC-6h buckets are YAML-only (see PoolFile.Buckets).
		&cli.BoolFlag{Name: "pool-enabled", Value: false, Usage: "enable the predictive pre-warm sandbox pool", EnvVars: []string{"POOL_ENABLED"}},
		&cli.StringFlag{Name: "pool-owner-id", Value: "pool", Usage: "sentinel user_id stamped on pool-owned sandbox rows (created_by); swapped to real user_id on match", EnvVars: []string{"POOL_OWNER_ID"}},
		&cli.IntFlag{Name: "pool-per-host-grow-rate", Value: 5, Usage: "max pool VMs a single host may accept per refill tick", EnvVars: []string{"POOL_PER_HOST_GROW_RATE"}},
		&cli.DurationFlag{Name: "pool-max-age", Value: 6 * time.Hour, Usage: "max age of an unclaimed pool VM before it is destroyed", EnvVars: []string{"POOL_MAX_AGE"}},
		&cli.StringFlag{Name: "pool-spec-shape", Value: "s-1vcpu-1gb", Usage: "shape a user create request must match to be eligible for pool-swap", EnvVars: []string{"POOL_SPEC_SHAPE"}},
		&cli.Int64Flag{Name: "pool-spec-disk-mib", Value: 10240, Usage: "disk_mib a user create request must match to be eligible for pool-swap", EnvVars: []string{"POOL_SPEC_DISK_MIB"}},
		&cli.StringFlag{Name: "pool-spec-rootfs", Value: "", Usage: "rootfs a user create request must match to be eligible for pool-swap (empty = host default)", EnvVars: []string{"POOL_SPEC_ROOTFS"}},
	}
	// PauseFlags are deliberately NOT added — the pause orchestrator runs
	// on the host, not control. Control only needs storage for fork's R2
	// CopyObject.
	return append(flags, StorageFlags()...)
}

// ControlFromContext resolves the final ControlConfig.
// Precedence: flag/env > YAML > default.
func ControlFromContext(c *cli.Context) (ControlConfig, error) {
	var f ControlFile
	if err := loadYAML(c.String("config"), &f); err != nil {
		return ControlConfig{}, err
	}
	cfg := ControlConfig{
		Addr:               pickStr(c, "addr", f.Addr),
		PostgresDSN:        pickStr(c, "postgres-dsn", f.PostgresDSN),
		ReplMonitorEnabled: true,
	}
	cfg.PanicMode = c.Bool("panic-mode")
	if f.PanicMode != nil && !c.IsSet("panic-mode") {
		cfg.PanicMode = *f.PanicMode
	}
	cfg.DeviceRegistrationEnabled = c.Bool("device-registration-enabled")
	if f.DeviceRegistrationEnabled != nil && !c.IsSet("device-registration-enabled") {
		cfg.DeviceRegistrationEnabled = *f.DeviceRegistrationEnabled
	}
	cfg.PlacementPolicies = f.PlacementPolicies
	cfg.EnabledCrossRegionUsers = f.EnabledCrossRegionUsers
	if c.IsSet("enabled-cross-region-users") {
		cfg.EnabledCrossRegionUsers = c.StringSlice("enabled-cross-region-users")
	}
	cfg.AdminToken = c.String("admin-token")
	if f.Auth != nil && f.Auth.AdminToken != nil && !c.IsSet("admin-token") {
		cfg.AdminToken = *f.Auth.AdminToken
	}
	cfg.PromSDTokenFile = pickStr(c, "prom-sd-token-file", f.PromSDTokenFile)
	cfg.RelayBootstrapToken = c.String("relay-bootstrap-token")
	if f.Auth != nil && f.Auth.RelayBootstrapToken != nil && !c.IsSet("relay-bootstrap-token") {
		cfg.RelayBootstrapToken = *f.Auth.RelayBootstrapToken
	}
	relayTokenFile := c.String("relay-bootstrap-token-file")
	if f.Auth != nil && f.Auth.RelayBootstrapTokenFile != nil && !c.IsSet("relay-bootstrap-token-file") {
		relayTokenFile = *f.Auth.RelayBootstrapTokenFile
	}
	if relayTokenFile != "" {
		b, err := os.ReadFile(relayTokenFile)
		if err != nil {
			return ControlConfig{}, fmt.Errorf("read relay-bootstrap-token-file %s: %w", relayTokenFile, err)
		}
		cfg.RelayBootstrapToken = strings.TrimSpace(string(b))
	}
	cfg.BootstrapToken = c.String("bootstrap-token")
	if f.Auth != nil && f.Auth.BootstrapToken != nil && !c.IsSet("bootstrap-token") {
		cfg.BootstrapToken = *f.Auth.BootstrapToken
	}
	tokenFile := c.String("bootstrap-token-file")
	if f.Auth != nil && f.Auth.BootstrapTokenFile != nil && !c.IsSet("bootstrap-token-file") {
		tokenFile = *f.Auth.BootstrapTokenFile
	}
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return ControlConfig{}, fmt.Errorf("read bootstrap-token-file %s: %w", tokenFile, err)
		}
		cfg.BootstrapToken = strings.TrimSpace(string(b))
	}
	cfg.VerifyBuilderPubkey = c.String("verify-builder-pubkey")
	cfg.VerifyBillingPubkey = c.String("verify-billing-pubkey")
	cfg.ClickHouseURL = c.String("clickhouse-url")
	if f.ClickHouseURL != nil && !c.IsSet("clickhouse-url") {
		cfg.ClickHouseURL = *f.ClickHouseURL
	}
	cfg.ClickHouseUsername = c.String("clickhouse-username")
	if f.ClickHouseUsername != nil && !c.IsSet("clickhouse-username") {
		cfg.ClickHouseUsername = *f.ClickHouseUsername
	}
	cfg.ClickHousePassword = c.String("clickhouse-password")
	if f.ClickHousePassword != nil && !c.IsSet("clickhouse-password") {
		cfg.ClickHousePassword = *f.ClickHousePassword
	}
	cfg.ClickHouseDatabase = c.String("clickhouse-database")
	if f.ClickHouseDatabase != nil && !c.IsSet("clickhouse-database") {
		cfg.ClickHouseDatabase = *f.ClickHouseDatabase
	}
	if f.Auth != nil && f.Auth.Verify != nil {
		if f.Auth.Verify.BuilderPubkey != nil && !c.IsSet("verify-builder-pubkey") {
			cfg.VerifyBuilderPubkey = *f.Auth.Verify.BuilderPubkey
		}
		if f.Auth.Verify.BillingPubkey != nil && !c.IsSet("verify-billing-pubkey") {
			cfg.VerifyBillingPubkey = *f.Auth.Verify.BillingPubkey
		}
	}
	cfg.AuthCacheTTL = c.Int("auth-cache-ttl")
	if f.Auth != nil && f.Auth.CacheTTLSeconds != nil && !c.IsSet("auth-cache-ttl") {
		cfg.AuthCacheTTL = *f.Auth.CacheTTLSeconds
	}
	cfg.DeadHostEvictAfter = c.Duration("dead-host-evict-after")
	if f.DeadHostEvictAfter != nil && !c.IsSet("dead-host-evict-after") {
		d, err := time.ParseDuration(*f.DeadHostEvictAfter)
		if err != nil {
			return ControlConfig{}, err
		}
		cfg.DeadHostEvictAfter = d
	}
	cfg.SchedulerURL = c.String("scheduler-url")
	if f.SchedulerURL != nil && !c.IsSet("scheduler-url") {
		cfg.SchedulerURL = *f.SchedulerURL
	}
	cfg.TraceDB = c.Bool("trace-db")
	if f.TraceDB != nil && !c.IsSet("trace-db") {
		cfg.TraceDB = *f.TraceDB
	}
	cfg.RelayCrossRegionFallback = c.Bool("relay-cross-region-fallback")
	if f.RelayCrossRegionFallback != nil && !c.IsSet("relay-cross-region-fallback") {
		cfg.RelayCrossRegionFallback = *f.RelayCrossRegionFallback
	}
	cfg.Region = c.String("region")
	if f.Region != nil && !c.IsSet("region") {
		cfg.Region = *f.Region
	}
	if strings.TrimSpace(cfg.Region) == "" {
		return ControlConfig{}, fmt.Errorf("region must be set (--region / REGION); refusing to start")
	}
	cfg.Storage = f.Storage.Resolve(c)

	cfg.ExternalAuthURL = c.String("external-auth-url")
	if f.ExternalAuthURL != nil && !c.IsSet("external-auth-url") {
		cfg.ExternalAuthURL = *f.ExternalAuthURL
	}
	cfg.ExternalAuthTTL = c.Duration("external-auth-ttl")
	if f.ExternalAuthTTL != nil && !c.IsSet("external-auth-ttl") {
		d, err := time.ParseDuration(*f.ExternalAuthTTL)
		if err != nil {
			return ControlConfig{}, fmt.Errorf("external_auth_ttl: %w", err)
		}
		cfg.ExternalAuthTTL = d
	}
	// Per-user creation caps. Flag/env wins; YAML fills in only when
	// the flag was not explicitly set on the CLI.
	cfg.MaxSandboxConcurrent = c.Int("max-sandbox-concurrent")
	if f.MaxSandboxConcurrent != nil && !c.IsSet("max-sandbox-concurrent") {
		cfg.MaxSandboxConcurrent = *f.MaxSandboxConcurrent
	}
	cfg.MaxSandboxPerDay = c.Int("max-sandbox-per-day")
	if f.MaxSandboxPerDay != nil && !c.IsSet("max-sandbox-per-day") {
		cfg.MaxSandboxPerDay = *f.MaxSandboxPerDay
	}
	cfg.MaxNetworkConcurrent = c.Int("max-network-concurrent")
	if f.MaxNetworkConcurrent != nil && !c.IsSet("max-network-concurrent") {
		cfg.MaxNetworkConcurrent = *f.MaxNetworkConcurrent
	}
	cfg.MaxNetworkPerDay = c.Int("max-network-per-day")
	if f.MaxNetworkPerDay != nil && !c.IsSet("max-network-per-day") {
		cfg.MaxNetworkPerDay = *f.MaxNetworkPerDay
	}
	cfg.MaxDiskConcurrent = c.Int("max-disk-concurrent")
	if f.MaxDiskConcurrent != nil && !c.IsSet("max-disk-concurrent") {
		cfg.MaxDiskConcurrent = *f.MaxDiskConcurrent
	}
	cfg.MaxDiskPerDay = c.Int("max-disk-per-day")
	if f.MaxDiskPerDay != nil && !c.IsSet("max-disk-per-day") {
		cfg.MaxDiskPerDay = *f.MaxDiskPerDay
	}
	cfg.MaxTemplateConcurrent = c.Int("max-template-concurrent")
	if f.MaxTemplateConcurrent != nil && !c.IsSet("max-template-concurrent") {
		cfg.MaxTemplateConcurrent = *f.MaxTemplateConcurrent
	}
	cfg.MaxTemplatePerDay = c.Int("max-template-per-day")
	if f.MaxTemplatePerDay != nil && !c.IsSet("max-template-per-day") {
		cfg.MaxTemplatePerDay = *f.MaxTemplatePerDay
	}
	cfg.IngressDomainSuffix = c.String("ingress-domain-suffix")
	if f.IngressDomainSuffix != nil && !c.IsSet("ingress-domain-suffix") {
		cfg.IngressDomainSuffix = *f.IngressDomainSuffix
	}
	cfg.GeoIPDBPath = c.String("geoip-db-path")
	if f.GeoIPDBPath != nil && !c.IsSet("geoip-db-path") {
		cfg.GeoIPDBPath = *f.GeoIPDBPath
	}
	cfg.DiskCredentialKeyPath = c.String("disk-credential-key")
	if f.DiskCredentialKey != nil && !c.IsSet("disk-credential-key") {
		cfg.DiskCredentialKeyPath = *f.DiskCredentialKey
	}
	cfg.APIKeyHMACKeyPath = c.String("api-key-hmac-key")
	if f.APIKeyHMACKey != nil && !c.IsSet("api-key-hmac-key") {
		cfg.APIKeyHMACKeyPath = *f.APIKeyHMACKey
	}
	cfg.CAKeyPath = c.String("ca-key-path")
	if f.CAKey != nil && !c.IsSet("ca-key-path") {
		cfg.CAKeyPath = *f.CAKey
	}
	cfg.CACertPath = c.String("ca-cert-path")
	if f.CACert != nil && !c.IsSet("ca-cert-path") {
		cfg.CACertPath = *f.CACert
	}

	// Internal-port listener (mTLS-only). YAML-only knobs; no CLI flags.
	if f.InternalAddr != nil {
		cfg.InternalAddr = *f.InternalAddr
	}
	if f.InternalTLSCert != nil {
		cfg.InternalTLSCertPath = *f.InternalTLSCert
	}
	if f.InternalTLSKey != nil {
		cfg.InternalTLSKeyPath = *f.InternalTLSKey
	}
	if f.InternalTLSCA != nil {
		cfg.InternalTLSCAPath = *f.InternalTLSCA
	}

	cfg.DefaultBandwidthQuotaBytes = c.Int64("default-bandwidth-quota-bytes")
	if f.DefaultBandwidthQuotaBytes != nil && !c.IsSet("default-bandwidth-quota-bytes") {
		cfg.DefaultBandwidthQuotaBytes = *f.DefaultBandwidthQuotaBytes
	}
	if f.PeerControls != nil {
		cfg.PeerControls = f.PeerControls
	}

	// Auto-top-up: YAML-only (no CLI flags — these are operator
	// settings, not per-invocation knobs).
	if f.CreateosBaseURL != nil {
		cfg.CreateosBaseURL = *f.CreateosBaseURL
	}
	if f.ReplMonitorEnabled != nil {
		cfg.ReplMonitorEnabled = *f.ReplMonitorEnabled
	}
	cfg.InfraAlertURL = c.String("infra-alert-url")
	if f.InfraAlertURL != nil && !c.IsSet("infra-alert-url") {
		cfg.InfraAlertURL = *f.InfraAlertURL
	}
	if f.BillingWebhookSecretPath != nil {
		cfg.BillingWebhookSecretPath = *f.BillingWebhookSecretPath
	}
	if f.AutoTopupThresholdBytes != nil {
		cfg.AutoTopupThresholdBytes = *f.AutoTopupThresholdBytes
	}
	if f.AutoTopupGiB != nil {
		cfg.AutoTopupGiB = *f.AutoTopupGiB
	}
	// CORS allowed origins — CLI/env takes priority (comma-separated), else YAML.
	if raw := strings.TrimSpace(c.String("cors-allowed-origins")); raw != "" {
		parts := strings.Split(raw, ",")
		for i, p := range parts {
			parts[i] = strings.TrimSpace(p)
		}
		out := parts[:0]
		for _, p := range parts {
			if p != "" {
				out = append(out, p)
			}
		}
		cfg.CORSAllowedOrigins = out
	} else if len(f.CORSAllowedOrigins) > 0 {
		cfg.CORSAllowedOrigins = f.CORSAllowedOrigins
	}

	if cfg.DefaultBandwidthQuotaBytes <= 0 {
		return ControlConfig{}, fmt.Errorf("default_bandwidth_quota_bytes must be > 0 (got %d)", cfg.DefaultBandwidthQuotaBytes)
	}

	// Pool config. Scalar fields: flag/env > YAML > default. Nested
	// buckets map is YAML-only.
	cfg.Pool.Enabled = c.Bool("pool-enabled")
	if f.Pool != nil && f.Pool.Enabled != nil && !c.IsSet("pool-enabled") {
		cfg.Pool.Enabled = *f.Pool.Enabled
	}
	cfg.Pool.OwnerID = c.String("pool-owner-id")
	if f.Pool != nil && f.Pool.OwnerID != nil && !c.IsSet("pool-owner-id") {
		cfg.Pool.OwnerID = *f.Pool.OwnerID
	}
	cfg.Pool.PerHostGrowRate = c.Int("pool-per-host-grow-rate")
	if f.Pool != nil && f.Pool.PerHostGrowRate != nil && !c.IsSet("pool-per-host-grow-rate") {
		cfg.Pool.PerHostGrowRate = *f.Pool.PerHostGrowRate
	}
	cfg.Pool.MaxAge = c.Duration("pool-max-age")
	if f.Pool != nil && f.Pool.MaxAge != nil && !c.IsSet("pool-max-age") {
		d, err := time.ParseDuration(*f.Pool.MaxAge)
		if err != nil {
			return ControlConfig{}, fmt.Errorf("pool.max_age: %w", err)
		}
		cfg.Pool.MaxAge = d
	}
	cfg.Pool.Spec.Shape = c.String("pool-spec-shape")
	if f.Pool != nil && f.Pool.Spec != nil && f.Pool.Spec.Shape != nil && !c.IsSet("pool-spec-shape") {
		cfg.Pool.Spec.Shape = *f.Pool.Spec.Shape
	}
	cfg.Pool.Spec.DiskMib = c.Int64("pool-spec-disk-mib")
	if f.Pool != nil && f.Pool.Spec != nil && f.Pool.Spec.DiskMib != nil && !c.IsSet("pool-spec-disk-mib") {
		cfg.Pool.Spec.DiskMib = *f.Pool.Spec.DiskMib
	}
	cfg.Pool.Spec.Rootfs = c.String("pool-spec-rootfs")
	if f.Pool != nil && f.Pool.Spec != nil && f.Pool.Spec.Rootfs != nil && !c.IsSet("pool-spec-rootfs") {
		cfg.Pool.Spec.Rootfs = *f.Pool.Spec.Rootfs
	}
	if f.Pool != nil && len(f.Pool.Buckets) > 0 {
		cfg.Pool.Buckets = make(map[string]PoolBucket, len(f.Pool.Buckets))
		for k, v := range f.Pool.Buckets {
			var refill time.Duration
			if v.RefillInterval != "" {
				d, err := time.ParseDuration(v.RefillInterval)
				if err != nil {
					return ControlConfig{}, fmt.Errorf("pool.buckets[%q].refill_interval: %w", k, err)
				}
				refill = d
			}
			cfg.Pool.Buckets[k] = PoolBucket{Target: v.Target, RefillInterval: refill}
		}
	}
	if f.Pool != nil && len(f.Pool.WeeklyWindows) > 0 {
		cfg.Pool.WeeklyWindows = make([]PoolWeeklyWindow, 0, len(f.Pool.WeeklyWindows))
		for i, window := range f.Pool.WeeklyWindows {
			parsed, err := parsePoolWeeklyWindow(window)
			if err != nil {
				return ControlConfig{}, fmt.Errorf("pool.weekly_windows[%d]: %w", i, err)
			}
			cfg.Pool.WeeklyWindows = append(cfg.Pool.WeeklyWindows, parsed)
		}
	}

	if err := cfg.Validate(); err != nil {
		return ControlConfig{}, err
	}
	return cfg, nil
}

// Validate fails fast on missing / invalid required fields. Only the
// pool block is currently checked here; the rest is validated inline
// in ControlFromContext for historical reasons.
func (cfg ControlConfig) Validate() error {
	if !cfg.Pool.Enabled {
		return nil
	}
	p := cfg.Pool
	if strings.TrimSpace(p.OwnerID) == "" {
		return fmt.Errorf("pool.owner_id required when pool.enabled=true")
	}
	if p.PerHostGrowRate <= 0 {
		return fmt.Errorf("pool.per_host_grow_rate must be > 0 (got %d)", p.PerHostGrowRate)
	}
	if p.MaxAge <= 0 {
		return fmt.Errorf("pool.max_age must be > 0 (got %s)", p.MaxAge)
	}
	if strings.TrimSpace(p.Spec.Shape) == "" {
		return fmt.Errorf("pool.spec.shape required when pool.enabled=true")
	}
	if p.Spec.DiskMib <= 0 {
		return fmt.Errorf("pool.spec.disk_mib must be > 0 (got %d)", p.Spec.DiskMib)
	}
	wantBuckets := make([]string, 24)
	for i := 0; i < 24; i++ {
		wantBuckets[i] = fmt.Sprintf("%02d", i)
	}
	if len(p.Buckets) == 0 {
		return fmt.Errorf("pool.buckets required when pool.enabled=true (must define all 24 hourly UTC keys 00..23; YAML-only surface)")
	}
	for _, k := range wantBuckets {
		b, ok := p.Buckets[k]
		if !ok {
			return fmt.Errorf("pool.buckets[%q] missing (must define all 24 hourly UTC keys 00..23)", k)
		}
		if b.Target < 0 {
			return fmt.Errorf("pool.buckets[%q].target must be >= 0 (got %d)", k, b.Target)
		}
		if b.RefillInterval < time.Second {
			return fmt.Errorf("pool.buckets[%q].refill_interval must be >= 1s (got %s)", k, b.RefillInterval)
		}
	}
	for i, window := range p.WeeklyWindows {
		if window.Timezone == nil {
			return fmt.Errorf("pool.weekly_windows[%d].timezone is required", i)
		}
		if window.Start < 0 || window.Start >= 24*time.Hour ||
			window.End <= 0 || window.End > 24*time.Hour || window.Start >= window.End {
			return fmt.Errorf("pool.weekly_windows[%d] must have 00:00 <= start < end <= 24:00", i)
		}
		if window.Target < 0 {
			return fmt.Errorf("pool.weekly_windows[%d].target must be >= 0", i)
		}
	}
	return nil
}

func parsePoolWeeklyWindow(f PoolWeeklyWindowFile) (PoolWeeklyWindow, error) {
	var weekday time.Weekday
	found := false
	for day := time.Sunday; day <= time.Saturday; day++ {
		if strings.EqualFold(strings.TrimSpace(f.Weekday), day.String()) {
			weekday, found = day, true
			break
		}
	}
	if !found {
		return PoolWeeklyWindow{}, fmt.Errorf("invalid weekday %q", f.Weekday)
	}

	location, err := time.LoadLocation(strings.TrimSpace(f.Timezone))
	if err != nil {
		return PoolWeeklyWindow{}, fmt.Errorf("timezone: %w", err)
	}
	start, err := parsePoolClock("start", f.Start)
	if err != nil {
		return PoolWeeklyWindow{}, err
	}
	end, err := parsePoolClock("end", f.End)
	if err != nil {
		return PoolWeeklyWindow{}, err
	}
	return PoolWeeklyWindow{
		Weekday: weekday, Timezone: location,
		Start: start, End: end, Target: f.Target,
	}, nil
}

func parsePoolClock(name, value string) (time.Duration, error) {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("%s must use HH:MM", name)
	}
	hour, err := strconv.Atoi(parts[0])
	if err != nil || hour < 0 || hour > 24 {
		return 0, fmt.Errorf("%s has invalid hour", name)
	}
	minute, err := strconv.Atoi(parts[1])
	if err != nil || minute < 0 || minute > 59 || (hour == 24 && minute != 0) {
		return 0, fmt.Errorf("%s has invalid minute", name)
	}
	return time.Duration(hour)*time.Hour + time.Duration(minute)*time.Minute, nil
}
