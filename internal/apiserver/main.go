// Package apiserver implements the CreateOS control-plane API: it schedules
// sandbox creates through the scheduler and forwards sandbox operations to the
// owning machine.
package apiserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/NodeOps-app/sandbox/config"
	"github.com/NodeOps-app/sandbox/internal/apiserver/cache"
	"github.com/NodeOps-app/sandbox/internal/apiserver/diskcrypto"
	"github.com/NodeOps-app/sandbox/internal/apiserver/handlers"
	"github.com/NodeOps-app/sandbox/internal/apiserver/hostwarm"
	"github.com/NodeOps-app/sandbox/internal/apiserver/inframonitor"
	"github.com/NodeOps-app/sandbox/internal/apiserver/middlewares"
	"github.com/NodeOps-app/sandbox/internal/apiserver/routes"
	"github.com/NodeOps-app/sandbox/internal/apiserver/sandboxaccess"
	"github.com/NodeOps-app/sandbox/internal/apiserver/userapikey"
	"github.com/NodeOps-app/sandbox/internal/auditemit"
	"github.com/NodeOps-app/sandbox/internal/billingemit"
	"github.com/NodeOps-app/sandbox/internal/ca"
	"github.com/NodeOps-app/sandbox/internal/ca/crl"
	"github.com/NodeOps-app/sandbox/internal/clickhouse"
	"github.com/NodeOps-app/sandbox/internal/createos"
	"github.com/NodeOps-app/sandbox/internal/hostrpc"
	"github.com/NodeOps-app/sandbox/internal/httpx"
	authjwt "github.com/NodeOps-app/sandbox/internal/jwt"
	"github.com/NodeOps-app/sandbox/internal/logging"
	"github.com/NodeOps-app/sandbox/internal/mtlsclient"
	"github.com/NodeOps-app/sandbox/internal/pool"
	"github.com/NodeOps-app/sandbox/internal/proto"
	schedclient "github.com/NodeOps-app/sandbox/internal/scheduler/client"
	"github.com/NodeOps-app/sandbox/internal/storage"
	"github.com/NodeOps-app/sandbox/models"
)

// Deps is the dependency bundle used to construct a control-plane Server.
type Deps struct {
	Repo      *models.Repo
	Addr      string
	PanicMode bool // emergency public-API kill switch; host-admin/internal/health remain available
	// DisableDeviceRegistration gates only creation of new devices. Existing
	// device management and VPN sessions remain operational when disabled.
	DisableDeviceRegistration bool
	Client                    *http.Client
	Resolver                  *userapikey.Cache // user-key resolver; nil makes protected routes return 503
	AdminToken                string            // shared secret for host operations and pprof; empty disables these routes
	PromSDToken               string            // static bearer protecting /v1/internal/sd/hosts; "" disables endpoint
	// HostPubkeys is the per-host Ed25519 verify-key cache used by
	// InternalJWTMiddleware. Populated by the wiring layer with a
	// HostPubkeys cache that reads from hosts.public_key. Internal routes
	// are mTLS-authenticated; the JWT path remains in place for the
	// few live callers that still bear JWTs (builder, billing webhooks).
	HostPubkeys *cache.HostPubkeys

	// StaticActors holds gateway/ingress pubkeys loaded from operator
	// config. Used by the JWT verifier resolver to verify their JWTs.
	StaticActors *authjwt.PubkeyMap

	// BootstrapToken is the X-Bootstrap-Token shared secret accepted on
	// /v1/internal/hosts/register for compute hosts. Empty fails-closed
	// at startup unless RelayBootstrapToken is set.
	BootstrapToken string

	// RelayBootstrapToken is a SEPARATE shared secret used only when
	// onboarding role=relay hosts. Distinct from BootstrapToken so a
	// leaked compute-onboarding secret can't mint a rogue relay (and
	// vice versa). Empty disables relay onboarding.
	RelayBootstrapToken string

	// Region is stamped onto every sandbox row this control plane creates.
	// Required at startup (validated in config); the ingress refuses to
	// route a sandbox whose stored region doesn't match its own.
	Region string

	// RelayCrossRegionFallback: when this control's region has no active
	// relay, allow the device session-create picker to fall back to any
	// region (preferring same). ON by default because not every active
	// region hosts a relay (devices may ride another region's relay).
	RelayCrossRegionFallback bool

	// SchedulerClient delegates placement to the standalone createos
	// scheduler service. Required — control does not schedule in-process.
	SchedulerClient *schedclient.Client

	// Storage is the blob backend used by the fork orchestration
	// path (R2 server-side CopyObject). Pause and resume happen on
	// the host side and use the host's own Storage; control only
	// touches storage for fork. Nil = fork returns 501.
	Storage storage.Storage

	// HostStorage is the raw S3 config relayed to hosts in the
	// register response so each host can construct its own R2 client
	// for pause/resume without persisting credentials on disk. Same
	// values as control uses for its own `Storage` client.
	HostStorage config.StorageConfig

	// PeerControls maps region → peer control URL for cross-region
	// create/resume/fork forwarding. Empty disables cross-region.
	PeerControls map[string]string

	// Per-user creation caps. 0 = unlimited. Internal keys always
	// bypass. Override maps are user_id → per-user replacement of
	// the matching default; nil = no overrides for that cap.
	MaxSandboxConcurrent  int
	MaxSandboxPerDay      int
	MaxNetworkConcurrent  int
	MaxNetworkPerDay      int
	MaxDiskConcurrent     int
	MaxDiskPerDay         int
	MaxTemplateConcurrent int
	MaxTemplatePerDay     int

	// IngressDomainSuffix is the public DNS suffix the cluster's
	// control ingress is reachable on. When non-empty and a sandbox
	// is created with ingress_enabled=true, the create response
	// includes a URL template the client can show the user.
	IngressDomainSuffix string

	// BuildLogs is the ClickHouse-backed log store for template builds.
	// Optional; nil disables the streaming logs endpoints.
	BuildLogs *clickhouse.Client

	// DiskCipher encrypts/decrypts disks.credentials at rest in PostgreSQL.
	// cryptobox separately protects decrypted credentials in transit to the
	// selected host. Optional; nil = disks API returns 503 and sandbox-create
	// rejects any `disks:` field.
	DiskCipher *diskcrypto.Cipher

	// APIKeyHasher computes HMAC-SHA256(pepper, token) for api_keys.key_hash.
	// Always non-nil; if the pepper file was empty, the hasher's Enabled()
	// reports false and Resolve fails-closed.
	APIKeyHasher *userapikey.Hasher

	// DefaultBandwidthQuotaBytes is the cluster default applied at create
	// time when the request omits (or sends 0) bandwidth_quota_bytes.
	// Source of truth: ControlConfig.DefaultBandwidthQuotaBytes.
	DefaultBandwidthQuotaBytes int64

	// Pool is the resolved predictive pre-warm sandbox pool config.
	// Enabled=false leaves the whole surface inert.
	Pool config.PoolConfig

	// CreateosClient is the outbound credit/plan client used by the
	// auto-top-up trigger. Nil disables auto-top-up.
	CreateosClient *createos.Client
	// ReplMonitorEnabled independently gates replication Slack alerts.
	ReplMonitorEnabled bool
	// InfraAlertURL receives infrastructure-monitor notifications. Empty
	// disables the monitor.
	InfraAlertURL string
	// AutoTopupThresholdBytes — remaining quota below this triggers an
	// auto-recharge. 0 disables.
	AutoTopupThresholdBytes int64
	// AutoTopupGiB is the GiB of bandwidth requested from createos per
	// trigger. 0 disables.
	AutoTopupGiB float64

	// CA is the optional in-process certificate authority that backs
	// the mTLS bootstrap endpoints (CSR issuance + CRL). Nil =
	// endpoints return 503.
	CA *ca.CA

	// InternalAddr enables the dedicated service-to-service mTLS listener
	// (host/ingress/gateway/proxy/scheduler). Empty disables. When set,
	// control listens on Addr (public — plain HTTP, terminated at
	// Cloudflare/nginx) AND on InternalAddr (TLS + RequireAndVerifyClientCert).
	InternalAddr        string
	InternalTLSCertPath string
	InternalTLSKeyPath  string
	InternalTLSCAPath   string

	// CORSAllowedOrigins — allowlist for the CORS middleware. Empty = permit
	// all + log a one-time warning.
	CORSAllowedOrigins []string
}

// Server is the control-plane HTTP server. It owns the process lifecycle
// (Fiber app, background reap/evict loops, graceful shutdown). All HTTP
// request handling lives in the handlers package; all route definitions
// live in the routes package.
type Server struct {
	repo                      *models.Repo
	addr                      string
	panicMode                 bool
	disableDeviceRegistration bool
	http                      *http.Client
	resolver                  *userapikey.Cache
	adminToken                string
	promSDToken               string
	hostPubkeys               *cache.HostPubkeys
	staticActors              *authjwt.PubkeyMap // gateway/ingress pubkeys for verify
	bootstrapToken            string
	relayBootstrapToken       string
	region                    string
	relayCrossRegionFallback  bool
	maxSandboxConcurrent      int
	maxSandboxPerDay          int
	maxNetworkConcurrent      int
	maxNetworkPerDay          int
	maxDiskConcurrent         int
	maxDiskPerDay             int
	maxTemplateConcurrent     int
	maxTemplatePerDay         int

	// limitsCache resolves the effective per-user policy at handler
	// time from the createos plan (falling back to static defaults).
	// Built in New(); read-only from then on.
	limitsCache *handlers.LimitsCache

	ingressDomainSuffix string

	apiKeyHasher *userapikey.Hasher

	// schedulerClient delegates all placement decisions to the standalone
	// control scheduler service over HTTP.
	schedulerClient *schedclient.Client

	// storage is the blob backend used by fork's R2 server-side copy.
	// Nil disables /v1/sandboxes/:id/fork (returns 501).
	storage storage.Storage
	// hostStorage is the raw S3 config relayed to hosts in the register
	// response so they don't need to carry credentials in serve.yaml.
	hostStorage config.StorageConfig
	// peerControls is region → peer control URL for cross-region forward.
	peerControls map[string]string

	// buildlogs is the ClickHouse-backed build log store. Nil disables
	// the templates log endpoints (POST ingest + GET reader).
	buildlogs *clickhouse.Client

	// diskCipher decrypts disks.credentials. Nil disables the disks API.
	diskCipher *diskcrypto.Cipher

	// defaultBandwidthQuotaBytes is the cluster's default per-sandbox
	// bandwidth byte cap; control resolves request.BandwidthQuotaBytes==0
	// onto this value before forwarding to the host.
	defaultBandwidthQuotaBytes int64

	// createosClient + auto-top-up knobs. Nil/zero values disable the
	// auto-recharge trigger (hard cap remains in effect as today).
	createosClient          *createos.Client
	replMonitorEnabled      bool
	infraAlertURL           string
	autoTopupThresholdBytes int64
	autoTopupGiB            float64

	// ca is the optional in-process CA used by the mTLS bootstrap
	// endpoints. Nil = mTLS disabled.
	ca *ca.CA

	// Dedicated internal-port listener (mTLS-only). Public addr stays plain.
	internalAddr        string
	crlLocal            *crl.Local
	internalTLSCertPath string
	internalTLSKeyPath  string
	internalTLSCAPath   string

	// corsAllowedOrigins is the configured allowlist of browser origins.
	// Empty = permit all (legacy behaviour); a startup warning is logged.
	corsAllowedOrigins []string

	// shapesCache is the DB-backed VM shape catalog with TTL caching.
	// Operators manage rows via direct SQL; the cache picks up changes
	// within 30 seconds. It returns an empty catalog when the DB is empty
	// or unreachable and the cache has never warmed (logged once; hosts
	// will see an empty Shapes push).
	shapesCache *cache.Shapes

	// pool is the resolved predictive pre-warm sandbox pool config,
	// threaded from Deps.Pool. Wired into the handler via SetPool().
	pool config.PoolConfig
}

// New constructs a control-plane server from the given deps.
func New(d Deps) *Server {
	// Local CRL cache — populated from issued_certs ledger directly,
	// no HTTP self-loop. Wired into BOTH the outbound mTLS transport
	// (control → host) and the inbound :8443 listener (see Run).
	crlLocal := crl.NewLocal(d.Repo)
	c := d.Client
	if c == nil {
		// 1h cap — long enough for buffered /exec on slow apt/pip
		// installs and for destroy queueing behind kernel locks
		// (xt_lock on iptables-restore, rtnl on veth teardown) under
		// heavy parallel delete, short enough that a wedged host
		// can't pin a goroutine forever. Per-call cancellation still
		// comes from the caller's Fiber ctx; dial / TLS handshake
		// timeouts on the transport bound the connect phase so dead
		// hosts fail fast.
		tr := http.DefaultTransport.(*http.Transport).Clone()
		// A burst is spread across the compute fleet, but each host can still
		// receive tens of concurrent execs. Retaining only ten idle connections
		// forced the remainder to pay a fresh TCP+mTLS handshake (roughly 25-55ms
		// in production) and was the dominant exec p95 tail. Keep enough of the
		// connections established by pool refill and ordinary traffic for a full
		// per-host burst. This changes only connection reuse; every request still
		// uses the same TLS 1.3 client certificate and CRL verification.
		tr.MaxIdleConns = 800
		tr.MaxIdleConnsPerHost = 100
		// Keep control-to-host connections across long quiet periods. The
		// connection warmer runs well inside this window; the host's server-side
		// idle timeout is deliberately slightly longer so the client owns normal
		// retirement and never discovers a server FIN in an exec critical path.
		tr.IdleConnTimeout = 9 * time.Minute
		// Install client-side mTLS for control→host RPCs when the
		// operator wired up the internal mTLS bundle. The same client cert
		// authenticates to every other internal mTLS-only listener
		// (host, ingress, gateway, scheduler).
		if d.InternalTLSCertPath != "" {
			tlsTr, err := mtlsclient.NewTransportWithVerify(d.InternalTLSCertPath, d.InternalTLSKeyPath, d.InternalTLSCAPath, tr, crlLocal.VerifyPeerCertificate)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[control] mTLS transport disabled — %v\n", err)
			} else {
				tr = tlsTr
			}
		}
		c = &http.Client{Timeout: time.Hour, Transport: tr}
	}
	return &Server{
		schedulerClient:           d.SchedulerClient,
		storage:                   d.Storage,
		hostStorage:               d.HostStorage,
		peerControls:              d.PeerControls,
		buildlogs:                 d.BuildLogs,
		repo:                      d.Repo,
		addr:                      d.Addr,
		panicMode:                 d.PanicMode,
		disableDeviceRegistration: d.DisableDeviceRegistration,
		http:                      c,
		resolver:                  d.Resolver,
		adminToken:                d.AdminToken,
		promSDToken:               d.PromSDToken,
		hostPubkeys:               d.HostPubkeys,
		staticActors:              d.StaticActors,
		bootstrapToken:            d.BootstrapToken,
		relayBootstrapToken:       d.RelayBootstrapToken,
		region:                    d.Region,
		relayCrossRegionFallback:  d.RelayCrossRegionFallback,
		maxSandboxConcurrent:      d.MaxSandboxConcurrent,
		maxSandboxPerDay:          d.MaxSandboxPerDay,
		maxNetworkConcurrent:      d.MaxNetworkConcurrent,
		maxNetworkPerDay:          d.MaxNetworkPerDay,
		maxDiskConcurrent:         d.MaxDiskConcurrent,
		maxDiskPerDay:             d.MaxDiskPerDay,
		maxTemplateConcurrent:     d.MaxTemplateConcurrent,
		maxTemplatePerDay:         d.MaxTemplatePerDay,

		ingressDomainSuffix: d.IngressDomainSuffix,
		diskCipher:          d.DiskCipher,
		apiKeyHasher:        d.APIKeyHasher,

		defaultBandwidthQuotaBytes: d.DefaultBandwidthQuotaBytes,

		createosClient:          d.CreateosClient,
		replMonitorEnabled:      d.ReplMonitorEnabled,
		infraAlertURL:           d.InfraAlertURL,
		autoTopupThresholdBytes: d.AutoTopupThresholdBytes,
		autoTopupGiB:            d.AutoTopupGiB,

		ca: d.CA,

		internalAddr:        d.InternalAddr,
		crlLocal:            crlLocal,
		internalTLSCertPath: d.InternalTLSCertPath,
		internalTLSKeyPath:  d.InternalTLSKeyPath,
		internalTLSCAPath:   d.InternalTLSCAPath,

		corsAllowedOrigins: d.CORSAllowedOrigins,

		shapesCache: cache.NewShapes(d.Repo, 30*time.Second),

		pool: d.Pool,
	}
}

// buildLimitsCache constructs the per-user effective-limits resolver
// from the static defaults + the optional createos client. Called once
// during Run after handler construction.
func (s *Server) buildLimitsCache() *handlers.LimitsCache {
	defaults := handlers.Limits{
		MaxSandboxes:              s.maxSandboxConcurrent,
		MaxSandboxesPerDay:        s.maxSandboxPerDay,
		MaxSandboxNetworks:        s.maxNetworkConcurrent,
		MaxSandboxNetworksPerDay:  s.maxNetworkPerDay,
		MaxSandboxDisks:           s.maxDiskConcurrent,
		MaxSandboxDisksPerDay:     s.maxDiskPerDay,
		MaxSandboxTemplates:       s.maxTemplateConcurrent,
		MaxSandboxTemplatesPerDay: s.maxTemplatePerDay,
		// AllowedShapes + MaxDiskMib have no static-config counterpart
		// today — empty/zero means "no plan restriction" at fallback.
		// MaxDevices: conservative default — most users register 1-3
		// machines (laptop, desktop, server). 10 catches sprawl long
		// before the CGNAT pool is at risk.
		MaxDevices: 10,
	}
	return handlers.NewLimitsCache(s.createosClient, defaults)
}

// Run starts the control-plane HTTP server and blocks until shutdown.
func (s *Server) Run(ctx context.Context) error {
	app := fiber.New(fiber.Config{
		AppName:               "createos-api-server",
		DisableStartupMessage: true,
		// Handlers launch background lifecycle/activity work after returning.
		// Make strings obtained from Ctx (params, headers, queries, paths) own
		// their bytes instead of aliasing fasthttp's reusable request buffer.
		Immutable: true,
		// User JSON is already capped at 256 KiB. Use that as the buffering
		// threshold so every meaningful file upload is exposed as a stream;
		// route-aware middleware below retains a separate internal-RPC cap.
		BodyLimit:         256 * 1024,
		StreamRequestBody: true,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			status := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				status = e.Code
			}
			// 4xx messages are user-actionable (e.g. fiber.NewError(400, "bad json")).
			// 5xx messages may carry internal detail — log + return generic.
			if status >= http.StatusInternalServerError {
				log.WithContext(ctx).WithFields(log.Fields{
					"status":     status,
					"method":     c.Method(),
					"path":       c.Path(),
					"request_id": c.Locals("requestid"),
				}).Errorf("[http-error] request failed: %v", err)

				return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
			}
			return httpx.Error(c, status, err.Error())
		},
	})

	// Only builder and billing routes accept JWTs; host RPCs use mTLS.
	// Never resolve caller-supplied JWT host IDs through the database/cache.
	jwtVerifier := &authjwt.Verifier{Resolve: authjwt.CombinedResolver(nil, s.staticActors)}
	sandboxOwner := func(ctx context.Context, sbID string) (string, bool, error) {
		rec, err := s.repo.Get(ctx, sbID)
		if err != nil {
			return "", false, err
		}
		if rec == nil {
			return "", false, nil
		}
		if rec.HostID != nil && *rec.HostID != "" {
			return *rec.HostID, true, nil
		}
		return "", true, nil
	}
	mw := middlewares.NewMiddleware(s.resolver, jwtVerifier, s.adminToken, s.bootstrapToken, s.relayBootstrapToken, sandboxOwner)
	mw.SetSandboxTokenResolver(sandboxaccess.NewResolver(s.repo, s.apiKeyHasher))

	app.Use(recover.New())
	app.Use(requestid.New())
	app.Use(httpx.FiberRequestIDIntoContext)
	// Path scope guard for the internal mTLS listener. Any request that
	// arrives with a verified client certificate is, by construction, on
	// the :8443 listener (the public :8080 listener doesn't request a
	// client cert). On that listener, refuse everything that isn't a
	// /v1/internal/* route. Without this guard, a holder of any valid
	// internal client cert could reach user-facing /v1/sandboxes/*,
	// user-facing routes by forging an API key or user-id header —
	// turning every issued internal cert into a universal credential.
	app.Use(func(c *fiber.Ctx) error {
		state := c.Context().TLSConnectionState()
		if state == nil || len(state.PeerCertificates) == 0 {
			return c.Next()
		}
		p := c.Path()
		if strings.HasPrefix(p, "/v1/internal/") {
			return c.Next()
		}
		return httpx.Fail(c, fiber.StatusNotFound, "route not available on internal listener")
	})
	app.Use(middlewares.PanicMode(s.panicMode))
	if s.panicMode {
		log.WithContext(ctx).Warn("[control] PANIC MODE ENABLED: user-facing API routes return 503")
	}
	app.Use(httpx.EnforceStreamingBodyLimits(256*1024, 500*1024*1024, proto.MaxFileUploadBytes))
	// Per-IP rate limit on user-facing routes. Caps unauth-flood +
	// auth-probe volume before we ever look at the API key. Internal
	// mTLS callers (any request with a verified client cert) are
	// exempt — they're peer services, not attackers. Liveness probes
	// and CORS preflight are exempt so ops tooling isn't caught.
	//
	// clientIP prefers Cf-Connecting-Ip → X-Forwarded-For → c.IP() so
	// the bucket keys on the real end-user, not the LB pod IP.
	app.Use(limiter.New(limiter.Config{
		Max:        300,
		Expiration: time.Minute,
		Next: func(c *fiber.Ctx) bool {
			if state := c.Context().TLSConnectionState(); state != nil && len(state.PeerCertificates) > 0 {
				return true
			}
			p := c.Path()
			if p == "/healthz" || p == "/readyz" {
				return true
			}
			// Host-facing routes on the public listener (first-time
			// bootstrap register, CRL fetch, etc.) have their own
			// auth gates and must never be throttled by user-traffic
			// buckets — a NAT'd fleet onboarding wave would otherwise
			// share one IP.
			if strings.HasPrefix(p, "/v1/internal/") {
				return true
			}
			return c.Method() == fiber.MethodOptions
		},
		KeyGenerator: func(c *fiber.Ctx) string {
			if v := strings.TrimSpace(c.Get("Cf-Connecting-Ip")); v != "" {
				return v
			}
			if v := strings.TrimSpace(c.Get("X-Forwarded-For")); v != "" {
				if i := strings.IndexByte(v, ','); i >= 0 {
					v = strings.TrimSpace(v[:i])
				}
				if v != "" {
					return v
				}
			}
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return httpx.Fail(c, fiber.StatusTooManyRequests, "rate limit exceeded")
		},
	}))
	// CORS allowlist — when corsAllowedOrigins is configured, only those
	// origins receive Access-Control-* headers (browsers in other origins
	// will reject the response). Empty allowlist = legacy permit-all
	// behaviour + a one-time startup warning. The auth gate is the actual
	// security boundary; CORS is browser-side only.
	if len(s.corsAllowedOrigins) == 0 {
		log.WithContext(ctx).Warnf("[control] CORS allow_origins not configured (cors_allowed_origins empty); permitting all origins — set the YAML key to lock down to a specific dashboard origin")
	}
	allowedSet := make(map[string]struct{}, len(s.corsAllowedOrigins))
	for _, o := range s.corsAllowedOrigins {
		allowedSet[o] = struct{}{}
	}
	app.Use(cors.New(cors.Config{
		AllowOriginsFunc: func(origin string) bool {
			if len(allowedSet) == 0 {
				return true
			}
			_, ok := allowedSet[origin]
			return ok
		},
		AllowMethods:     "GET,POST,PUT,PATCH,DELETE,OPTIONS",
		AllowHeaders:     "Content-Type,X-Request-Id,X-Api-Key,X-Auth-Token,X-Access-Token",
		ExposeHeaders:    "X-Request-Id,X-Poll-After",
		AllowCredentials: false,
	}))
	app.Use(mw.MustBeAuthenticated())
	// Pin user-facing body parsing to JSON. Fiber's BodyParser would
	// otherwise dispatch on Content-Type and parse XML / form-encoded
	// payloads with different coercion rules (CWE-20).
	app.Use(mw.RequireJSON())
	// Cap JSON body size + nesting depth on user-facing routes. The global
	// 500 MB BodyLimit above is sized for the /v1/sandboxes/:id/files
	// path; everything else inherits that cap unless we narrow it here.
	app.Use(mw.JSONGuard())
	app.Use(httpx.LogServerErrors("control"))
	app.Use(logger.New(logger.Config{
		Format:     logging.AccessLogFormat(),
		CustomTags: logging.AccessLogCustomTags(),
		TimeFormat: "15:04:05.000",
	}))

	s.limitsCache = s.buildLimitsCache()
	billingEmitter := billingemit.New(s.repo.DB, s.shapesCache)
	apiHandler := handlers.NewHandler(
		s.repo, s.http, s.hostPubkeys, s.resolver, s.apiKeyHasher,
		s.region,
		s.limitsCache,
		s.ingressDomainSuffix,
		billingEmitter,
		s.schedulerClient, s.storage, s.buildlogs, s.diskCipher,
		s.defaultBandwidthQuotaBytes,
		s.createosClient,
		s.autoTopupThresholdBytes,
		s.autoTopupGiB,
		hostSchemeFor(s.internalTLSCertPath, s.internalTLSKeyPath, s.internalTLSCAPath),
	)
	handlers.SetHostScheme(hostSchemeFor(s.internalTLSCertPath, s.internalTLSKeyPath, s.internalTLSCAPath))
	hostrpc.SetHostScheme(hostSchemeFor(s.internalTLSCertPath, s.internalTLSKeyPath, s.internalTLSCAPath))
	if s.internalTLSCertPath != "" {
		if err := handlers.SetHostDialTLS(
			s.internalTLSCertPath,
			s.internalTLSKeyPath,
			s.internalTLSCAPath,
			s.crlLocal.VerifyPeerCertificate,
		); err != nil {
			log.WithContext(ctx).Warnf("[control] host-dial TLS not configured: %v", err)
		}
	}
	apiHandler.SetCA(s.ca)
	apiHandler.SetShapes(s.shapesCache)
	apiHandler.SetHostStorage(s.hostStorage)
	apiHandler.SetPeerControls(s.peerControls)
	apiHandler.SetPool(s.pool)
	// Audit emitter — writes audit_events; defaults to 90-day retention
	// (sweeper deletes expired rows). Worker drains via control audit-worker.
	apiHandler.SetAudit(auditemit.New(s.repo.DB, 90*24*time.Hour))
	apiHandler.SetRelayCrossRegionFallback(s.relayCrossRegionFallback)
	apiHandler.SetDeviceRegistrationDisabled(s.disableDeviceRegistration)
	routes.Register(app, apiHandler, mw, s.promSDToken)

	log.WithContext(ctx).Infof("[control] startup config: quotas={sb_concurrent=%d sb_per_day=%d net=%d disk=%d disk_per_day=%d tpl=%d tpl_per_day=%d} region=%s",
		s.maxSandboxConcurrent, s.maxSandboxPerDay, s.maxNetworkConcurrent, s.maxDiskConcurrent, s.maxDiskPerDay,
		s.maxTemplateConcurrent, s.maxTemplatePerDay,
		s.region)

	// Register this control plane's region. Idempotent — re-runs on every
	// startup are no-ops once the slot_index is claimed. New region picks
	// the next free slot (0..3) and seeds its allocator rows. Fails fast
	// if slot_index would exceed the 4-region cap.
	if slot, err := s.repo.RegisterRegion(ctx, s.region); err != nil {
		return fmt.Errorf("register region %q: %w", s.region, err)
	} else {
		log.WithContext(ctx).Infof("[control] region=%s slot_index=%d", s.region, slot)
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	// No background loops here — all sweeping/reaping/drain runs in
	// the `control sweep` CronJob. We still use an errgroup so the
	// shutdown wiring below can g.Wait() uniformly.
	g, gctx := errgroup.WithContext(runCtx)
	_ = gctx

	// CRL cache: polls issued_certs ledger every 30s and exposes
	// VerifyPeerCertificate to the listener tls.Config + outbound mTLS
	// transport. An `admin ca revoke <serial>` propagates fleet-wide
	// within (poll interval + verifier callsite) — typically ~30s.
	if s.crlLocal != nil {
		go s.crlLocal.Run(runCtx, 30*time.Second)
	}

	// Predictive pre-warm pool grow/shrink loop. Concurrent replicas
	// coordinate via a Postgres advisory lock so only one replica ticks
	// per pool. When cfg.Pool.Enabled=false, Pool.Run returns immediately.
	if s.pool.Enabled {
		if err := pool.ValidateBuckets(s.pool.Buckets); err != nil {
			return fmt.Errorf("pool config: %w", err)
		}
		p := pool.New(s.pool, s.region, s.repo.DB, apiHandler)
		go p.Run(runCtx)
		log.WithContext(ctx).Infof("[control] pool goroutine started (region=%s buckets=%d)", s.region, len(s.pool.Buckets))
	}

	// The host API is HTTP/1.1, so a cold replica otherwise opens TCP+mTLS
	// connections in the first exec burst. Keep a bounded per-host set ready.
	if s.internalTLSCertPath != "" {
		go hostwarm.New(s.repo, s.http, s.region).Run(runCtx)
	}

	// Infrastructure monitor: checks LOCAL pg_replication_slots plus critical
	// database security invariants every replMonitorInterval and POSTs alerts to
	// the configured infrastructure alert URL. Watching only local replication
	// slots is deliberate — a
	// cross-region reach would die in the very outage this exists to catch.
	// An empty webhook URL disables delivery explicitly, so this no longer
	// depends on the unrelated createos credit client as a deployment proxy.
	if s.replMonitorEnabled && s.infraAlertURL != "" {
		go inframonitor.New(s.repo, s.region, s.infraAlertURL).Run(runCtx)
		log.WithContext(ctx).Infof("[control] infrastructure monitor started (region=%s)", s.region)
	} else if !s.replMonitorEnabled {
		log.WithContext(ctx).Infof("[control] infrastructure monitor disabled (region=%s)", s.region)
	} else {
		log.WithContext(ctx).Infof("[control] infrastructure monitor disabled: infra alert URL is empty (region=%s)", s.region)
	}

	// Billing webhook worker runs as its own deployment now (the
	// `control billing-worker` subcommand). Control's only job in the
	// billing pipeline is to write outbox rows from emitBillingEvent —
	// the separate worker process drains them. See internal/billing/cli.go.

	log.WithContext(ctx).Infof("[control] public listener on %s (plain HTTP, terminated at LB/nginx)", s.addr)

	shutdownErr := make(chan error, 1)
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-sigCh:
			log.WithContext(ctx).Info("[control] shutdown signal received")
		case <-ctx.Done():
			log.WithContext(ctx).Info("[control] context cancelled, shutting down")
		}
		cancelRun()
		sdCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shutdownErr <- app.ShutdownWithContext(sdCtx)
	}()

	// Dedicated internal-port listener (mTLS-only) — for service-to-service
	// callers (host/ingress/gateway/proxy/scheduler). Always RequireAndVerifyClientCert.
	// Public port stays on s.addr (plain HTTP or LB-terminated TLS).
	internalEnabled := s.internalAddr != "" && s.internalTLSCertPath != "" && s.internalTLSKeyPath != "" && s.internalTLSCAPath != ""
	if internalEnabled {
		cert, err := tls.LoadX509KeyPair(s.internalTLSCertPath, s.internalTLSKeyPath)
		if err != nil {
			return fmt.Errorf("control: load internal TLS keypair: %w", err)
		}
		caPEM, err := os.ReadFile(s.internalTLSCAPath)
		if err != nil {
			return fmt.Errorf("control: read internal TLS CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return fmt.Errorf("control: internal TLS CA %q has no PEM certs", s.internalTLSCAPath)
		}
		tlsCfg := &tls.Config{
			Certificates:          []tls.Certificate{cert},
			ClientCAs:             pool,
			ClientAuth:            tls.RequireAndVerifyClientCert,
			MinVersion:            tls.VersionTLS13,
			VerifyPeerCertificate: s.crlLocal.VerifyPeerCertificate,
			// Resumed sessions skip VerifyPeerCertificate; a cert revoked
			// after the first handshake would otherwise stay usable for the
			// session-ticket lifetime.
			VerifyConnection: crl.VerifyConnectionFunc(s.crlLocal.VerifyPeerCertificate),
		}
		rawLn, err := net.Listen("tcp", s.internalAddr)
		if err != nil {
			return fmt.Errorf("control: listen on internal %s: %w", s.internalAddr, err)
		}
		// The internal mTLS listener serves the same Fiber app as the
		// public listener, but a global pre-middleware (registered early
		// in this Run function) detects "verified client cert present" and
		// 404s anything outside /v1/internal/*. Without that guard a
		// holder of any internal cert could pivot into /v1/sandboxes/* by
		// forging an API key — turning the issued cert into a universal
		// credential. The pre-middleware enforces "internal listener →
		// internal routes only" without splitting the app.
		internalLn := tls.NewListener(rawLn, tlsCfg)
		log.WithContext(ctx).Infof("[control] internal mTLS listener enabled on %s cert=%s", s.internalAddr, s.internalTLSCertPath)
		g.Go(func() error {
			<-gctx.Done()
			return internalLn.Close()
		})
		g.Go(func() error {
			err := app.Listener(internalLn)
			if err != nil && err != net.ErrClosed {
				return err
			}
			return nil
		})
	}

	if err := app.Listen(s.addr); err != nil {
		return err
	}
	if err := <-shutdownErr; err != nil {
		return err
	}
	// Block until every background loop has observed the cancelled ctx
	// and returned, so Run doesn't outlive its own goroutines.
	if err := g.Wait(); err != nil {
		return err
	}
	return nil
}

func hostSchemeFor(cert, key, ca string) string {
	if cert != "" && key != "" && ca != "" {
		return "https"
	}
	return "http"
}
