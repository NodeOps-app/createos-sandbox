// Package handlers holds every HTTP handler for the control api-server
// plane. It was split out of internal/apiserver so that route definitions
// (internal/apiserver/routes) and server lifecycle (internal/apiserver)
// stay thin and decoupled from request-handling logic.
package handlers

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/NodeOps-app/createos-sandbox/config"
	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/cache"
	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/diskcrypto"
	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/userapikey"
	"github.com/NodeOps-app/createos-sandbox/internal/audit"
	"github.com/NodeOps-app/createos-sandbox/internal/billingemit"
	"github.com/NodeOps-app/createos-sandbox/internal/ca"
	"github.com/NodeOps-app/createos-sandbox/internal/clickhouse"
	"github.com/NodeOps-app/createos-sandbox/internal/createos"
	schedclient "github.com/NodeOps-app/createos-sandbox/internal/scheduler/client"
	"github.com/NodeOps-app/createos-sandbox/internal/storage"
	"github.com/NodeOps-app/createos-sandbox/models"
)

type okResp struct {
	OK bool `json:"ok"`
}

// PubkeyInvalidator is the narrow slice of the host pubkey cache the
// handlers need. *cache.HostPubkeys satisfies it. Declared as an
// interface here so the handlers package does not import internal/apiserver
// (which would create an import cycle).
type PubkeyInvalidator interface {
	Invalidate(hostID string)
}

// Quotas — DEPRECATED shape kept for backwards compat with any external
// consumers. The control plane no longer threads this directly into the
// handler; per-user caps are now resolved through LimitsProvider with
// the precedence documented in limits.go (operator override > createos
// plan > static default). Operators wire static defaults + the override
// maps into a *LimitsCache at startup; the handler reads only Limits.
type Quotas struct {
	SandboxConcurrent  int
	SandboxPerDay      int
	NetworkConcurrent  int
	DiskConcurrent     int
	DiskPerDay         int
	TemplateConcurrent int
	TemplatePerDay     int

	SandboxConcurrentOverrides  map[string]int
	SandboxPerDayOverrides      map[string]int
	NetworkConcurrentOverrides  map[string]int
	DiskConcurrentOverrides     map[string]int
	DiskPerDayOverrides         map[string]int
	TemplateConcurrentOverrides map[string]int
	TemplatePerDayOverrides     map[string]int
}

// Handler carries every dependency the control-plane HTTP handlers use.
// Constructed by NewHandler from the server's Deps.
type Handler struct {
	adminEmailMu sync.RWMutex
	adminEmails  map[string]string
	repo         *models.Repo
	http         *http.Client
	hostPubkeys  PubkeyInvalidator
	resolver     *userapikey.Cache
	apiKeyHasher *userapikey.Hasher // hashes user credentials before database lookups
	region       string
	// limits resolves the effective per-user policy with the
	// precedence operator-override > createos > static-default. Each
	// create handler calls h.limits.Get(ctx, userID, isInternal) once
	// and treats the result as a snapshot for the rest of the request.
	limits              LimitsProvider
	ingressDomainSuffix string
	schedulerClient     *schedclient.Client
	storage             storage.Storage
	// hostStorage is the raw S3 config relayed verbatim to hosts in the
	// register response. Hosts use it to construct their own object-storage client
	// for pause/resume + template fetches, so they don't need to carry
	// credentials in their serve.yaml. Single source of truth lives in
	// control's `storage:` block.
	hostStorage config.StorageConfig
	buildlogs   *clickhouse.Client
	diskCipher  *diskcrypto.Cipher
	// billingEmitter records billing_events rows atomically with the
	// caller's status-mutation tx. Always emits when non-nil; internal
	// users get an internal_skip stamp inside the same tx so the worker
	// skips delivery. nil-safe: every Mark* function tolerates a nil
	// emitter and simply skips emit (the status flip still commits).
	billingEmitter *billingemit.Emitter
	// audit emits user-facing lifecycle events to the audit_events
	// outbox. Wired via SetAudit() after construction; nil-safe (every
	// Emit on a nil emitter is a no-op).
	audit audit.Emitter
	// relayCrossRegionFallback flips the device-session-create picker
	// from strict in-region to any-region (preferring same). Set via
	// SetRelayCrossRegionFallback from the control startup wiring.
	relayCrossRegionFallback bool
	// deviceRegistrationDisabled gates only POST /v1/devices. Its zero value
	// preserves the historical behaviour for embedded/test construction.
	deviceRegistrationDisabled bool
	// defaultBandwidthQuotaBytes is the cluster's bandwidth default
	// applied at create time when the request omits (or sends 0)
	// bandwidth_quota_bytes. Source of truth lives in ControlConfig.
	defaultBandwidthQuotaBytes int64

	// hostScheme is the URL scheme control uses when dialing hosts —
	// "http" when running plaintext, "https" when control is configured
	// for mTLS (so the outbound client transport actually executes the
	// TLS handshake). Wired by NewHandler from TLS paths.
	hostScheme string

	// peerControls maps region name → peer control plane base URL for
	// cross-region create/resume/fork forwarding. Each region's control
	// owns its scheduler; the scheduler's in-process reservation state
	// can't be safely shared, so cross-region requests forward to the
	// owning region's control instead of scheduling against remote hosts.
	// Empty map = single-region deployment (no cross-region forwarding).
	peerControls map[string]string

	// peerHTTPClient is the http.Client used for cross-region forwarding
	// to peerControls URLs. Distinct from h.http (which carries the
	// cluster-CA mTLS bundle for host/scheduler dials) — peer URLs
	// point at peer controls' PUBLIC endpoints, which serve real
	// public-CA certs (Let's Encrypt / CF Universal SSL / etc.). This
	// client uses Go's default transport so system roots verify those
	// certs. Auth between controls is the user's API key relayed in the
	// request header, not the TLS layer.
	peerHTTPClient *http.Client

	// createos is the outbound credit-API client. Nil/disabled = no
	// auto-top-up — the meter's hard cap kicks in as today.
	createos                *createos.Client
	autoTopupThresholdBytes int64         // remaining < this triggers a top-up
	autoTopupGiB            float64       // recharge size in GiB per trigger
	autoTopupCooldown       time.Duration // suppress retries for this long after the last attempt
	// autoTopupLast tracks the last attempt timestamp per user_id so
	// rapid meter PATCHes (every ~5s) don't fire concurrent recharges
	// before the previous one's quota bump has landed.
	autoTopupLast sync.Map // map[userID]time.Time

	// ca is the in-process certificate authority used to issue leaf
	// certs to hosts and non-host actors over the mTLS bootstrap
	// endpoints. Nil = mTLS disabled; cert endpoints return 503.
	ca *ca.CA

	// shapes is the cluster's VM shape catalog provider. Pushed to every
	// host on register + heartbeat and served by /v1/shapes. The
	// concrete implementation (*cache.Shapes) reads from the
	// shapes DB table with a TTL cache.
	shapes ShapesProvider

	// pool is the resolved predictive pre-warm sandbox pool config.
	// Wired via SetPool(); disabled/zero-value = the pool fast path
	// is a no-op (matchesPool short-circuits at cfg.Enabled=false).
	pool config.PoolConfig

	// claimBatcher coalesces concurrent pool claims into one DB tx.
	// Non-nil only when pool.ClaimBatch is set; tryClaimFromPool routes
	// through it when present, else uses the inline per-request claim.
	claimBatcher *poolClaimBatcher

	// hostCache short-circuits the per-request Repo.GetHost round-trip
	// on the exec/delete/bandwidth/metrics forward path. TTL=5s matches
	// the heartbeat cadence; HandleHostHeartbeat invalidates on write
	// so status changes propagate immediately. Never nil after
	// NewHandler runs (constructed with a default 5s TTL).
	hostCache *cache.Hosts

	// rootfsCache short-circuits the two DB reads (ListHosts +
	// ListRootfsMetadata) that clusterRootfsUnion does on every create.
	// Under N=100 burst those cost ~10ms p50 / ~80ms p99 per create.
	// The union changes on host restart / operator deprecation cadence
	// (minutes-to-days), so a 30s TTL is safe. Templates are excluded
	// by contract — see the SAFETY note in cache/rootfs.go.
	// Never nil after NewHandler runs.
	rootfsCache *cache.Rootfs

	// Screenshot responses are buffered by the generic host-forwarding path.
	// Keep the aggregate control-plane memory bound independent of host count.
	computerOnce        sync.Once
	computerMu          sync.Mutex
	computerScreenshots map[string]struct{}
	computerSlots       chan struct{}
}

// getHostCached wraps Repo.GetHost with a TTL cache to save the DB
// round-trip on hot forward paths. On miss/stale it fetches from DB,
// caches, returns. Errors bypass the cache entirely.
func (h *Handler) getHostCached(ctx context.Context, id string) (*models.Host, error) {
	if h.hostCache != nil {
		if hh, ok := h.hostCache.Get(id); ok {
			return hh, nil
		}
	}
	hh, err := h.repo.GetHost(ctx, id)
	if err != nil {
		return nil, err
	}
	if hh != nil && h.hostCache != nil {
		h.hostCache.Put(id, hh)
	}
	return hh, nil
}

// SetPool installs the predictive pre-warm pool config. Called once by
// the control server during construction. Disabled pool = no-op fast
// path; the create handler still falls through to the normal flow.
func (h *Handler) SetPool(p config.PoolConfig) {
	h.pool = p
	if p.Enabled && poolClaimBatchEnabled && h.claimBatcher == nil {
		h.claimBatcher = newPoolClaimBatcher(h)
	}
}

// SetShapes installs the shape-catalog provider. Called once by the
// control server during construction.
func (h *Handler) SetShapes(s ShapesProvider) { h.shapes = s }

// SetHostStorage installs the storage config relayed to hosts in the
// register response. Called once at control startup; hosts that
// re-register pick up rotated values without a control restart.
func (h *Handler) SetHostStorage(s config.StorageConfig) { h.hostStorage = s }

// SetPeerControls installs the region → peer-control-URL map for
// cross-region request forwarding. Called once at control startup.
// Initializes the peer http.Client with system root CAs (peer URLs
// are public endpoints, not mTLS-protected inner endpoints).
func (h *Handler) SetPeerControls(m map[string]string) {
	h.peerControls = m
	h.peerHTTPClient = &http.Client{Timeout: 30 * time.Second}
}

// SetCA installs the optional in-process CA used by the mTLS bootstrap
// endpoints. Called by the control-plane wiring layer after handler
// construction; nil = mTLS disabled.
func (h *Handler) SetCA(c *ca.CA) { h.ca = c }

func (h *Handler) SetAudit(e audit.Emitter) { h.audit = e }

// SetRelayCrossRegionFallback enables the fallback that lets device
// session create pick a relay from any region when the caller's region
// has none. Off by default. See ControlConfig.RelayCrossRegionFallback.
func (h *Handler) SetRelayCrossRegionFallback(v bool) { h.relayCrossRegionFallback = v }

// SetDeviceRegistrationDisabled temporarily pauses new device registrations
// without affecting existing devices or VPN sessions.
func (h *Handler) SetDeviceRegistrationDisabled(v bool) { h.deviceRegistrationDisabled = v }

// NewHandler constructs a Handler from the control plane's dependencies.
func NewHandler(
	repo *models.Repo,
	httpClient *http.Client,
	hostPubkeys PubkeyInvalidator,
	resolver *userapikey.Cache,
	apiKeyHasher *userapikey.Hasher,
	region string,
	limits LimitsProvider,
	ingressDomainSuffix string,
	billingEmitter *billingemit.Emitter,
	schedulerClient *schedclient.Client,
	storage storage.Storage,
	buildlogs *clickhouse.Client,
	diskCipher *diskcrypto.Cipher,
	defaultBandwidthQuotaBytes int64,
	createosClient *createos.Client,
	autoTopupThresholdBytes int64,
	autoTopupGiB float64,
	hostScheme string,
) *Handler {
	if hostScheme == "" {
		hostScheme = "http"
	}
	return &Handler{
		repo:                       repo,
		http:                       httpClient,
		hostPubkeys:                hostPubkeys,
		resolver:                   resolver,
		apiKeyHasher:               apiKeyHasher,
		region:                     region,
		limits:                     limits,
		ingressDomainSuffix:        ingressDomainSuffix,
		billingEmitter:             billingEmitter,
		schedulerClient:            schedulerClient,
		storage:                    storage,
		buildlogs:                  buildlogs,
		diskCipher:                 diskCipher,
		defaultBandwidthQuotaBytes: defaultBandwidthQuotaBytes,
		createos:                   createosClient,
		autoTopupThresholdBytes:    autoTopupThresholdBytes,
		autoTopupGiB:               autoTopupGiB,
		autoTopupCooldown:          30 * time.Second,
		hostScheme:                 hostScheme,
		audit:                      audit.Noop{},
		hostCache:                  cache.NewHosts(5 * time.Second),
		rootfsCache:                cache.NewRootfs(30 * time.Second),
	}
}

// HostScheme is the URL scheme control uses for outbound host RPCs
// ("http" or "https"). Read by forward / net-reconcile helpers.
func (h *Handler) HostScheme() string { return h.hostScheme }

// hostScheme returns the URL scheme control uses for outbound host RPCs.
// Set once at startup by SetHostScheme; standalone helpers (ForwardResponseTo,
// kickHostNetReconciler) read it. Defaults to "http".
var pkgHostScheme = "http"

func hostScheme() string { return pkgHostScheme }

// SetHostScheme is invoked once during control startup based on TLS paths.
func SetHostScheme(s string) {
	if s != "" {
		pkgHostScheme = s
	}
}
