package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rgurov/pgerrors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"

	"github.com/NodeOps-app/sandbox/internal/apiserver/cache"
	"github.com/NodeOps-app/sandbox/internal/apiserver/metrics"
	"github.com/NodeOps-app/sandbox/internal/apiserver/middlewares"
	"github.com/NodeOps-app/sandbox/internal/audit"
	"github.com/NodeOps-app/sandbox/internal/hostrpc"
	"github.com/NodeOps-app/sandbox/internal/hosts/api"
	"github.com/NodeOps-app/sandbox/internal/hosts/vm"
	"github.com/NodeOps-app/sandbox/internal/httpx"
	"github.com/NodeOps-app/sandbox/internal/httpx/types"
	"github.com/NodeOps-app/sandbox/internal/placementpolicy"
	"github.com/NodeOps-app/sandbox/internal/proto"
	"github.com/NodeOps-app/sandbox/internal/requestctx"
	schedapi "github.com/NodeOps-app/sandbox/internal/scheduler/api"
	schedclient "github.com/NodeOps-app/sandbox/internal/scheduler/client"
	"github.com/NodeOps-app/sandbox/internal/storage"
	"github.com/NodeOps-app/sandbox/internal/trace"
	"github.com/NodeOps-app/sandbox/internal/utils"
	"github.com/NodeOps-app/sandbox/models"
)

type patchSandboxReq struct {
	IngressEnabled        *bool             `json:"ingress_enabled,omitempty"`
	AutoPauseAfterSeconds *int              `json:"auto_pause_after_seconds,omitempty"`
	DisableAutoPause      bool              `json:"disable_auto_pause,omitempty"`
	Labels                map[string]string `json:"labels,omitempty"`
}

type addSSHPubkeyReq struct {
	Keys []string `json:"keys"`
}

type addSSHPubkeyResp struct {
	Count int `json:"count"`
}

type whoAmIView struct {
	UserID string          `json:"user_id"`
	Stats  whoAmIStatsView `json:"stats"`
}

type whoAmIStatsView struct {
	Running int `json:"running"`
	Paused  int `json:"paused"`
	Other   int `json:"other"`
	Total   int `json:"total"`
}

type egressPresetsView struct {
	Version string              `json:"version"`
	Presets map[string][]string `json:"presets"`
}

type idsResp struct {
	IDs []string `json:"ids"`
}

type gatewaySandboxView struct {
	ID         string   `json:"id"`
	IP         string   `json:"ip"`
	HostID     string   `json:"host_id"`
	SSHPubkeys []string `json:"ssh_pubkeys"`
	CreatedBy  string   `json:"created_by"`
	Status     string   `json:"status"`
}

type createRespEnvelope struct {
	Status string         `json:"status"`
	Data   api.CreateResp `json:"data"`
}

type sshPubkeysProjection struct {
	SSHPubkeys []string `json:"ssh_pubkeys,omitempty"`
}

type execStreamProjection struct {
	Stream bool `json:"stream"`
}

type rootfsDefaultView struct {
	Default string `json:"default"`
}

type rootfsDefaultEnvelope struct {
	Status string            `json:"status"`
	Data   rootfsDefaultView `json:"data"`
}

// handleControlReadyz reports whether this control instance is ready to
// accept user traffic. In external scheduler mode, an unhealthy
// SchedulerClient drops this control out of the LB rotation immediately —
// no point accepting creates that would just retry-and-fail.
func (h *Handler) HandleControlReadyz(c *fiber.Ctx) error {
	if h.schedulerClient != nil && !h.schedulerClient.Healthy() {
		snap := h.schedulerClient.HealthSnapshot()
		return httpx.Fail(c, fiber.StatusServiceUnavailable, proto.ReadyzResp{
			Ready:                false,
			Reason:               "scheduler unreachable",
			SchedulerLastOkMsAgo: snap.LastOkMsAgo,
		})
	}
	return httpx.Success(c, proto.ReadyzResp{Ready: true})
}

func (h *Handler) DbInsertSandbox(c *fiber.Ctx) error {
	var rec models.Sandbox
	if err := c.BodyParser(&rec); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if rec.ID == "" || rec.HostID == nil || *rec.HostID == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "missing sandbox or host id")
	}
	if rec.Status != models.StatusRunning {
		return httpx.Fail(c, fiber.StatusBadRequest, "status must be running")
	}
	transitioned, err := h.repo.CompleteSandboxCreate(c.UserContext(), rec, *rec.HostID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if !transitioned {
		// A lost response may cause the host to retry after the first request
		// already committed. Treat that exact state as idempotent success, but
		// reject missing, cross-host, or otherwise invalid transitions.
		existing, getErr := h.repo.Get(c.UserContext(), rec.ID)
		if getErr != nil {
			log.WithContext(c.UserContext()).Errorf("[handler] sandbox completion lookup: %v", getErr)
			return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
		}
		if existing == nil || existing.HostID == nil || *existing.HostID != *rec.HostID ||
			existing.Status != models.StatusRunning {
			return httpx.Fail(c, fiber.StatusConflict, "sandbox cannot be completed")
		}
	} else {
		h.emitBillingEvent(c.UserContext(), rec.ID, models.BillingEventSandboxRunning, string(models.StatusCreating))
	}
	return httpx.Success(c, proto.NewIDResp(rec.ID))
}

func (h *Handler) DbGetSandbox(c *fiber.Ctx) error {
	rec, err := h.repo.Get(c.UserContext(), c.Params(middlewares.ParamSandboxID))
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if role, _ := c.Locals(middlewares.MTLSRoleLocalsKey).(string); role == "gateway" {
		ip, hostID := "", ""
		if rec.IP != nil {
			ip = *rec.IP
		}
		if rec.HostID != nil {
			hostID = *rec.HostID
		}
		return httpx.Success(c, gatewaySandboxView{
			ID: rec.ID, IP: ip, HostID: hostID, SSHPubkeys: rec.SSHPubkeys,
			CreatedBy: rec.CreatedBy, Status: string(rec.Status),
		})
	}
	return httpx.Success(c, rec)
}

func (h *Handler) DbGetSandboxByIP(c *fiber.Ctx) error {
	rec, err := h.repo.GetByIP(c.UserContext(), c.Params(middlewares.ParamIP))
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "no sandbox with this ip")
	}
	// Per-host scoping: a `host`-role caller may only look up IPs that
	// belong to its own host. Without this, a compromised host could
	// enumerate the fleet by walking the IP range. Pass-through for
	// gateway (cluster-wide router, no host id on its SPIFFE leaf).
	// host-proxy reuses the host's cert so it's covered by this gate.
	if callerHost := middlewares.CallerHostIfHostRole(c); callerHost != "" {
		recHost := ""
		if rec.HostID != nil {
			recHost = *rec.HostID
		}
		if recHost != callerHost {
			// 404 (not 403) so the caller can't distinguish
			// "wrong host" from "no such IP" via the response.
			return httpx.Fail(c, fiber.StatusNotFound, "no sandbox with this ip")
		}
	}
	// Return the narrow {id, ip, egress} projection the proxy needs for
	// egress attribution — not the full sandbox row.
	ipStr := ""
	if rec.IP != nil {
		ipStr = *rec.IP
	}
	return httpx.Success(c, proto.SandboxByIP{
		ID:     rec.ID,
		IP:     ipStr,
		Egress: rec.Egress,
	})
}

func (h *Handler) DbListSandboxes(c *fiber.Ctx) error {
	host := c.Query("host", "")
	userID := c.Query("user_id", "")
	status := c.Query("status", "")
	limit := c.QueryInt("limit", 50)
	recs, err := h.repo.List(c.UserContext(), host, userID, status, limit)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if recs == nil {
		recs = []models.Sandbox{}
	}
	return httpx.Success(c, recs)
}

func (h *Handler) DbMarkDestroyed(c *fiber.Ctx) error {
	var r proto.ControlMarkDestroyedReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	id := c.Params(middlewares.ParamSandboxID)
	if err := h.repo.MarkDestroyed(c.UserContext(), id, r.At, r.Note, h.billingEmitter); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	// MarkDestroyed now emits the billing event atomically inside its tx.
	return httpx.Success(c, proto.NewIDResp(id))
}

func (h *Handler) DbMarkFailed(c *fiber.Ctx) error {
	var r proto.ControlMarkFailedReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	id := c.Params(middlewares.ParamSandboxID)
	if err := h.repo.MarkFailed(c.UserContext(), id, r.ErrText, r.At, h.billingEmitter); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	// MarkFailed now emits the billing event atomically inside its tx.
	return httpx.Success(c, proto.NewIDResp(id))
}

// DbMarkFailedFromCreatingCAS handles the host-reconcile self-heal
// path: atomically flip a row from 'creating' → 'failed' iff the row's
// host_id matches the body's HostID. The route is also gated by
// MustBeOwningHost so a compromised host can't fail another host's
// rows; the SQL CAS is defense-in-depth.
func (h *Handler) DbMarkFailedFromCreatingCAS(c *fiber.Ctx) error {
	var r proto.ControlMarkFailedFromCreatingCASReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	id := c.Params(middlewares.ParamSandboxID)
	flipped, err := h.repo.MarkFailedFromCreatingCAS(c.UserContext(), id, r.HostID, r.ErrText, r.At, h.billingEmitter)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.ControlMarkFailedFromCreatingCASResp{Flipped: flipped})
}

func (h *Handler) DbSetSandboxHost(c *fiber.Ctx) error {
	var r proto.ControlSetSandboxHostReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if err := h.repo.SetSandboxHost(c.UserContext(), c.Params(middlewares.ParamSandboxID), r.HostID); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.NewIDResp(c.Params(middlewares.ParamSandboxID)))
}

func (h *Handler) DbSetSSHPubkeys(c *fiber.Ctx) error {
	var r proto.ControlSetSSHPubkeysReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if err := h.repo.SetSSHPubkeys(c.UserContext(), c.Params(middlewares.ParamSandboxID), r.Keys); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.NewIDResp(c.Params(middlewares.ParamSandboxID)))
}

func (h *Handler) DbSetEgress(c *fiber.Ctx) error {
	var r proto.ControlSetEgressReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if err := h.repo.SetEgress(c.UserContext(), c.Params(middlewares.ParamSandboxID), r.Rules); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.NewIDResp(c.Params(middlewares.ParamSandboxID)))
}

func (h *Handler) DbSetDiskMib(c *fiber.Ctx) error {
	var r proto.ControlSetDiskMibReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if err := h.repo.SetDiskMib(c.UserContext(), c.Params(middlewares.ParamSandboxID), r.DiskMib); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.NewIDResp(c.Params(middlewares.ParamSandboxID)))
}

func (h *Handler) DbSetRuntime(c *fiber.Ctx) error {
	var r proto.ControlSetRuntimeReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if err := h.repo.SetRuntime(c.UserContext(), c.Params(middlewares.ParamSandboxID), r.APISock, r.ContainerID, r.OverlayPath, r.FCPid); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.NewIDResp(c.Params(middlewares.ParamSandboxID)))
}

// DbSetSandboxDiskStatus handles PATCH /v1/internal/db/sandboxes/:id/disks/:disk/status.
// Owner gate (host-issued JWT must match the sandbox's host_id) is
// applied at the route layer, same as other write endpoints.

func (h *Handler) DbSetBandwidthQuota(c *fiber.Ctx) error {
	var r proto.ControlBandwidthValueReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if err := h.repo.SetBandwidthQuota(c.UserContext(), c.Params(middlewares.ParamSandboxID), r.Value); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.NewIDResp(c.Params(middlewares.ParamSandboxID)))
}

func (h *Handler) DbSetBandwidthUsed(c *fiber.Ctx) error {
	var r proto.ControlBandwidthValueReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	sandboxID := c.Params(middlewares.ParamSandboxID)
	if err := h.repo.SetBandwidthUsed(c.UserContext(), sandboxID, r.Value); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	// Fire-and-forget: if remaining quota has dipped below the
	// configured threshold, try to debit credits from createos and
	// bump the quota. Best-effort; failures are logged.
	h.maybeAutoTopup(sandboxID, r.Value)
	return httpx.Success(c, proto.NewIDResp(sandboxID))
}

func (h *Handler) DbSetBandwidthCapped(c *fiber.Ctx) error {
	var r proto.ControlBandwidthCappedReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if err := h.repo.SetBandwidthCapped(c.UserContext(), c.Params(middlewares.ParamSandboxID), r.Value); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.NewIDResp(c.Params(middlewares.ParamSandboxID)))
}

func (h *Handler) DbSetIngressEnabled(c *fiber.Ctx) error {
	var r proto.ControlSetIngressEnabledReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if err := h.repo.SetIngressEnabled(c.UserContext(), c.Params(middlewares.ParamSandboxID), r.Enabled); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.NewIDResp(c.Params(middlewares.ParamSandboxID)))
}

func (h *Handler) DbUpdateBandwidthIngress(c *fiber.Ctx) error {
	var r proto.ControlBandwidthValueReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if err := h.repo.UpdateBandwidthIngress(c.UserContext(), c.Params(middlewares.ParamSandboxID), r.Value); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.NewIDResp(c.Params(middlewares.ParamSandboxID)))
}

func (h *Handler) DbGetIngressRoute(c *fiber.Ctx) error {
	return h.getIngressRoute(c)
}

// HandleInternalIngressRoute serves the public ingress process a narrow
// routing projection. Route middleware restricts this handler to an
// ingress-role mTLS peer; no sandbox owner or secret fields are returned.
func (h *Handler) HandleInternalIngressRoute(c *fiber.Ctx) error {
	return h.getIngressRoute(c)
}

func (h *Handler) getIngressRoute(c *fiber.Ctx) error {
	route, err := h.repo.GetIngressRoute(c.UserContext(), c.Params(middlewares.ParamSandboxID))
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if route.ID == "" {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	return httpx.Success(c, proto.ControlIngressRouteResp{
		ID:              route.ID,
		HostAddr:        route.HostAddr,
		Status:          route.Status,
		IngressEnabled:  route.IngressEnabled,
		Region:          route.Region,
		BandwidthCapped: route.BandwidthCapped,
	})
}

func (h *Handler) DbListRunningIDs(c *fiber.Ctx) error {
	host := c.Query("host")
	ids, err := h.repo.ListRunningIDs(c.UserContext(), host)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, idsResp{IDs: ids})
}

func (h *Handler) DbListLiveIDs(c *fiber.Ctx) error {
	host := c.Query("host")
	ids, err := h.repo.ListLiveIDs(c.UserContext(), host)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, idsResp{IDs: ids})
}

// handleSchedulerHealth is the operator-facing snapshot of the scheduler
// client's atomics. Cluster-token gated so internal callers (dashboards,
// createos-cli) can hit it without user auth.
func (h *Handler) HandleSchedulerHealth(c *fiber.Ctx) error {
	if h.schedulerClient == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "external scheduler not configured")
	}
	return httpx.Success(c, h.schedulerClient.HealthSnapshot())
}

// ---- user-facing handlers ----

func (h *Handler) HandleCreate(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	t := trace.Start("create").WithObserver(func(name string, d time.Duration) {
		metrics.CreatePhaseSeconds.WithLabelValues(name).Observe(d.Seconds())
	})
	t.Attr("rid", httpx.RequestID(c.UserContext()))
	defer t.End()
	stopPreflight := t.Phase("preflight")
	// Only catalog shapes become metric labels, including on rejected requests.
	// Unrecognized input stays "unknown" to keep series cardinality bounded.
	tCreate := time.Now()
	shapeLabel := "unknown"
	poolHit := false
	// Per-stage timestamps for burst diagnostics. Each is set once at the
	// end of its stage; zero = the request short-circuited earlier. Deltas
	// are printed in the deferred log so we can see where time actually
	// goes at N-parallel without needing pg_stat_statements or pprof.
	//
	// Stages (in call order):
	//   parse  = HTTP body parse + shape lookup
	//   auth   = API-key hash + LookupAPIKeyByHash + limits.Get + quota check
	//     split into: authKey (apikey lookup) → authLim (limits.Get) →
	//     authQuota (concurrency + shape allowlist + disk-cap gate)
	//   rootfs = rootfs catalog union + disabled check
	//   shape  = shape → (mem,vcpu,disk) resolve
	//   pool   = tryClaimFromPool round trip (pool_hit only)
	//   fwd    = normal-path scheduler + host forward (pool_miss only)
	var tParse, tAuthKey, tAuthLimits, tAuth, tRootfs, tShape, tPool, tFwd time.Time
	defer func() {
		dur := time.Since(tCreate)
		metrics.CreateSeconds.
			WithLabelValues(
				shapeLabel,
				metrics.StatusClass(c.Response().StatusCode()),
				metrics.Country(clientIP(c)),
			).
			Observe(dur.Seconds())
		// Burst diagnostic: log EVERY create with per-stage deltas so we
		// can build a real histogram of where wall-clock goes at N=100.
		// One-line per request; log volume is manageable and rotates
		// fast. Missing stages print as "-" (short-circuit path).
		fmtMs := func(t time.Time, ref time.Time) string {
			if t.IsZero() || ref.IsZero() {
				return "-"
			}
			return fmt.Sprintf("%d", t.Sub(ref).Milliseconds())
		}
		log.WithContext(c.UserContext()).Infof("[create-stages] wall=%dms parse=%s authKey=%s authLim=%s authQuota=%s rootfs=%s shape=%s pool=%s fwd=%s shape_id=%s status=%d pool_hit=%v rid=%s",
			dur.Milliseconds(),
			fmtMs(tParse, tCreate),
			fmtMs(tAuthKey, tParse),
			fmtMs(tAuthLimits, tAuthKey),
			fmtMs(tAuth, tAuthLimits),
			fmtMs(tRootfs, tAuth),
			fmtMs(tShape, tRootfs),
			fmtMs(tPool, tShape),
			fmtMs(tFwd, tShape),
			shapeLabel, c.Response().StatusCode(), poolHit, c.Locals("requestid"))
	}()

	var req api.CreateReq
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	// Resolved credentials are produced only after control checks disk ownership.
	if len(req.DisksResolved) != 0 {
		return httpx.Fail(c, fiber.StatusBadRequest, types.FieldError{
			"disks_resolved": "internal field; use disks to reference an owned disk",
		})
	}
	if !utils.IsInternalFromContext(c.UserContext()) {
		placementErrors := types.FieldError{}
		if len(req.NodeSelector) > 0 {
			placementErrors["node_selector"] = "requires an internal API key"
		}
		if strings.TrimSpace(req.HostID) != "" {
			placementErrors["host_id"] = "requires an internal API key"
		}
		if len(placementErrors) > 0 {
			return httpx.Fail(c, fiber.StatusForbidden, placementErrors)
		}
	}
	expandedEgress, err := expandEgressPresets(req.Egress)
	if err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, err.Error())
	}
	req.Egress = expandedEgress
	// Rootfs must be explicit. Letting the host resolve an omitted value to
	// its local default makes create succeed while control persists NULL;
	// pause/resume later has no durable rootfs identity and fails trying to
	// restore rootfs "". Control validates the supplied catalog name below.
	if req.Rootfs == nil || strings.TrimSpace(*req.Rootfs) == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, types.FieldError{
			"rootfs": "rootfs is required; choose a value from GET /v1/rootfs",
		})
	}
	shapeCat := h.shapes.Shapes(c.UserContext())
	for _, sh := range shapeCat {
		if sh.ID == req.Shape {
			shapeLabel = sh.ID
			break
		}
	}
	tParse = time.Now()
	if req.Shape == "" {
		return httpx.Fail(c, fiber.StatusBadRequest,
			types.UnknownShape{Shape: "required", Choices: vm.NewCatalog(shapeCat).IDs()})
	}
	// Bandwidth quota policy: not user-settable at create. Every new
	// sandbox gets the cluster default; growing the budget happens via
	// POST /v1/sandboxes/:id/bandwidth/recharge. Reject any non-zero
	// value at the boundary so clients don't silently get the default
	// when they think they're requesting something else.
	if req.BandwidthQuotaBytes != 0 {
		return httpx.Fail(c, fiber.StatusBadRequest,
			"bandwidth_quota_bytes is not settable at create; use POST /v1/sandboxes/:id/bandwidth/recharge to grow the quota")
	}
	// Operator-owned placement policy overrides the requested region for new
	// sandboxes. It is keyed by the authenticated user and is never populated
	// from the public request body.
	var fallback *api.CreateReq
	if target := h.createFallbackTarget(utils.UserID(c), &req); target != "" {
		original := req
		original.Region = target
		fallback = &original
	}
	req.Region = placementpolicy.RegionForNewSandbox(utils.UserID(c), req.Region)
	// Region: default to this control's region when the caller omits one.
	// Cross-region requests forward to the owning region's control — its
	// scheduler is authoritative for its own host inventory. Scheduling
	// locally against a remote region would double-spend reservations
	// (each region's InMemReserver is process-local; only durable rows
	// replicate asynchronously, and a sub-second window exists between
	// reserve and row-commit where the foreign scheduler can't see it).
	req.Region = strings.TrimSpace(req.Region)
	if req.Region == "" {
		req.Region = h.region
	}
	switch req.Region {
	case models.EuropeRegion, models.UnitedStatesRegion:
	default:
		return httpx.Fail(c, fiber.StatusBadRequest,
			types.FieldError{"region": "unknown region"})
	}
	if req.Region != h.region {
		// Forward the normalized request rather than the original body so the
		// peer validates and schedules the same region value. Keep the bandwidth
		// quota at zero here: it is not client-settable, and stamping our default
		// before forwarding makes the destination reject it as caller input.
		if body, marshalErr := json.Marshal(&req); marshalErr == nil {
			c.Request().SetBody(body)
		}
		return h.forwardToPeerControl(c, req.Region, c.Method(), c.Path())
	}
	// The authoritative destination region stamps its own cluster default only
	// after cross-region forwarding has finished.
	req.BandwidthQuotaBytes = h.defaultBandwidthQuotaBytes
	// Validate envs server-side before any forwarding/scheduling. Keep limits
	// tight (64 keys, POSIX-style names, no NUL, 4 KiB per value, 64 KiB
	// total) so a hostile create can't blow up downstream JSON encoders or
	// the agent's process env.
	if _, msg := validateEnvs(req.Envs); msg != "" {
		return httpx.Fail(c, fiber.StatusBadRequest, msg)
	}
	if _, msg := validateLabels(req.Labels); msg != "" {
		return httpx.Fail(c, fiber.StatusBadRequest, msg)
	}
	// Validate + canonicalize ssh_pubkeys up front. ssh.ParseAuthorizedKey
	// is forgiving (accepts trailing comments, options, etc.); we round-trip
	// each entry through ssh.MarshalAuthorizedKey so the value stored in
	// the DB and shipped to the gateway is `<type> <base64>` only — no
	// comment fields that could mask a newline-injected second entry and
	// no options like `command=...` that change SSH semantics in the
	// gateway. Same canonicalization the PATCH /v1/sandboxes/:id/ssh-pubkeys
	// path does — kept in sync via canonicalizeSSHPubkeys.
	if rawKeys := extractSSHPubkeys(&req); len(rawKeys) > 0 {
		canon, badIdx, perr := canonicalizeSSHPubkeys(rawKeys)
		if perr != nil {
			return httpx.Fail(c, fiber.StatusBadRequest,
				fmt.Sprintf("ssh_pubkeys[%d]: %v", badIdx, perr))
		}
		setCanonicalSSHPubkeys(&req, canon)
	}
	// Reject malformed network entries up front. An entry with an empty id
	// (e.g. a client that sent {"name":...} instead of {"id":...}) would
	// otherwise be silently skipped by attachNetworks, leaving the sandbox
	// unexpectedly off the network.
	for _, ne := range req.Networks {
		if ne.ID == "" {
			return httpx.Fail(c, fiber.StatusBadRequest,
				"is required")
		}
	}
	// Pre-validate disk attachments. Owner-mismatch returns 404 (no
	// existence leak); shape errors return 400. Defer the decryption +
	// row inserts until after the durable sandbox row exists.
	if len(req.Disks) > 0 {
		if h.diskCipher == nil {
			return httpx.Error(c, fiber.StatusServiceUnavailable, "disks API not configured")
		}
		if len(req.Disks) > maxDisksPerSandbox {
			return httpx.Fail(c, fiber.StatusBadRequest,
				fmt.Sprintf("too many disks: %d (max %d per sandbox)",
					len(req.Disks), maxDisksPerSandbox))
		}
		seenPaths := make(map[string]struct{}, len(req.Disks))
		for i, da := range req.Disks {
			if strings.TrimSpace(da.DiskID) == "" {
				return httpx.Fail(c, fiber.StatusBadRequest, "disks[].disk_id is required")
			}
			cleaned, err := validateMountPath(da.MountPath)
			if err != nil {
				return httpx.Fail(c, fiber.StatusBadRequest,
					fmt.Sprintf("disks[%d].mount_path: %s", i, err.Error()))
			}
			// Persist the normalized path so `//foo` and `/foo` both
			// collapse to `/foo` for the unique-index collision check
			// (sandbox_id, mount_path).
			req.Disks[i].MountPath = cleaned
			if _, dup := seenPaths[cleaned]; dup {
				return httpx.Fail(c, fiber.StatusBadRequest,
					fmt.Sprintf("mount_path %q used by multiple disks", cleaned))
			}
			seenPaths[cleaned] = struct{}{}
		}
	}
	// A user-supplied name becomes the VM's hostname and DNS label, so it
	// must be a valid DNS label. Empty = auto-generated (always valid).
	reqName := ""
	if req.Name != nil {
		reqName = *req.Name
	}
	if msg := validateSandboxName(reqName); msg != "" {
		return httpx.Fail(c, fiber.StatusBadRequest, msg)
	}
	// Validate auto_pause_after_seconds bounds: 60–86400 (1 min – 24 h).
	if req.AutoPauseAfterSeconds != nil {
		v := *req.AutoPauseAfterSeconds
		if v < 60 || v > 86400 {
			return httpx.Fail(c, fiber.StatusBadRequest,
				"auto_pause_after_seconds must be between 60 and 86400")
		}
	}
	// Per-user sandbox caps. Internal keys (operator-issued) bypass.
	var quotaUserID string
	{
		authType, token, hasAuth := middlewares.ExtractAuthToken(c)
		if !hasAuth {
			return httpx.Fail(c, fiber.StatusUnauthorized, "missing auth")
		}
		// Resolve the caller via the in-process api-key cache
		// (userapikey.Cache): 60s TTL, single-flight, negative caching,
		// invalidated on admin key create/revoke. Falls back to a direct
		// DB lookup when the cache isn't wired (test/bootstrap paths).
		//
		// Perf: under N=100 burst this eliminates the p99 tail on the
		// api-key lookup — previously ~150ms per pod's fresh miss went
		// straight to Postgres; now every cached hit is sub-millisecond.
		var userID string
		var isInternal bool
		if h.resolver != nil {
			var ok bool
			userID, isInternal, ok = h.resolver.Resolve(authType, token, nil)
			tAuthKey = time.Now()
			if !ok {
				return httpx.Fail(c, fiber.StatusUnauthorized, "unauthorized")
			}
		} else {
			keyRec, lookupErr := h.repo.LookupAPIKeyByHash(c.UserContext(), authType, h.apiKeyHasher.Hash(token))
			tAuthKey = time.Now()
			if lookupErr != nil {
				log.WithContext(c.UserContext()).Errorf("[quota] api-key lookup: %v", lookupErr)
				return httpx.Error(c, fiber.StatusServiceUnavailable, "internal error")
			}
			if keyRec == nil {
				return httpx.Fail(c, fiber.StatusUnauthorized, "unauthorized")
			}
			userID = keyRec.UserID
			isInternal = keyRec.IsInternal
		}
		quotaUserID = userID
		// One snapshot of the effective per-user policy for the whole
		// handler. The shape-allowlist + disk-size cap below reuse L
		// without a second cache lookup.
		L := h.limits.Get(c.UserContext(), userID, isInternal)
		tAuthLimits = time.Now()
		if !isInternal {
			// Credit gate. Block every create operation when the user's
			// balance is exhausted. createos disabled / outage falls
			// through with +Inf balance so this is a no-op in local-dev
			// and a fail-OPEN during transient upstream outages.
			if !L.HasCredit() {
				return httpx.Fail(c, fiber.StatusPaymentRequired,
					"insufficient credit; please top up to continue")
			}
			if status, msg, ok := h.checkSandboxConcurrencyQuotaFor(c, userID, L); !ok {
				if status >= 500 {
					return httpx.Error(c, status, msg)
				}
				return httpx.Fail(c, status, msg)
			}
			// Plan shape allowlist. Empty allowlist = no plan
			// restriction (every enabled catalog shape OK).
			if !L.IsShapeAllowed(req.Shape) {
				return httpx.Fail(c, fiber.StatusForbidden, types.FieldError{
					"shape": fmt.Sprintf("shape %q not allowed on your plan; choices: %v", req.Shape, L.AllowedShapes),
				})
			}
			// Plan disk-size ceiling. The static AllowedDiskSizesMib
			// menu is still enforced separately (10/20/.../60 GiB);
			// this gates the user's value below the plan's cap.
			if L.MaxDiskMib > 0 && req.DiskMib > L.MaxDiskMib {
				return httpx.Fail(c, fiber.StatusForbidden, types.FieldError{
					"disk_mib": fmt.Sprintf("disk_mib %d exceeds your plan's max of %d MiB", req.DiskMib, L.MaxDiskMib),
				})
			}
		}
	}
	tAuth = time.Now()

	// Resolve template names (or tpl_<ulid> direct reference) to their
	// canonical tpl_id BEFORE any catalog/scheduler logic runs. Templates
	// plug into the same code paths as catalog rootfses by sharing the
	// rootfs name.
	reqRootfs := ""
	if req.Rootfs != nil {
		reqRootfs = *req.Rootfs
	}
	// Rootfs resolution reordered to skip the per-create templates DB
	// lookup for names that are already known catalog rootfs. Under
	// N=100 burst, resolveSandboxRootfs did GetLatestReadyByName(userID,
	// name) even for "devbox:1" — 100 concurrent templates SELECTs
	// causing pgxpool contention → ~200ms tail on the rootfs stage.
	//
	// New order (each check is cheap when the previous one applies):
	//   1. Empty rootfs → host default (nothing to resolve).
	//   2. tpl_<ulid> prefix → user is directly referencing a template
	//      id → validate ownership + readiness via resolveSandboxRootfs.
	//   3. Name is in the cached catalog union → catalog rootfs. Skip
	//      templates DB entirely; no user template can shadow a catalog
	//      name because we validate the catalog membership below anyway.
	//   4. Otherwise → could be a user template NAME (mapped via
	//      GetLatestReadyByName) → resolveSandboxRootfs handles it.
	//
	// Steps 3+ share the same clusterRootfsUnion cache read; we fetch
	// (names, metaByName) once and reuse for the disabled check too.
	var catalogNames []string
	var catalogMeta map[string]models.RootfsCatalog
	if reqRootfs != "" && !strings.HasPrefix(reqRootfs, models.TemplateIDPrefix) {
		var err error
		catalogNames, catalogMeta, err = h.clusterRootfsUnion(c.UserContext())
		if err != nil {
			log.WithContext(c.UserContext()).Errorf("[create] rootfs catalog lookup failed: %v", err)
			return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
		}
	}
	inCatalog := false
	for _, n := range catalogNames {
		if n == reqRootfs {
			inCatalog = true
			break
		}
	}
	if userID := utils.UserID(c); userID != "" && reqRootfs != "" && !inCatalog {
		// Not a known catalog name: could be a tpl_ id or a template
		// name. Resolve through the templates path (DB lookup).
		resolved, status, fail := h.resolveSandboxRootfs(c.UserContext(), userID, reqRootfs)
		if status != 0 {
			return httpx.Fail(c, status, fail)
		}
		reqRootfs = resolved
		if resolved != "" {
			req.Rootfs = &resolved
		} else {
			req.Rootfs = nil
		}
	}

	// Validate rootfs against the cluster-wide catalog union BEFORE
	// forwarding to the scheduler. Without this, an unknown rootfs name
	// (typo like "devbox" vs "devbox:1") would only surface as a
	// scheduler 503 — a generic infra error that pages operators. The
	// real cause is a client typo and deserves a 400 with the catalog
	// so callers can self-correct. Empty rootfs falls through to the
	// host default; tpl_ ids bypass the catalog (scheduler resolves
	// them against the templates table).
	if reqRootfs != "" && !strings.HasPrefix(reqRootfs, models.TemplateIDPrefix) {
		if !inCatalog {
			// resolveSandboxRootfs may have turned a template NAME into
			// a tpl_ id; if we still don't recognise the name it's a
			// real typo.
			return httpx.Fail(c, fiber.StatusBadRequest, types.FieldError{
				"rootfs": fmt.Sprintf("unknown rootfs %q; available: %v", reqRootfs, catalogNames),
			})
		}
		// Disabled-rootfs check reuses catalogMeta from the cached union
		// above — O(1) hash lookup, no DB round-trip.
		if rec, ok := catalogMeta[reqRootfs]; ok && rec.Disabled {
			msg := "rootfs disabled"
			if rec.Successor != nil && *rec.Successor != "" {
				msg = "rootfs disabled, use " + *rec.Successor + " instead"
			}
			return httpx.Fail(c, fiber.StatusBadRequest, msg)
		}
	}
	tRootfs = time.Now()

	// Resolve shape to (mem, vcpu, default_disk) for the multi-dim
	// scheduler admission filter. Host re-validates authoritatively.
	schedMem := 0
	schedVCPU := 0
	var schedDefaultDisk int64
	for _, sh := range shapeCat {
		if sh.ID == req.Shape {
			schedMem = sh.MemMib
			schedVCPU = sh.VCPU
			schedDefaultDisk = sh.DefaultDisk
			break
		}
	}
	if schedMem == 0 {
		return httpx.Fail(c, fiber.StatusBadRequest,
			types.UnknownShape{Shape: "unknown", Choices: vm.NewCatalog(shapeCat).IDs()})
	}
	// Resolve disk: user override (req.DiskMib) if set, else shape default.
	schedDisk := schedDefaultDisk
	if req.DiskMib > 0 {
		schedDisk = req.DiskMib
	}
	t.Attr("shape", req.Shape)
	tShape = time.Now()

	ctx := c.UserContext()

	// Pool fast path — atomically re-assign a pre-warmed pool sandbox
	// to this user when the request exactly matches the pool spec and
	// carries no personalization (SSH keys, envs, disks, etc.). Failure
	// modes: (a) request ineligible → matchesPool returns false and we
	// fall through; (b) pool empty → same; (c) tx error → log and fall
	// through (the normal path will still succeed). A hit skips the
	// scheduler + host forward entirely because the sandbox already
	// exists on a host.
	// Pool claims bypass scheduler placement. A user with preferred hosts must
	// take the normal path or could receive a pool VM on an unpreferred host.
	preferredHosts := placementpolicy.PreferredHosts(
		utils.UserID(c), req.Shape, req.Region,
	)
	if quotaUserID != "" && len(preferredHosts) == 0 {
		if sb, perr := h.tryClaimFromPool(ctx, c, &req, quotaUserID); perr != nil {
			log.WithContext(c.UserContext()).Warnf("[pool] claim tx failed for user=%s shape=%s: %v (falling through to normal create)", quotaUserID, req.Shape, perr)
		} else if sb != nil {
			poolHit = true
			tPool = time.Now()
			stopPreflight()
			return h.respondPoolCreated(c, sb)
		}
	}
	tPool = time.Now()

	stopPreflight()
	createErr := h.HandleCreateExternal(c, t, ctx, &req, schedMem, schedVCPU, schedDisk, fallback)
	tFwd = time.Now()
	return createErr
}

func (h *Handler) createFallbackTarget(user string, req *proto.CreateReq) string {
	policy, _ := placementpolicy.Lookup(user)
	if !placementpolicy.CrossRegionEnabled(user) || policy.Region != "" || len(policy.PreferredHostIDs) != 0 ||
		strings.TrimSpace(req.Region) != "" || strings.TrimSpace(req.HostID) != "" ||
		len(req.NodeSelector) != 0 || len(req.Disks) != 0 || len(req.Networks) != 0 || len(req.DisksResolved) != 0 {
		return ""
	}
	// Explicit names can collide with the origin's still-replicating creating
	// row under the cross-region unique-name index. Keep them regional for now.
	if req.Name != nil && strings.TrimSpace(*req.Name) != "" {
		return ""
	}
	target := models.EuropeRegion
	switch h.region {
	case models.EuropeRegion:
		target = models.UnitedStatesRegion
	case models.UnitedStatesRegion:
	default:
		return ""
	}
	if strings.TrimSpace(h.peerControls[target]) == "" {
		return ""
	}
	return target
}

// handleCreateExternal implements the create flow. The sandbox id is minted
// by control before any scheduling decision and threaded into:
//   - the INSERT (durable claim that survives a control crash)
//   - the scheduler.Schedule call (reservation key)
//   - the X-Sandbox-ID header on the forward (host uses it verbatim)
//
// All three converge on the same id, which is what makes hydrate able to
// reconcile in-mem reservations against the durable record without any
// notification or ack from the host.
func (h *Handler) HandleCreateExternal(c *fiber.Ctx, t *trace.Trace, ctx context.Context, req *api.CreateReq, schedMem, schedVCPU int, schedDisk int64, fallback *api.CreateReq) error {
	sbID := vm.NewSandboxID()
	setSandboxContext(c, sbID)
	t.Attr("id", sbID)

	now := time.Now().UTC()
	reqRootfs := ""
	if req.Rootfs != nil {
		reqRootfs = *req.Rootfs
	}
	rec := models.Sandbox{
		ID:                  sbID,
		Status:              models.StatusCreating,
		Shape:               req.Shape,
		Rootfs:              req.Rootfs,
		MemMib:              schedMem,
		VCPU:                schedVCPU,
		DiskMib:             schedDisk,
		CreatedAt:           now,
		CreatedBy:           utils.UserIDFromContext(ctx),
		Region:              req.Region,
		Egress:              req.Egress,
		BandwidthQuotaBytes: req.BandwidthQuotaBytes,
		Envs:                req.Envs,
		Labels:              req.Labels,
	}
	if req.IngressEnabled != nil && *req.IngressEnabled {
		rec.IngressEnabled = true
	}
	if req.AutoPauseAfterSeconds != nil {
		rec.AutoPauseAfterSeconds = req.AutoPauseAfterSeconds
	}
	log.WithContext(ctx).Infof("[control] create id=%s shape=%s rootfs=%s envs=%s", sbID, req.Shape, reqRootfs, redactEnvs(req.Envs))
	stopInsert := t.Phase("insert")
	reqName := ""
	if req.Name != nil {
		reqName = *req.Name
	}
	name, status, fail := h.insertSandboxWithName(ctx, rec, reqName)
	if status != 0 {
		stopInsert()
		if fail != "" {
			return httpx.Fail(c, status, fail)
		}
		return httpx.Error(c, status, "insert sandbox row")
	}
	stopInsert()
	// Thread the resolved name back into req so the host's row upsert
	// (creating→running) and the forwarded body both carry it.
	req.Name = &name
	rec.Name = &name

	stopReserve := t.Phase("schedule")
	resp, err := h.schedulerClient.Schedule(ctx, schedapi.ScheduleRequest{
		SandboxID: sbID,
		Shape:     req.Shape,
		Rootfs:    reqRootfs,
		MemMiB:    schedMem,
		VCPU:      schedVCPU,
		DiskMiB:   schedDisk,
		HostID:    req.HostID,
		// Local region only — cross-region requests were already
		// forwarded to the owning region's control above.
		Region: h.region,
		Labels: req.NodeSelector,
		PreferredHostIDs: placementpolicy.PreferredHosts(
			utils.UserIDFromContext(ctx), req.Shape, h.region,
		),
	})
	stopReserve()
	if err != nil {
		// Mark the row failed so the next hydrate excludes it from SUM.
		schedMsg := "schedule failed: " + err.Error()
		if markErr := h.repo.MarkFailed(ctx, sbID, &schedMsg, time.Now().UTC(), h.billingEmitter); markErr != nil {
			log.WithContext(ctx).Errorf("[create] mark failed id=%s: %v", sbID, markErr)
			return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
		}
		if fallback != nil && errors.Is(err, schedclient.ErrNoCapacity) {
			body, marshalErr := json.Marshal(fallback)
			if marshalErr != nil {
				return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
			}
			c.Request().SetBody(body)
			return h.forwardToPeerControl(c, fallback.Region, http.MethodPost, "/v1/sandboxes")
		}
		log.WithContext(ctx).Errorf("[handler] service unavailable: %v", err)

		return httpx.Error(c, fiber.StatusServiceUnavailable, "service unavailable")
	}
	t.Attr("host", resp.HostID)

	respHostID := resp.HostID
	if err := h.repo.SetSandboxHost(ctx, sbID, &respHostID); err != nil {
		setHostMsg := "set host failed: " + err.Error()
		_ = h.repo.MarkFailed(ctx, sbID, &setHostMsg, time.Now().UTC(), h.billingEmitter)
		log.WithContext(ctx).Errorf("[create.set-host] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}

	// Resolve + attach disks. Ownership check returns 404 (don't leak
	// existence of another user's disks). Each attachment is its own
	// sandbox_disks row, persisted *before* the forward so a host crash
	// leaves us with a recoverable record. The decrypted bundle is
	// written into req.DisksResolved for the host to read; the raw
	// req.Disks form is cleared so untrusted user input never reaches
	// the host.
	stopDisks := t.Phase("disks")
	if len(req.Disks) > 0 {
		userID := utils.UserIDFromContext(ctx)
		// Need the destination host's pubkey to seal disk creds.
		destHost, derr := h.repo.GetHost(ctx, respHostID)
		if derr != nil || destHost == nil || len(destHost.PublicKey) == 0 {
			log.WithContext(ctx).Errorf("[control] disk fanout: host %s pubkey lookup failed: %v", respHostID, derr)
			failMsg := "host pubkey unavailable"
			_ = h.repo.MarkFailed(ctx, sbID, &failMsg, time.Now().UTC(), h.billingEmitter)
			return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
		}
		resolved := make([]proto.ResolvedDisk, 0, len(req.Disks))
		for _, da := range req.Disks {
			disk, derr := h.repo.GetDisk(ctx, userID, strings.TrimSpace(da.DiskID))
			if derr != nil {
				log.WithContext(ctx).Errorf("[control] disk lookup %s: %v", da.DiskID, derr)
				failMsg := "disk lookup failed"
				_ = h.repo.MarkFailed(ctx, sbID, &failMsg, time.Now().UTC(), h.billingEmitter)
				return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
			}
			if disk == nil {
				// Identical-404 either way: not found OR owned by another user.
				_ = h.repo.MarkFailed(ctx, sbID, ptrString("disk not found"), time.Now().UTC(), h.billingEmitter)
				return httpx.Fail(c, fiber.StatusNotFound,
					fmt.Sprintf("disk %q not found", da.DiskID))
			}
			plain, derr := h.diskCipher.Decrypt(disk.Credentials)
			if derr != nil {
				log.WithContext(ctx).Errorf("[control] disk decrypt %s: %v", disk.ID, derr)
				failMsg := "disk credentials unreadable"
				_ = h.repo.MarkFailed(ctx, sbID, &failMsg, time.Now().UTC(), h.billingEmitter)
				return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
			}
			subPath := normalizeSubPath(da.SubPath)
			if err := validateSubPath(subPath); err != nil {
				_ = h.repo.MarkFailed(ctx, sbID, ptrString("invalid sub_path"), time.Now().UTC(), h.billingEmitter)
				return httpx.Fail(c, fiber.StatusBadRequest,
					fmt.Sprintf("disks[%s].sub_path: %s", da.DiskID, err.Error()))
			}
			if derr := h.repo.AttachDisk(ctx, sbID, disk.ID, da.MountPath, subPath); derr != nil {
				if isUniqueViolation(derr) {
					_ = h.repo.MarkFailed(ctx, sbID,
						ptrString("duplicate mount_path"), time.Now().UTC(), h.billingEmitter)
					return httpx.Fail(c, fiber.StatusBadRequest,
						fmt.Sprintf("another disk is already mounted at %q on this sandbox", da.MountPath))
				}
				log.WithContext(ctx).Errorf("[control] disk attach %s -> %s: %T %v", disk.ID, sbID, derr, derr)
				failMsg := "disk attach failed"
				_ = h.repo.MarkFailed(ctx, sbID, &failMsg, time.Now().UTC(), h.billingEmitter)
				return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
			}
			sealed, serr := sealDiskCreds(destHost.PublicKey, plain)
			if serr != nil {
				log.WithContext(ctx).Errorf("[control] disk seal %s -> %s: %v", disk.ID, respHostID, serr)
				failMsg := "disk seal failed"
				_ = h.repo.MarkFailed(ctx, sbID, &failMsg, time.Now().UTC(), h.billingEmitter)
				return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
			}
			resolved = append(resolved, proto.ResolvedDisk{
				DiskID:      disk.ID,
				Kind:        disk.Kind,
				Config:      disk.Config,
				Credentials: sealed,
				MountPath:   da.MountPath,
				SubPath:     subPath,
			})
		}
		req.Disks = nil // never forward user-side shape to host
		req.DisksResolved = resolved
	}
	stopDisks()

	host := models.Host{ID: resp.HostID, Addr: resp.HostAddr}
	stopForward := t.Phase("forward")
	hostResponse, fwdErr := hostrpc.Create(
		ctx, h.http, host, sbID, utils.UserIDFromContext(ctx), req,
	)
	stopForward()
	if fwdErr != nil {
		fwdMsg := "forward failed: " + fwdErr.Error()
		_ = h.repo.MarkFailed(ctx, sbID, &fwdMsg, time.Now().UTC(), h.billingEmitter)
		log.WithContext(ctx).Warnf("[create] host %s unreachable: %v", resp.HostID, fwdErr)
		return httpx.Error(c, fiber.StatusBadGateway, "host unreachable")
	}
	defer hostResponse.Body.Close()
	if err := writeBufferedHostResponse(c, hostResponse); err != nil {
		fwdMsg := "forward response failed: " + err.Error()
		_ = h.repo.MarkFailed(ctx, sbID, &fwdMsg, time.Now().UTC(), h.billingEmitter)
		return err
	}
	if c.Response().StatusCode() < 200 || c.Response().StatusCode() >= 300 {
		hostMsg := "host non-2xx"
		_ = h.repo.MarkFailed(ctx, sbID, &hostMsg, time.Now().UTC(), h.billingEmitter)
		return nil
	}

	ingressOn := req.IngressEnabled != nil && *req.IngressEnabled
	if ingressOn && h.ingressDomainSuffix != "" {
		var env createRespEnvelope
		if err := json.Unmarshal(c.Response().Body(), &env); err == nil && env.Data.ID != "" {
			env.Data.IngressURLTemplate = h.ingressURLTemplate(env.Data.ID)
			if buf, err := json.Marshal(env); err == nil {
				c.Response().SetBody(buf)
			}
		}
	}

	stopPost := t.Phase("post")
	defer stopPost()
	if keys := extractSSHPubkeys(req); len(keys) > 0 {
		if err := h.repo.SetSSHPubkeys(ctx, sbID, keys); err != nil {
			log.WithContext(ctx).Warnf("[control] SetSSHPubkeys(%s): %v", sbID, err)
		}
	}

	attachNetworks(ctx, h, sbID, utils.UserID(c), req.Networks)

	// Audit. Best-effort: never blocks or fails the create response.
	if sb, _ := h.repo.Get(ctx, sbID); sb != nil {
		h.audit.Emit(ctx, h.auditCtxWithSubject(c, "sandbox", sb.ID),
			audit.ActionSandboxCreate, audit.OperationCreate,
			audit.BuildSandboxCreate(sb))
	}

	return nil
}

// sandboxNameRe is the DNS-label rule for a user-facing VM name: lowercase
// letters/digits/hyphens only, must start and end alphanumeric, no dots,
// no underscores. The name doubles as the guest hostname and a DNS label
// (<name>.<network>.fc.local), so it has to be a clean label.
var sandboxNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// validateSandboxName checks a user-supplied sandbox name. An empty name is
// allowed (control auto-generates one). Returns "" when valid, else a
// human-readable reason.
func validateSandboxName(name string) string {
	if name == "" {
		return ""
	}
	if len(name) > 22 {
		return fmt.Sprintf("too long: %d characters (max 22)", len(name))
	}
	if !sandboxNameRe.MatchString(name) {
		return "must be lowercase letters, digits and hyphens only " +
			"(no dots or underscores), and start and end with a letter or digit"
	}
	return ""
}

// insertSandboxWithName inserts the sandbox row, resolving its user-facing
// name and handling the per-user unique-name constraint.
//
//   - If userName is non-empty the user supplied it: insert verbatim. A
//     unique-violation (Postgres 23505 on idx_sandboxes_user_name) is a
//     real user error → returns HTTP 409 with a clear JSend fail.
//   - If userName is empty control auto-generates a "<adjective>-<animal>"
//     name. A unique-violation just means the random pick collided with an
//     existing non-terminal sandbox of the same user — regenerate and retry
//     up to nameRetryBudget times before giving up with a 500.
//
// Returns the resolved name on success (status==0). On failure returns a
// non-zero HTTP status and, for the 409 case, the JSend fail body.
func (h *Handler) insertSandboxWithName(ctx context.Context, rec models.Sandbox, userName string) (string, int, string) {
	const nameRetryBudget = 5
	userSupplied := userName != ""

	attempts := 1
	if !userSupplied {
		attempts = nameRetryBudget
	}
	for i := 0; i < attempts; i++ {
		name := userName
		if !userSupplied {
			name = generateSandboxName()
		}
		nameCopy := name
		rec.Name = &nameCopy
		err := h.repo.Insert(ctx, rec)
		if err == nil {
			return name, 0, ""
		}
		if isUniqueNameViolation(err) {
			if userSupplied {
				return "", fiber.StatusConflict,
					fmt.Sprintf("a sandbox named %q already exists", name)
			}
			// Auto-generated collision — try a fresh name.
			log.WithContext(ctx).Warnf("[control] create: generated name %q collided, retrying", name)
			continue
		}
		log.WithContext(ctx).Errorf("[control] insert sandbox row: %v", err)
		return "", fiber.StatusInternalServerError, ""
	}
	log.WithContext(ctx).Errorf("[control] create: exhausted name generation retries (%d)", nameRetryBudget)
	return "", fiber.StatusInternalServerError, ""
}

// ptrString is a one-liner for &s of a literal.
func ptrString(s string) *string { return &s }

// isUniqueViolation reports whether err is a Postgres unique-constraint
// violation regardless of which index triggered it. Callers that care
// about a specific constraint should inspect pgErr.ConstraintName.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgerrors.UniqueViolation
}

// isUniqueNameViolation reports whether err is a Postgres unique-constraint
// violation. Called from insertSandboxWithName, where the only unique
// constraint that can fire is the per-user sandbox-name index — the row's
// id is a fresh ULID so PK collisions are statistically impossible.
func isUniqueNameViolation(err error) bool {
	return isUniqueViolation(err)
}

// attachNetworks resolves and attaches each requested network to a newly-created
// sandbox. Failures are logged but never fail the create response. After
// attaches land, fans out a non-blocking overlay-reconciler kick to every host
// that currently has a member in any of the affected networks, so BPF policy
// maps update within milliseconds instead of waiting for the next reconciler
// tick (≤5s) and the first cross-VM connection succeeds immediately.
func attachNetworks(ctx context.Context, h *Handler, sbID, userID string, nets []proto.NetworkEntry) {
	attachedNets := make(map[string]struct{})
	for _, ne := range nets {
		if ne.ID == "" {
			continue
		}
		n, err := h.repo.GetNetwork(ctx, userID, ne.ID)
		if err != nil || n == nil {
			log.WithContext(ctx).Warnf("[control] create attach network %q for sandbox %s: not found or error: %v", ne.ID, sbID, err)
			continue
		}
		if err := h.repo.AttachNetwork(ctx, sbID, n.ID); err != nil {
			log.WithContext(ctx).Warnf("[control] create attach network %q for sandbox %s: %v", ne.ID, sbID, err)
			continue
		}
		attachedNets[n.ID] = struct{}{}
	}
	if len(attachedNets) == 0 {
		return
	}
	// Gather every host with a live sandbox in the affected networks and
	// kick each one's reconciler. Single-host clusters get one POST; the
	// general case fans out one per host. Best-effort: warn on failure
	// and move on — the periodic tick is the safety net.
	hosts := make(map[string]struct{})
	for netID := range attachedNets {
		members, err := h.repo.ListNetworkMembers(ctx, netID)
		_ = members
		if err != nil {
			continue
		}
	}
	// ListNetworkMembers returns sandbox views without host_id; resolve
	// owning hosts via a single sandbox lookup per attached row. For the
	// hot path of "new sandbox joining a network" the most important
	// host to kick is the new sandbox's own host — peers will pick up on
	// their next tick. So just kick the new sandbox's host directly.
	rec, err := h.repo.Get(ctx, sbID)
	if err != nil || rec == nil || rec.HostID == nil || *rec.HostID == "" {
		return
	}
	host, err := h.repo.GetHost(ctx, *rec.HostID)
	if err != nil || host == nil {
		return
	}
	hosts[host.ID] = struct{}{}
	// Bust the host-state response cache so the kick-triggered
	// reconcile reads fresh data. The cache holds for 1s — without
	// invalidation, the kick fetch lands during the cached window
	// and the reconciler sees stale "0 members" right after we
	// wrote the new attachment.
	invalidateHostStateCache(host.ID)
	go func() {
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		if err := kickHostNetReconciler(bg, *host, h.http); err != nil {
			log.WithContext(ctx).Warnf("[control] net-reconcile kick host=%s: %v (next tick will catch up)", host.ID, err)
		}
	}()
}

// kickHostNetReconciler POSTs an empty body to the host's
// /v1/internal/net-reconcile-kick endpoint. The host's handler is a
// non-blocking signal — returns 200 immediately and the reconciler
// goroutine wakes on the same tick.
//
// Auth is the outbound mTLS client cert configured on `client` (control's
// SPIFFE leaf). The host route is `HostMustBePeerRoleMTLS("control")`;
// no JWT is read on the host side. Callers pass `client` from the
// mTLS-equipped Transport in handlers.Handler — a plain http.DefaultClient
// would handshake-fail at the host.
// kickHostNetReconciler is exported so sub-packages (handlers/relay)
// can fire the same kick from their own device-attach / session paths.
func kickHostNetReconciler(ctx context.Context, host models.Host, client *http.Client) error {
	addr := host.Addr
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		addr = hostScheme() + "://" + addr
	}
	url := strings.TrimRight(addr, "/") + "/v1/internal/net-reconcile-kick"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("host returned %d", resp.StatusCode)
	}
	return nil
}

// envKeyRe gates env-var names to POSIX-shell-portable identifiers. We're
// strict on purpose: shells (and many runtimes) silently drop names with
// non-identifier chars, leaving the user wondering why "FOO-BAR" never
// reaches their app. Reject early instead of swallowing.
var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// validateEnvs enforces the size + character limits on a CreateReq.Envs
// map. Returns ("", "") on success; ("<field>", "<msg>") on the first
// violation, naming the offending key so callers can fix it without a
// guessing game.
func validateEnvs(envs map[string]string) (string, string) {
	if len(envs) == 0 {
		return "", ""
	}
	if len(envs) > 64 {
		return "envs", fmt.Sprintf("too many env vars: %d (max 64)", len(envs))
	}
	const maxValueBytes = 4096
	const maxTotalBytes = 65536
	total := 0
	for k, v := range envs {
		if !envKeyRe.MatchString(k) {
			return "envs." + k, "key must match ^[A-Za-z_][A-Za-z0-9_]*$"
		}
		if strings.ContainsRune(v, 0) {
			return "envs." + k, "value contains NUL byte"
		}
		if len(v) > maxValueBytes {
			return "envs." + k, fmt.Sprintf("value too long: %d bytes (max %d)", len(v), maxValueBytes)
		}
		total += len(k) + len(v) + 4 // rough JSON overhead per entry
	}
	if total > maxTotalBytes {
		return "envs", fmt.Sprintf("total env size too large: ~%d bytes (max %d)", total, maxTotalBytes)
	}
	return "", ""
}

// validateLabels bounds user-defined sandbox metadata. Labels are opaque
// strings (unlike environment variable names), but control characters and
// oversized payloads are rejected so they remain safe in APIs and logs.
func validateLabels(labels map[string]string) (string, string) {
	if len(labels) == 0 {
		return "", ""
	}
	if len(labels) > 100 {
		return "labels", fmt.Sprintf("too many labels: %d (max 100)", len(labels))
	}
	const (
		maxKeyBytes   = 128
		maxValueBytes = 1024
		maxTotalBytes = 65536
	)
	total := 0
	for k, v := range labels {
		if k == "" {
			return "labels", "label key must not be empty"
		}
		if len(k) > maxKeyBytes {
			return "labels." + k, fmt.Sprintf("key too long: %d bytes (max %d)", len(k), maxKeyBytes)
		}
		if strings.ContainsRune(k, 0) || strings.ContainsRune(v, 0) {
			return "labels." + k, "key and value must not contain NUL bytes"
		}
		if len(v) > maxValueBytes {
			return "labels." + k, fmt.Sprintf("value too long: %d bytes (max %d)", len(v), maxValueBytes)
		}
		total += len(k) + len(v) + 4
	}
	if total > maxTotalBytes {
		return "labels", fmt.Sprintf("total label size too large: ~%d bytes (max %d)", total, maxTotalBytes)
	}
	return "", ""
}

// redactEnvs returns a log-safe summary of an envs map. We never log values
// — they may carry credentials. "{N keys}" is enough to confirm intent
// while keeping logs grep-friendly.
func redactEnvs(envs map[string]string) string {
	if len(envs) == 0 {
		return "{}"
	}
	return fmt.Sprintf("{%d keys}", len(envs))
}

// extractSSHPubkeys pulls req.SSHPubkeys via a tiny helper so this file
// compiles against today's api.CreateReq (no field) and the integrated
// CreateReq (field present). Once the field exists, this becomes a direct
// access; for now we marshal/unmarshal to pick it up if present.
func extractSSHPubkeys(req *api.CreateReq) []string {
	// Fast path: if future CreateReq has SSHPubkeys, reflect-less marshal will
	// include it; otherwise we get nothing. Keep it cheap and resilient.
	b, err := json.Marshal(req)
	if err != nil {
		return nil
	}
	var peek sshPubkeysProjection
	_ = json.Unmarshal(b, &peek)
	return peek.SSHPubkeys
}

// canonicalizeSSHPubkeys parses each entry with ssh.ParseAuthorizedKey,
// then re-encodes via ssh.MarshalAuthorizedKey so the stored form is
// only "<type> <base64>" — comments stripped, options stripped, the
// trailing newline trimmed. Rejects empty input or any line we can't
// parse, returning the offending index. ParseAuthorizedKey rejects
// embedded newlines and only consumes the first entry of a multi-line
// input, so this is also the gate against newline-injection bypass.
func canonicalizeSSHPubkeys(raw []string) ([]string, int, error) {
	out := make([]string, 0, len(raw))
	for i, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, i, fmt.Errorf("empty entry")
		}
		// ParseAuthorizedKey returns the rest-of-input. If non-empty,
		// the caller stuffed multiple keys into a single string —
		// refuse rather than silently keep the first.
		k, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(s))
		if err != nil {
			return nil, i, err
		}
		if len(strings.TrimSpace(string(rest))) != 0 {
			return nil, i, fmt.Errorf("multiple keys in one entry")
		}
		out = append(out, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))))
	}
	return out, -1, nil
}

// setCanonicalSSHPubkeys writes the canonicalized list back through the
// same JSON marshal/unmarshal trick extractSSHPubkeys uses. This keeps
// the rest of the forwarding pipeline (which serializes req before
// shipping to the host) from re-sending the unsanitized strings.
func setCanonicalSSHPubkeys(req *api.CreateReq, keys []string) {
	b, err := json.Marshal(req)
	if err != nil {
		return
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return
	}
	enc, err := json.Marshal(keys)
	if err != nil {
		return
	}
	raw["ssh_pubkeys"] = enc
	merged, err := json.Marshal(raw)
	if err != nil {
		return
	}
	_ = json.Unmarshal(merged, req)
}

func (h *Handler) HandleList(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	limit := c.QueryInt(middlewares.QueryLimit, 50)
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	offset := c.QueryInt(middlewares.QueryOffset, 0)
	if offset < 0 {
		offset = 0
	}
	// `?status=` optional: empty = any status; "running" (most common) /
	// "destroyed" / "creating" / "failed" filter server-side so `limit` is
	// applied AFTER the filter.
	status := c.Query("status", "")
	labels := map[string]string{}
	if raw := c.Query("labels", ""); raw != "" {
		if err := json.Unmarshal([]byte(raw), &labels); err != nil {
			return httpx.Fail(c, fiber.StatusBadRequest, "labels must be a JSON object of string values")
		}
		if _, msg := validateLabels(labels); msg != "" {
			return httpx.Fail(c, fiber.StatusBadRequest, msg)
		}
	}
	uid := utils.UserIDFromContext(c.UserContext())
	if uid == "" {
		// Fail closed if authentication middleware is accidentally omitted or
		// disabled. An empty user filter means "all tenants" to the shared
		// repository query and is valid only for trusted internal callers.
		return httpx.Fail(c, fiber.StatusUnauthorized,
			types.AuthError{Auth: "authentication required"})
	}
	recs, err := h.repo.ListPaged(c.UserContext(), "", uid, status, labels, limit, offset)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	total, err := h.repo.CountSandboxesForList(c.UserContext(), "", uid, status, labels)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] count internal error: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	views := make([]api.SandboxView, 0, len(recs))
	for _, r := range recs {
		views = append(views, h.viewWith(r))
	}
	return httpx.Paginated(c, views, total, limit, offset, len(views))
}

func (h *Handler) HandleGet(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	rec, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		if errors.Is(err, api.ErrNotFound) {
			return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		}
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil || !runtimeOwnerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	return httpx.Success(c, h.viewWith(*rec))
}

// ownerOK returns true if the request is allowed to see rec. Fails CLOSED:
// if the caller's user_id is unset (auth middleware didn't fire, future
// route-ordering bug, etc.), this returns false. The old fail-open behavior
// — "no user_id = see everything, intended for dev mode" — would turn any
// auth-middleware regression into a full cross-tenant bypass, which is too
// expensive a default. Dev paths that legitimately need to bypass auth
// should stamp a synthetic user_id via the auth middleware rather than
// leaving the context empty.
func ownerOK(c *fiber.Ctx, rec *models.Sandbox) bool {
	caller := utils.UserIDFromContext(c.UserContext())
	if caller == "" {
		return false
	}
	if rec == nil || rec.CreatedBy != caller {
		return false
	}
	setSandboxContext(c, rec.ID)
	return true
}

// runtimeOwnerOK is used only by controllers deliberately exposed to a
// delegated sandbox credential. All account/configuration controllers keep
// using ownerOK, so a sandbox token cannot grow beyond its runtime surface.
func runtimeOwnerOK(c *fiber.Ctx, rec *models.Sandbox) bool {
	// A sandbox-scoped token may only act on its own sandbox.
	if sandboxID := utils.SandboxPrincipalIDFromContext(c.UserContext()); sandboxID != "" {
		if rec == nil || rec.ID != sandboxID {
			return false
		}
		setSandboxContext(c, rec.ID)
		return true
	}
	return ownerOK(c, rec)
}

func setSandboxContext(c *fiber.Ctx, id string) {
	if id == "" {
		return
	}
	c.Locals("sandbox_id", id)
	c.SetUserContext(requestctx.WithSandboxID(c.UserContext(), id))
}

func isSandboxPrincipal(c *fiber.Ctx) bool {
	return utils.SandboxPrincipalIDFromContext(c.UserContext()) != ""
}

func sandboxPrincipalForbidden(c *fiber.Ctx) error {
	return httpx.Fail(c, fiber.StatusForbidden,
		"sandbox access token is not permitted for this operation")
}

// forwardedOwnerID returns the durable owner expected by the host's
// independent authorization check. A delegated token remains a sandbox
// principal in control; it is never promoted into a user principal.
func forwardedOwnerID(c *fiber.Ctx, rec *models.Sandbox) string {
	if isSandboxPrincipal(c) && rec != nil {
		return rec.CreatedBy
	}
	return utils.UserID(c)
}

func (h *Handler) HandleGetByIP(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	ipStr := c.Params(middlewares.ParamIP)
	if net.ParseIP(ipStr) == nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid ip")
	}
	userID := utils.UserIDFromContext(c.UserContext())
	if userID == "" {
		// Auth middleware should have stamped a user_id; bail out the same
		// way a non-owner would so callers can't probe.
		return httpx.Fail(c, fiber.StatusNotFound, "no sandbox with this ip")
	}
	rec, err := h.repo.GetByIPForUser(c.UserContext(), userID, ipStr)
	if err != nil {
		if errors.Is(err, api.ErrNotFound) {
			return httpx.Fail(c, fiber.StatusNotFound, "no sandbox with this ip")
		}
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "no sandbox with this ip")
	}
	return httpx.Success(c, h.viewWith(*rec))
}

func (h *Handler) HandleGetEgress(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	id := c.Params(middlewares.ParamSandboxID)
	rec, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil || !ownerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	return httpx.Success(c, proto.EgressView{ID: rec.ID, Egress: rec.Egress})
}

func (h *Handler) HandleListEgressPresets(c *fiber.Ctx) error {
	return httpx.Success(c, egressPresetsView{
		Version: egressPresetVersion,
		Presets: egressPresetCatalog(),
	})
}

func (h *Handler) HandleExec(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	tPre := time.Now()
	rec, err := h.repo.GetForExec(c.UserContext(), id)
	preGetMs := float64(time.Since(tPre).Microseconds()) / 1000.0
	log.WithContext(c.UserContext()).Infof("[exec-pregate] sb=%s pre_get_sb=%.2f", id, preGetMs)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] exec lookup: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil || !runtimeOwnerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if rec.Status != models.StatusRunning {
		if rec.Status == models.StatusPaused || rec.Status == models.StatusError {
			return httpx.Fail(c, fiber.StatusConflict,
				"sandbox is "+string(rec.Status)+"; resume it before running commands")
		}
		return httpx.Fail(c, fiber.StatusConflict,
			"sandbox is "+string(rec.Status)+"; commands require a running sandbox")
	}
	if rec.AutoPauseAfterSeconds != nil {
		go h.repo.TouchActivity(context.WithoutCancel(c.UserContext()), strings.Clone(id), rec.BandwidthUsedBytes+rec.BandwidthIngressBytes) //nolint:errcheck
	}
	if c.QueryBool("stream") || bodyAsksStream(c.Body()) {
		return h.forwardStreamBySandboxUsingRec(c, "/v1/sandboxes/"+id+"/exec", rec)
	}
	// Skip the redundant Repo.Get inside forwardBySandbox — we already
	// fetched rec above for the owner gate. Saves one DB round-trip
	// (~30ms under N≥30 contention).
	return h.forwardBySandboxUsingRec(c, "/v1/sandboxes/"+id+"/exec", rec)
}

// bodyAsksStream is a cheap inspection of the JSON body for `"stream":true`
// so clients can opt in via body alone (matches the proto.ExecRequest field).
// We don't fully parse here; the host re-validates.
func bodyAsksStream(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	var probe execStreamProjection
	_ = json.Unmarshal(b, &probe)
	return probe.Stream
}

// forwardStreamBySandboxUsingRec is forwardBySandbox + streaming relay. Uses
// the same routing logic to pick the host, then ForwardStreamTo to
// pipe the chunked body through.
func (h *Handler) forwardStreamBySandboxUsingRec(c *fiber.Ctx, path string, rec *models.Sandbox) error {
	id := c.Params(middlewares.ParamSandboxID)
	if rec == nil {
		var err error
		rec, err = h.repo.Get(c.UserContext(), id)
		if err != nil {
			log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

			return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
		}
	}
	// Defence in depth: gate by owner BEFORE upgrading to a chunked
	// streaming response — once the response writer is in stream mode
	// the status code is sunk and any "not found" surfaces as an in-band
	// NDJSON event rather than a proper HTTP 404. Mirrors the buffered
	// forwardBySandbox path which has had this check from day one.
	if rec == nil || !runtimeOwnerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if rec.HostID == nil || *rec.HostID == "" {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	host, err := h.getHostCached(c.UserContext(), *rec.HostID)
	if err != nil || host == nil {
		return httpx.Fail(c, fiber.StatusServiceUnavailable, "owning host unavailable")
	}
	return ForwardStreamToAs(c, *host, path, h.http, forwardedOwnerID(c, rec))
}

func (h *Handler) HandleDestroy(c *fiber.Ctx) error {
	// Delete is async: control flips the row to `destroying` and returns
	// immediately. Each host's reconciler (startup + periodic 30s tick)
	// picks up its own `destroying` rows, runs Manager.Destroy, and marks
	// the row `destroyed`. This survives the owning host being down at
	// the moment of the request — the row sits in `destroying` until the
	// host comes back.
	id := c.Params(middlewares.ParamSandboxID)
	ctx := c.UserContext()
	rec, _ := h.repo.Get(ctx, id)
	if rec == nil || !runtimeOwnerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	// Already terminal — DELETE is idempotent: same shape, status=destroyed.
	if rec.Status == models.StatusDestroyed || rec.Status == models.StatusFailed {
		return httpx.Success(c, proto.DestroyResp{ID: id, Status: string(rec.Status)})
	}
	// Destruction is initiated by a durable database transition in control.
	// Keep that transition in the sandbox's home region so the owning host's
	// regional database observes `destroying` even while replication is down.
	if rec.Region != "" && rec.Region != h.region {
		return h.forwardToPeerControl(c, rec.Region, c.Method(), c.Path())
	}
	// Paused/error rows have no owning host. Use a CAS-guarded transition
	// that ONLY fires when the row is still in {paused, error} — without
	// this, a concurrent HandleResume can flip paused→resuming between
	// our read at (rec.Status check) and the destroy, leaving us about
	// to delete the R2 bundle while a host is restoring from it.
	if rec.Status == models.StatusPaused || rec.Status == models.StatusError {
		ok, err := h.repo.MarkDestroyingFromTerminalCAS(ctx, id)
		if err != nil {
			log.WithContext(c.UserContext()).Errorf("[destroy.cas] internal error: %v", err)
			return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
		}
		if !ok {
			// Row moved out from under us — likely a /resume slipped in.
			// Refresh + tell the caller to retry; do NOT touch R2.
			return httpx.Fail(c, fiber.StatusConflict, "sandbox state changed; retry")
		}
		// The caller that wins the transition owns the single logical
		// destroy audit event. Emitting before the CAS lets concurrent DELETEs
		// publish duplicates even though only one request claimed the row.
		h.audit.Emit(ctx, h.auditCtxForSandboxLifecycle(c, rec),
			audit.ActionSandboxDestroy, audit.OperationRemove,
			audit.BuildSandboxDestroy(rec, "user", models.StatusDestroying))
		snapshotURI := ""
		if rec.SnapshotURI != nil {
			snapshotURI = *rec.SnapshotURI
		}
		requestID := httpx.RequestID(ctx)
		go h.finishPausedDestroy(strings.Clone(id), snapshotURI, requestID)
		return httpx.Success(c, proto.DestroyResp{ID: id, Status: string(models.StatusDestroying)})
	}
	// host_id empty without paused/error usually means a resuming/forking
	// row mid-transition (host_id only stamps on completion). Routing it
	// through the CAS-protected MarkDestroying below is correct: the host's
	// reconciler will pick it up when SetSandboxHost lands. Falling through
	// here is safer than the previous "fast-path empty host" branch which
	// shared the same race.
	// Running / creating / pausing / resuming / forking → flip to destroying.
	// CAS-protected; no-op if another caller raced us into a terminal state.
	transitionedTo, err := h.repo.MarkDestroying(ctx, id)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[destroy.mark-destroying] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if transitionedTo != "" {
		h.audit.Emit(ctx, h.auditCtxForSandboxLifecycle(c, rec),
			audit.ActionSandboxDestroy, audit.OperationRemove,
			audit.BuildSandboxDestroy(rec, "user", models.StatusDestroying))
	}
	// Eagerly tell the owning host to destroy NOW. Best-effort: if the host
	// is unreachable the row stays in `destroying` and the host's
	// reconciler picks it up when it comes back. We return 202 either way —
	// callers must poll for status=destroyed.
	go func(hostID string) {
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		host, err := h.repo.GetHost(bg, hostID)
		if err != nil || host == nil {
			return
		}
		response, err := hostrpc.Destroy(bg, h.http, *host, id, rec.CreatedBy)
		if err != nil {
			log.WithContext(bg).Warnf("[destroy] eager DestroyOnHost(host=%s sb=%s): %v (reconcile will retry)", hostID, id, err)
			return
		}
		defer response.Body.Close()
		if !hostrpc.DestroyAccepted(response) {
			log.WithContext(bg).Warnf("[destroy] eager DestroyOnHost(host=%s sb=%s): status=%d (reconcile will retry)", hostID, id, response.StatusCode)
		}
	}(func() string {
		if rec.HostID != nil {
			return *rec.HostID
		}
		return ""
	}())
	// Async destroy semantics — return 200 (JSend Success). The `status`
	// field on the body is the actual signal callers poll on; the HTTP
	// status code stays in the standard 2xx Success channel.
	return httpx.Success(c, proto.DestroyResp{ID: id, Status: string(models.StatusDestroying)})
}

// finishPausedDestroy removes a hostless sandbox's durable bundle outside the
// request lifetime. The row is already `destroying`, so resume cannot race the
// cleanup. If this worker fails or control restarts, the sweeper retries it.
func (h *Handler) finishPausedDestroy(id, snapshotURI, requestID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ctx = httpx.WithRequestID(ctx, requestID)

	cleanupStarted := time.Now()
	deleteErrors := 0
	if h.storage == nil && snapshotURI != "" {
		log.WithFields(log.Fields{"sandbox_id": id, "request_id": requestID}).Warn(
			"[destroy.paused-async] storage unavailable; sweeper will retry")
		return
	}
	if h.storage != nil && snapshotURI != "" {
		prefix := storage.BundlePrefix(id)
		for _, art := range []string{storage.ArtifactMemfile, storage.ArtifactVMState, storage.ArtifactOverlay, storage.ArtifactManifest} {
			key := prefix + art
			started := time.Now()
			err := h.storage.Delete(ctx, key)
			fields := log.Fields{
				"sandbox_id":  id,
				"request_id":  requestID,
				"artifact":    art,
				"object_key":  key,
				"duration_ms": time.Since(started).Milliseconds(),
			}
			if err != nil {
				deleteErrors++
				fields["error"] = err
				log.WithFields(fields).Warn("[destroy.paused-storage-delete] failed")
			} else {
				log.WithFields(fields).Info("[destroy.paused-storage-delete] complete")
			}
		}
	}
	log.WithFields(log.Fields{
		"sandbox_id":  id,
		"request_id":  requestID,
		"duration_ms": time.Since(cleanupStarted).Milliseconds(),
		"artifacts":   4,
		"errors":      deleteErrors,
	}).Info("[destroy.paused-storage-cleanup] complete")
	if deleteErrors != 0 {
		log.WithFields(log.Fields{"sandbox_id": id, "request_id": requestID}).Warn(
			"[destroy.paused-async] storage cleanup incomplete; sweeper will retry")
		return
	}

	transitioned, err := h.repo.MarkDestroyedFromDestroyingCAS(
		ctx, id, time.Now().UTC(), nil, h.billingEmitter,
	)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{"sandbox_id": id, "request_id": requestID}).Error(
			"[destroy.paused-async] finalize failed; sweeper will retry")
		return
	}
	if transitioned {
		log.WithFields(log.Fields{"sandbox_id": id, "request_id": requestID}).Info(
			"[destroy.paused-async] complete")
	}
}

// HandleBandwidth serves bandwidth counters straight from the DB for every
// sandbox state. The host's meter loop pushes used/capped to control every
// ~5s (internal/hosts/vm/manager.go:StartMeterLoop), so the DB value is at
// most one tick stale — sufficient for a read endpoint, and avoids a
// per-request host round-trip on every poll.
func (h *Handler) HandleBandwidth(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	rec, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil || !runtimeOwnerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	remaining := rec.BandwidthQuotaBytes - rec.BandwidthUsedBytes
	if rec.BandwidthQuotaBytes < 0 {
		remaining = -1
	}
	return httpx.Success(c, proto.BandwidthView{
		ID:             id,
		QuotaBytes:     rec.BandwidthQuotaBytes,
		UsedBytes:      rec.BandwidthUsedBytes,
		IngressBytes:   rec.BandwidthIngressBytes,
		RemainingBytes: remaining,
		Capped:         rec.BandwidthCapped,
	})
}

// maxRechargePerCallBytesControl mirrors the host's per-call cap
// (internal/hosts/api/handler.go) so we reject oversized requests BEFORE
// debiting createos. Keeping it in sync by value rather than importing
// the host package — control-side fallback only; host is the source of
// truth and re-checks.
const maxRechargePerCallBytesControl int64 = 100 * 1024 * 1024 * 1024

func (h *Handler) HandleRecharge(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	id := c.Params(middlewares.ParamSandboxID)
	ctx := c.UserContext()
	// Owner check BEFORE checkCredit: createos rate-limits credit
	// lookups per user, so without this an attacker with any sandbox id
	// could burn the caller's own rate budget on victim ids. forwardBySandbox
	// catches the cross-tenant probe downstream, but the upstream call
	// already landed.
	rec, _ := h.repo.Get(ctx, id)
	if rec == nil || !ownerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if rec.Region != "" && rec.Region != h.region {
		return h.forwardToPeerControl(c, rec.Region, c.Method(), c.Path())
	}
	// Only debit when the VM is live on a host. Paused / destroying /
	// error / resuming sandboxes have no `Mgr.Lookup` hit on the host
	// side, so a forward would 404 AFTER we'd already debited createos.
	// Reject up front with 409.
	if rec.Status != models.StatusRunning {
		return httpx.Fail(c, fiber.StatusConflict,
			"sandbox must be running to recharge bandwidth (current status: "+string(rec.Status)+")")
	}
	// Parse + validate the body up front. We must reject obvious garbage
	// (zero/negative, over per-call cap) BEFORE calling createos so a
	// bad request never debits the user. The host re-validates identically.
	var req proto.RechargeReq
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if req.AddBytes <= 0 {
		return httpx.Fail(c, fiber.StatusBadRequest, "add_bytes must be > 0")
	}
	if req.AddBytes > maxRechargePerCallBytesControl {
		return httpx.Fail(c, fiber.StatusBadRequest,
			"add_bytes exceeds the 100 GiB per-call cap; split into multiple recharge calls")
	}
	// Resolve auth → user_id + is_internal. Internal keys bypass the
	// credit debit (operator-issued, never billed); external keys must
	// have positive credit AND get their credit debited via createos.
	authType, token, hasAuth := middlewares.ExtractAuthToken(c)
	if !hasAuth {
		return httpx.Fail(c, fiber.StatusUnauthorized, "missing auth")
	}
	keyRec, err := h.repo.LookupAPIKeyByHash(ctx, authType, h.apiKeyHasher.Hash(token))
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[recharge] api-key lookup: %v", err)
		return httpx.Error(c, fiber.StatusServiceUnavailable, "internal error")
	}
	if keyRec == nil {
		return httpx.Fail(c, fiber.StatusUnauthorized, "invalid api key")
	}
	if !keyRec.IsInternal {
		// Credit gate — refuse when balance is already exhausted (mirrors
		// the old checkCredit() behaviour, kept inline so we own the
		// keyRec/Limits we just looked up).
		L := h.limits.Get(ctx, keyRec.UserID, false)
		if !L.HasCredit() {
			return httpx.Fail(c, fiber.StatusPaymentRequired,
				"insufficient credit; please top up to continue")
		}
		// Debit createos BEFORE forwarding so we never hand out free
		// quota. Skip when createos is unconfigured (dev / local-only
		// installs) — operator decision; logged once at startup.
		if h.createos != nil && h.createos.BaseURL != "" {
			gib := float64(req.AddBytes) / (1024.0 * 1024.0 * 1024.0)
			dCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			rch, derr := h.createos.RechargeEgressBandwidth(dCtx, keyRec.UserID, id, gib)
			cancel()
			if derr != nil {
				log.WithContext(c.UserContext()).Errorf("[recharge] createos debit for user=%s sb=%s gib=%.4f: %v",
					keyRec.UserID, id, gib, derr)
				return httpx.Error(c, fiber.StatusBadGateway,
					"billing service unavailable; please retry")
			}
			log.WithContext(c.UserContext()).Infof("[recharge] user=%s sb=%s debited %.4f credits for %.2f GiB",
				keyRec.UserID, id, rch.Amount, gib)
		}
	}
	// Forward to the owning host to actually bump bandwidth_quota_bytes.
	// If credit was debited above and the host rejects (e.g. sandbox
	// torn down between owner check and forward), log loudly — this is
	// the same posture as runAutoTopup: external charge is final, local
	// recovery is best-effort.
	fwdErr := h.forwardBySandbox(c, "/v1/sandboxes/"+id+"/bandwidth/recharge")
	if !keyRec.IsInternal && h.createos != nil && h.createos.BaseURL != "" {
		if status := c.Response().StatusCode(); status >= 400 {
			log.WithContext(c.UserContext()).Errorf("[recharge] credit was debited for user=%s sb=%s but host returned %d — local quota NOT bumped",
				keyRec.UserID, id, status)
		}
	}
	return fwdErr
}

func (h *Handler) HandleSetEgress(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	id := c.Params(middlewares.ParamSandboxID)
	// Owner check BEFORE the audit log: without this, any caller could
	// spam attacker-controlled `rules=[...]` arrays into the audit log
	// tagged to any sandbox id, polluting SIEM and forensics. The forward
	// catches the auth mismatch downstream but the log line already landed.
	rec, _ := h.repo.Get(c.UserContext(), id)
	if rec == nil || !ownerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	// Egress is a durable security-policy mutation. Route it through the
	// sandbox's home control so the authoritative regional row performs the
	// final ownership/state check before its host changes the firewall.
	if rec.Region != "" && rec.Region != h.region {
		return h.forwardToPeerControl(c, rec.Region, c.Method(), c.Path())
	}
	var req proto.SetEgressReq
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	expandedEgress, err := expandEgressPresets(req.Egress)
	if err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, err.Error())
	}
	req.Egress = expandedEgress
	body, err := json.Marshal(req)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	c.Request().SetBody(body)
	// Audit log: WHO is changing WHAT egress rules on WHICH sandbox.
	// Goes to structured logs for later grep / SIEM ingest.
	log.WithContext(c.UserContext()).Infof("[audit] egress.set user=%s sandbox=%s rules=%v ip=%s",
		utils.UserIDFromContext(c.UserContext()), id, req.Egress, c.IP())
	if rec.Status == models.StatusPaused {
		updated, err := h.repo.SetEgressIfPaused(c.UserContext(), id, req.Egress)
		if err != nil {
			log.WithContext(c.UserContext()).Errorf("[egress] persist paused sandbox %s: %v", id, err)
			return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
		}
		if !updated {
			return httpx.Fail(c, fiber.StatusConflict,
				"sandbox state changed while updating egress; retry when resume completes")
		}
		return httpx.Success(c, proto.EgressView{ID: id, Egress: req.Egress})
	}
	return h.forwardBySandbox(c, "/v1/sandboxes/"+id+"/egress")
}

// handlePatchSandbox mutates DB-only fields on the sandbox row. Today the
// only such field is ingress_enabled — host-side state isn't touched, so
// no host hop is needed (mirrors the pattern used by admin cordon/drain).
func (h *Handler) HandlePatchSandbox(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	id := c.Params(middlewares.ParamSandboxID)
	ctx := c.UserContext()
	rec, err := h.repo.Get(ctx, id)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil || !ownerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	// PATCH changes durable row state (currently labels, ingress and auto-pause).
	// Keep those writes in the sandbox's home region during replication gaps.
	if rec.Region != "" && rec.Region != h.region {
		return h.forwardToPeerControl(c, rec.Region, c.Method(), c.Path())
	}
	var req patchSandboxReq
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if req.IngressEnabled != nil {
		if err := h.repo.SetIngressEnabled(ctx, id, *req.IngressEnabled); err != nil {
			log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

			return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
		}
	}
	if req.DisableAutoPause {
		if err := h.repo.SetAutoPause(ctx, id, nil); err != nil {
			log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

			return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
		}
	} else if req.AutoPauseAfterSeconds != nil {
		v := *req.AutoPauseAfterSeconds
		if v < 60 || v > 86400 {
			return httpx.Fail(c, fiber.StatusBadRequest,
				"auto_pause_after_seconds must be between 60 and 86400")
		}
		if err := h.repo.SetAutoPause(ctx, id, req.AutoPauseAfterSeconds); err != nil {
			log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

			return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
		}
	}
	if req.Labels != nil {
		merged := make(map[string]string, len(rec.Labels)+len(req.Labels))
		for key, value := range rec.Labels {
			merged[key] = value
		}
		for key, value := range req.Labels {
			merged[key] = value
		}
		if field, msg := validateLabels(merged); msg != "" {
			return httpx.Fail(c, fiber.StatusBadRequest, map[string]string{field: msg})
		}
		if err := h.repo.SetSandboxLabels(ctx, id, merged); err != nil {
			log.WithContext(c.UserContext()).Errorf("[handler] update labels: %v", err)
			return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
		}
	}
	out, err := h.repo.Get(ctx, id)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if out == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	return httpx.Success(c, h.viewWith(*out))
}

// HandleAddSSHPubkey appends one or more OpenSSH-formatted public keys
// to a sandbox's ssh_pubkeys list (the list the gateway uses for
// tunnel auth). Idempotent — already-present keys are silently
// de-duplicated. Used by `createos-cli sync --temp-key`, which mints an
// ephemeral keypair and needs the gateway to accept it.
//
// Auth: API key + sandbox ownership. The sandbox's gateway/ingress
// state isn't touched; the new keys take effect on the next tunnel
// open. (Active tunnels are unaffected — they already authed with
// whatever key the user had at the time.)
func (h *Handler) HandleAddSSHPubkey(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	id := c.Params(middlewares.ParamSandboxID)
	ctx := c.UserContext()
	rec, err := h.repo.Get(ctx, id)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil || !ownerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if rec.Region != "" && rec.Region != h.region {
		return h.forwardToPeerControl(c, rec.Region, c.Method(), c.Path())
	}
	var req addSSHPubkeyReq
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if len(req.Keys) == 0 {
		return httpx.Fail(c, fiber.StatusBadRequest, "keys is required (non-empty array)")
	}
	// Validate + canonicalize each key. Reject the whole request on the
	// first bad entry so the caller knows exactly what's wrong, rather
	// than partial-applying.
	// Filter empties before canonicalizing so we keep the friendly
	// "no usable keys in request" path; everything else (parse error,
	// multi-key smuggling, comment shenanigans) bubbles up through the
	// canonicalizer's badIdx/error signal.
	cleaned := make([]string, 0, len(req.Keys))
	for _, raw := range req.Keys {
		if s := strings.TrimSpace(raw); s != "" {
			cleaned = append(cleaned, s)
		}
	}
	normalized, badIdx, perr := canonicalizeSSHPubkeys(cleaned)
	if perr != nil {
		return httpx.Fail(c, fiber.StatusBadRequest,
			fmt.Sprintf("keys[%d]: %v", badIdx, perr))
	}
	if len(normalized) == 0 {
		return httpx.Fail(c, fiber.StatusBadRequest, "no usable keys in request")
	}
	// Merge with existing, de-dup by canonical form.
	seen := make(map[string]struct{}, len(rec.SSHPubkeys)+len(normalized))
	merged := make([]string, 0, len(rec.SSHPubkeys)+len(normalized))
	for _, k := range rec.SSHPubkeys {
		s := strings.TrimSpace(k)
		if _, dup := seen[s]; dup || s == "" {
			continue
		}
		seen[s] = struct{}{}
		merged = append(merged, s)
	}
	for _, k := range normalized {
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		merged = append(merged, k)
	}
	// Cap the list size — a misbehaving / malicious client could
	// otherwise loop this endpoint forever and bloat the sandbox row
	// without bound. 16 is roomy for legitimate use (a few personal
	// keys + a few team / CI keys) but cheap on the DB side.
	const maxSSHPubkeysPerSandbox = 16
	if len(merged) > maxSSHPubkeysPerSandbox {
		return httpx.Fail(c, fiber.StatusBadRequest, fmt.Sprintf(
			"too many ssh keys (max %d per sandbox); existing=%d, would be %d",
			maxSSHPubkeysPerSandbox, len(rec.SSHPubkeys), len(merged)))
	}
	if err := h.repo.SetSSHPubkeys(ctx, id, merged); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] SetSSHPubkeys(%s): %v", id, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, addSSHPubkeyResp{Count: len(merged)})
}

func (h *Handler) HandleFileUpload(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	// Owner check BEFORE TouchActivity: without this, an attacker with
	// any sandbox id and their own API key could repeatedly POST and
	// keep the victim's last_activity_at fresh — preventing auto-pause
	// from ever firing on the victim's sandbox.
	rec, _ := h.repo.Get(c.UserContext(), id)
	if rec == nil || !runtimeOwnerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if rec.Status != models.StatusRunning {
		if rec.Status == models.StatusPaused || rec.Status == models.StatusError {
			return httpx.Fail(c, fiber.StatusConflict,
				"sandbox is "+string(rec.Status)+"; resume it before accessing files")
		}
		return httpx.Fail(c, fiber.StatusConflict,
			"sandbox is "+string(rec.Status)+"; file access requires a running sandbox")
	}
	if rec.AutoPauseAfterSeconds != nil {
		go h.repo.TouchActivity(context.WithoutCancel(c.UserContext()), strings.Clone(id), rec.BandwidthUsedBytes+rec.BandwidthIngressBytes) //nolint:errcheck
	}
	return h.forwardBySandboxUsingRec(c, "/v1/sandboxes/"+id+"/files", rec)
}

func (h *Handler) HandleFileDownload(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	rec, _ := h.repo.Get(c.UserContext(), id)
	if rec == nil || !runtimeOwnerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if rec.Status != models.StatusRunning {
		if rec.Status == models.StatusPaused || rec.Status == models.StatusError {
			return httpx.Fail(c, fiber.StatusConflict,
				"sandbox is "+string(rec.Status)+"; resume it before accessing files")
		}
		return httpx.Fail(c, fiber.StatusConflict,
			"sandbox is "+string(rec.Status)+"; file access requires a running sandbox")
	}
	if rec.AutoPauseAfterSeconds != nil {
		go h.repo.TouchActivity(context.WithoutCancel(c.UserContext()), strings.Clone(id), rec.BandwidthUsedBytes+rec.BandwidthIngressBytes) //nolint:errcheck
	}
	return h.forwardBySandboxUsingRec(c, "/v1/sandboxes/"+id+"/files", rec)
}

// forwardBySandbox resolves a sandbox's owning host and forwards the request.
// Owner check happens here too: if the caller doesn't own the sandbox, return
// 404 immediately rather than letting the host service layer answer (avoids
// unnecessary forwarding and keeps cross-tenant probes cheap).
// forwardBySandbox loads the sandbox row, owner-checks, resolves the
// owning host, and forwards the request over mTLS. Legacy convenience
// wrapper — new callers that already hold a *models.Sandbox from an
// upstream check (e.g. HandleExec's ownership gate) should invoke
// forwardBySandboxUsingRec directly to skip the redundant Get.
func (h *Handler) forwardBySandbox(c *fiber.Ctx, path string) error {
	return h.forwardBySandboxUsingRec(c, path, nil)
}

// forwardBySandboxUsingRec is forwardBySandbox with an optional
// pre-fetched sandbox record. When rec is non-nil, the DB round-trip
// for the sandbox row is skipped — saves ~30ms under contention on
// hot-path calls like exec (measured 2025-07-17). Ownership is
// re-verified against the caller so a bug in the upstream check
// can't grant access to a wrong sandbox.
func (h *Handler) forwardBySandboxUsingRec(c *fiber.Ctx, path string, rec *models.Sandbox) error {
	return h.forwardBySandboxUsingRecWithClient(c, path, rec, h.http)
}

func (h *Handler) forwardBySandboxUsingRecWithClient(
	c *fiber.Ctx,
	path string,
	rec *models.Sandbox,
	client *http.Client,
) error {
	id := c.Params(middlewares.ParamSandboxID)
	ctx := c.UserContext()
	tStart := time.Now()
	var getSbMs float64
	if rec == nil {
		tA := time.Now()
		var err error
		rec, err = h.repo.Get(ctx, id)
		getSbMs = float64(time.Since(tA).Microseconds()) / 1000.0
		if err != nil {
			log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

			return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
		}
	}
	if rec == nil || !runtimeOwnerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	hostID := ""
	if rec.HostID != nil {
		hostID = *rec.HostID
	}
	tB := time.Now()
	host, err := h.getHostCached(ctx, hostID)
	getHostMs := float64(time.Since(tB).Microseconds()) / 1000.0
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] service unavailable: %v", err)

		return httpx.Error(c, fiber.StatusServiceUnavailable, "service unavailable")
	}
	if host == nil {
		return httpx.Error(c, fiber.StatusServiceUnavailable, "host unavailable")
	}
	tC := time.Now()
	if strings.HasSuffix(path, "/files") && c.Method() == fiber.MethodPut {
		err = ForwardFileUploadToAs(c, *host, path, client, forwardedOwnerID(c, rec))
	} else if strings.HasSuffix(path, "/files") && c.Method() == fiber.MethodGet {
		err = ForwardFileDownloadToAs(c, *host, path, client, forwardedOwnerID(c, rec))
	} else {
		err = ForwardResponseToAs(c, *host, path, client, forwardedOwnerID(c, rec))
	}
	fwdMs := float64(time.Since(tC).Microseconds()) / 1000.0
	totalMs := float64(time.Since(tStart).Microseconds()) / 1000.0
	// Internal telemetry — server-only. Grep by sandbox id to correlate
	// wall-clock client latency with per-phase control-side breakdown.
	log.WithContext(c.UserContext()).Infof("[fwd-trace] sb=%s path=%s get_sb=%.2f get_host=%.2f forward=%.2f total=%.2f",
		id, path, getSbMs, getHostMs, fwdMs, totalMs)
	return err
}

// handleListShapes returns the catalog of VM shapes.
func (h *Handler) HandleListShapes(c *fiber.Ctx) error {
	limit := c.QueryInt(middlewares.QueryLimit, 50)
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	offset := c.QueryInt(middlewares.QueryOffset, 0)
	if offset < 0 {
		offset = 0
	}
	page, total := httpx.PageSlice(h.shapes.Shapes(c.UserContext()), limit, offset)
	return httpx.Paginated(c, page, total, limit, offset, len(page))
}

// ingressURLTemplate builds the public URL hint for a sandbox. The
// sandbox id is `sb-<ulid>` — already a valid DNS label — but the
// ingress addresses VMs by the bare ulid, so we strip the `sb-`
// prefix here too. Port is left literal so clients can substitute
// their own.
func (h *Handler) ingressURLTemplate(sandboxID string) string {
	ulid := strings.TrimPrefix(sandboxID, "sb-")
	return fmt.Sprintf("https://%s-<port>.%s", ulid, h.ingressDomainSuffix)
}

// handleWhoAmI introspects the bearer key used on the request and
// returns the resolved identity. Useful as a connectivity + auth probe
// — equivalent to `aws sts get-caller-identity` for createos-cli users.
//
// We deliberately do not return the full key. Only the last 4 chars
// are exposed so the caller can visually confirm "yes, this is the
// key I think it is" against a key manager entry.
func (h *Handler) HandleWhoAmI(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized,
			types.AuthError{Auth: "invalid api key"})
	}
	view := whoAmIView{UserID: userID}

	// Tally sandboxes for this user. Single List call with status="" gets
	// every row; we tally client-side. 500 is plenty for current usage —
	// if a user genuinely has >500 sandboxes, raise the limit later or
	// add a dedicated count query.
	rows, err := h.repo.List(c.UserContext(), "", userID, "", 500)
	if err == nil {
		for _, r := range rows {
			view.Stats.Total++
			switch r.Status {
			case "running":
				view.Stats.Running++
			case "paused":
				view.Stats.Paused++
			case "destroyed", "failed":
				// terminal states — counted in Total but not split out
			default:
				view.Stats.Other++
			}
		}
	}
	return httpx.Success(c, view)
}

// clusterRootfsUnion returns the sorted union of rootfs names advertised
// across active hosts, minus any names flagged disabled in rootfs_catalog.
// Two indexed DB reads; no per-host HTTP. Shared by HandleListRootfs and
// the create handler's pre-forward validation so /v1/rootfs and a
// rejection from POST /v1/sandboxes agree on what's actually available.
//
// Served from a 30s TTL cache (cache.Rootfs). The union changes on
// host restart / operator deprecation cadence — minutes to days — so
// stale-by-up-to-30s is acceptable. On cold/stale, one DB round-trip
// (ListHosts + ListRootfsMetadata) refreshes the whole snapshot. See
// internal/apiserver/cache/rootfs.go for the SAFETY note about templates.
func (h *Handler) clusterRootfsUnion(ctx context.Context) ([]string, map[string]models.RootfsCatalog, error) {
	// Cache path (typical): single-flighted so a 100-parallel burst on
	// an expired cache fires ONE DB refresh, not 100. Without this
	// dedup we'd hit a thundering-herd every 30s.
	if h.rootfsCache != nil {
		snap, err := h.rootfsCache.GetOrLoad(func() (*cache.Snapshot, error) {
			return loadRootfsUnion(ctx, h.repo)
		})
		if err != nil {
			return nil, nil, err
		}
		return snap.Names, snap.MetaByN, nil
	}
	// Fallback (test/bootstrap): direct load, no cache.
	snap, err := loadRootfsUnion(ctx, h.repo)
	if err != nil {
		return nil, nil, err
	}
	return snap.Names, snap.MetaByN, nil
}

// loadRootfsUnion is the DB read that populates a cache.Snapshot.
// Runs ListHosts + ListRootfsMetadata (two indexed queries) and builds
// the union in Go. Extracted from clusterRootfsUnion so the cache path
// and the fallback path share one implementation.
func loadRootfsUnion(ctx context.Context, repo *models.Repo) (*cache.Snapshot, error) {
	hosts, err := repo.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	meta, err := repo.ListRootfsMetadata(ctx)
	if err != nil {
		return nil, err
	}
	metaByName := make(map[string]models.RootfsCatalog, len(meta))
	for _, m := range meta {
		metaByName[m.Name] = m
	}
	seen := make(map[string]struct{})
	var names []string
	for _, host := range hosts {
		if host.Status != "active" {
			continue
		}
		for _, rf := range host.Rootfses {
			if _, dup := seen[rf]; dup {
				continue
			}
			if m, ok := metaByName[rf]; ok && m.Disabled {
				continue
			}
			seen[rf] = struct{}{}
			names = append(names, rf)
		}
	}
	sort.Strings(names)
	return &cache.Snapshot{Names: names, MetaByN: metaByName}, nil
}

// handleListRootfs returns the cluster-wide rootfs catalog.
//
// Names come from the union of hosts.rootfses across all active hosts
// (the source of truth for which ext4 images are actually available).
// Metadata (description, disabled, deprecated, successor) is joined from
// rootfs_catalog. Rows marked disabled are filtered out — to the user
// they don't exist. The default name is taken from the first active
// host's listing (representative; fleets typically standardise it).
func (h *Handler) HandleListRootfs(c *fiber.Ctx) error {
	ctx := c.UserContext()
	names, metaByName, err := h.clusterRootfsUnion(ctx)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[rootfs] catalog union failed: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	hosts, err := h.repo.ListHosts(ctx)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[rootfs] list hosts failed: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}

	entries := make([]proto.RootfsEntry, 0, len(names))
	for _, n := range names {
		e := proto.RootfsEntry{Name: n}
		if m, ok := metaByName[n]; ok {
			e.Description = m.Description
			e.Deprecated = m.Deprecated
			e.Successor = m.Successor
		}
		entries = append(entries, e)
	}

	// Resolve `default` by asking the first active host. If that host's
	// default has been disabled in rootfs_catalog, fall back to the first
	// non-disabled name in the union — better than returning empty.
	var defaultName string
	for _, host := range hosts {
		if host.Status != "active" {
			continue
		}
		if v, err := fetchHostDefaultRootfs(ctx, h.http, host); err == nil {
			if m, ok := metaByName[v]; !ok || !m.Disabled {
				defaultName = v
			}
			break
		}
	}
	if defaultName == "" && len(names) > 0 {
		defaultName = names[0]
	}

	return httpx.Success(c, proto.RootfsView{
		Rootfs:  names,
		Default: defaultName,
		Entries: entries,
	})
}

// fetchHostDefaultRootfs fetches just the `default` field from a host's
// own /v1/rootfs. Used by the cluster aggregator to pick a representative
// default without replicating the host's per-process catalog logic.
//
// Uses a tight per-call timeout so a single unreachable host doesn't
// stall the whole aggregator: the handler loops over every active host
// and falls through on error, so each blocking call would otherwise
// stack to the shared client's 120 s default. The host endpoint is an
// in-process catalog read, ~milliseconds when reachable.
func fetchHostDefaultRootfs(ctx context.Context, client *http.Client, h models.Host) (string, error) {
	url := "http://" + h.Addr + "/v1/rootfs"
	tctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(tctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var env rootfsDefaultEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return "", err
	}
	return env.Data.Default, nil
}

// HandleUserTunnel is the API-key-authenticated tunnel entrypoint behind
// `createos-cli tunnel`. It authorises the caller by sandbox ownership instead of
// an SSH key, so users can port-forward without provisioning a key at
// create time. One HTTP Upgrade per forwarded TCP connection.
func (h *Handler) HandleUserTunnel(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	rec, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		if errors.Is(err, api.ErrNotFound) {
			return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		}
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil || !runtimeOwnerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if rec.AutoPauseAfterSeconds != nil {
		go h.repo.TouchActivity(context.WithoutCancel(c.UserContext()), strings.Clone(id), rec.BandwidthUsedBytes+rec.BandwidthIngressBytes) //nolint:errcheck
	}
	return h.tunnelSplice(c, id, forwardedOwnerID(c, rec))
}

// tunnelSplice opens the upstream host tunnel for (id, :port) and hijacks
// the incoming connection into a raw bidirectional byte pipe. Shared by
// the internal (JWT) and user-facing (API-key) tunnel handlers.
func (h *Handler) tunnelSplice(c *fiber.Ctx, id, userID string) error {
	portStr := c.Params(middlewares.ParamPort)
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid")
	}

	// Open the upstream tunnel to the host BEFORE hijacking — if it fails we
	// still want to emit a proper JSend error, not a half-upgraded conn.
	upstream, err := h.OpenTunnelAs(c.UserContext(), id, port, userID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return httpx.Fail(c, fiber.StatusNotFound, err.Error())
		}
		log.WithContext(c.UserContext()).Errorf("[handler] upstream error: %v", err)

		return httpx.Error(c, fiber.StatusBadGateway, "upstream error")
	}

	// Hijack and splice. Fiber's fasthttp context schedules the callback after
	// the response headers flush, so we emit 101 first and the splicing happens
	// on the raw socket.
	logCtx := c.UserContext()
	c.Context().Hijack(func(netConn net.Conn) {
		defer upstream.Close()
		defer netConn.Close()
		log.WithContext(logCtx).Infof("[control] tunnel sandbox=%s port=%d active", id, port)
		done := make(chan struct{}, 2)
		// Copy errors are just one side hanging up; the deferred Closes tear
		// the other direction down regardless.
		go func() { _, _ = io.Copy(upstream, netConn); done <- struct{}{} }()
		go func() { _, _ = io.Copy(netConn, upstream); done <- struct{}{} }()
		<-done
	})
	c.Status(fiber.StatusSwitchingProtocols)
	c.Set("Connection", "Upgrade")
	c.Set("Upgrade", "tcp-tunnel")
	return nil
}

// HandleShell is the API-key-authenticated interactive-shell entrypoint
// behind `createos-cli shell` (the keyless, no-SSH path). It authorises by
// sandbox ownership, opens a byte pipe to the agent's PTY listener via
// the owning host, and hijacks the incoming connection into a raw
// bidirectional splice. The data/resize framing is end-to-end between
// createos-cli and the agent — control just shuttles bytes.
func (h *Handler) HandleShell(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	rec, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		if errors.Is(err, api.ErrNotFound) {
			return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		}
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil || !runtimeOwnerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if rec.Status != models.StatusRunning {
		if rec.Status == models.StatusPaused || rec.Status == models.StatusError {
			return httpx.Fail(c, fiber.StatusConflict,
				"sandbox is "+string(rec.Status)+"; resume it before opening a shell")
		}
		return httpx.Fail(c, fiber.StatusConflict,
			"sandbox is "+string(rec.Status)+"; shell requires a running sandbox")
	}

	stopActivity := func() {}
	if rec.AutoPauseAfterSeconds != nil {
		stopActivity = h.keepInteractiveActivity(id, *rec.AutoPauseAfterSeconds)
	}
	upstream, err := h.OpenShellAs(c.UserContext(), id, forwardedOwnerID(c, rec))
	if err != nil {
		stopActivity()
		if strings.Contains(err.Error(), "not found") {
			return httpx.Fail(c, fiber.StatusNotFound, err.Error())
		}
		log.WithContext(c.UserContext()).Errorf("[handler] upstream error: %v", err)

		return httpx.Error(c, fiber.StatusBadGateway, "upstream error")
	}

	logCtx := c.UserContext()
	c.Context().Hijack(func(netConn net.Conn) {
		defer upstream.Close()
		defer netConn.Close()
		defer stopActivity()
		log.WithContext(logCtx).Infof("[control] shell sandbox=%s active", id)
		done := make(chan struct{}, 2)
		// Copy errors are the normal way a hijacked tunnel ends (peer
		// closes); the deferred Closes handle teardown.
		go func() { _, _ = io.Copy(upstream, netConn); done <- struct{}{} }()
		go func() { _, _ = io.Copy(netConn, upstream); done <- struct{}{} }()
		<-done
	})
	c.Status(fiber.StatusSwitchingProtocols)
	c.Set("Connection", "Upgrade")
	c.Set("Upgrade", "tcp-tunnel")
	return nil
}

// recordToView mirrors the service-layer projection since we bypass the
// Service interface and talk to the repo directly from the control plane.
// Delegates to api.NewSandboxView so the projection lives in one place
// (and internal-only fields get stripped consistently).
func recordToView(r models.Sandbox) api.SandboxView {
	return api.NewSandboxView(r)
}

// viewWith stamps the ingress URL template onto a view when ingress is
// enabled AND the cluster's domain suffix is configured. Keeps the
// underlying recordToView pure for callers that don't need URL
// enrichment.
func (h *Handler) viewWith(r models.Sandbox) api.SandboxView {
	v := recordToView(r)
	if v.IngressEnabled && h.ingressDomainSuffix != "" {
		v.IngressURLTemplate = h.ingressURLTemplate(v.ID)
	}
	return v
}

// HandleShellWS is the browser-friendly flavor of HandleShell. Browsers
// can't speak raw HTTP/Upgrade with a tcp-tunnel protocol, but they can
// open a WebSocket. This handler wraps the exact same upstream byte pipe
// (control → host → agent PTY) inside a WS connection.
//
// Auth: same Bearer token, but accepted via `?token=` query string
// because browser WebSocket APIs can't set Authorization headers.
//
// Wire shape:
//   - WS binary message from browser → upstream verbatim (browser is
//     responsible for the framing the agent expects: 0x00+bytes for
//     stdin, 0x01+u16cols+u16rows for SIGWINCH).
//   - upstream bytes → WS binary message (raw agent stdout, no framing).
func (h *Handler) HandleShellWS(c *fiber.Ctx) error {
	// Auth is already done by MustBeAuthenticated for /v1/* routes,
	// but that middleware only reads the Authorization header. Browsers
	// can't set it on WS, so accept ?token=… as a fallback BEFORE the
	// upgrade. We rely on the route group having both middlewares wired.
	id := c.Params(middlewares.ParamSandboxID)
	rec, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		if errors.Is(err, api.ErrNotFound) {
			return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		}
		log.WithContext(c.UserContext()).Errorf("[shell-ws] lookup: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil || !runtimeOwnerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if rec.Status != models.StatusRunning {
		if rec.Status == models.StatusPaused || rec.Status == models.StatusError {
			return httpx.Fail(c, fiber.StatusConflict,
				"sandbox is "+string(rec.Status)+"; resume it before opening a shell")
		}
		return httpx.Fail(c, fiber.StatusConflict,
			"sandbox is "+string(rec.Status)+"; shell requires a running sandbox")
	}
	// Stash the sandbox id on Locals so the WS handler can read it.
	c.Locals("shell_sb_id", id)
	c.Locals("shell_owner_id", forwardedOwnerID(c, rec))
	return wsShellUpgrade(c, h, rec.AutoPauseAfterSeconds)
}
