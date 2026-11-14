package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/middlewares"
	"github.com/NodeOps-app/createos-sandbox/internal/audit"
	"github.com/NodeOps-app/createos-sandbox/internal/hostrpc"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/api"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/vm"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/placementpolicy"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/internal/sandboxlifecycle"
	"github.com/NodeOps-app/createos-sandbox/internal/storage"
	"github.com/NodeOps-app/createos-sandbox/models"
)

type forkReq struct {
	SSHPubkeys          []string          `json:"ssh_pubkeys,omitempty"`
	Egress              []string          `json:"egress,omitempty"`
	IngressEnabled      *bool             `json:"ingress_enabled,omitempty"`
	Envs                map[string]string `json:"envs,omitempty"`
	BandwidthQuotaBytes *int64            `json:"bandwidth_quota_bytes,omitempty"`
	StartPaused         bool              `json:"start_paused,omitempty"`
}

type clearedResp struct {
	Cleared bool `json:"cleared"`
}

// HandlePause sends the typed pause command to the owning host. The host's
// service layer does the CAS to 'pausing' and starts the background work; the
// control API relays the host's response to the caller.
func (h *Handler) HandlePause(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	rec, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[pause] %s repo.Get: %v", id, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil || !runtimeOwnerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if rec.Status != models.StatusRunning && rec.Status != models.StatusPausing {
		return httpx.Fail(c, fiber.StatusConflict,
			fmt.Sprintf("sandbox is %s, expected running", rec.Status))
	}
	recHostID := ""
	if rec.HostID != nil {
		recHostID = *rec.HostID
	}
	host, err := h.repo.GetHost(c.UserContext(), recHostID)
	if err != nil || host == nil {
		log.WithContext(c.UserContext()).Warnf("[pause] %s host %q not found", id, recHostID)
		return httpx.Error(c, fiber.StatusServiceUnavailable, "owning host unavailable")
	}
	c.Set("X-Poll-After", "2")
	response, err := hostrpc.Pause(
		c.UserContext(), h.http, *host, id, forwardedOwnerID(c, rec),
	)
	if err != nil {
		log.WithContext(c.UserContext()).Warnf("[pause] %s host %q unreachable: %v", id, recHostID, err)
		return httpx.Error(c, fiber.StatusBadGateway, "host unreachable")
	}
	defer response.Body.Close()
	if err := writeBufferedHostResponse(c, response); err != nil {
		return err
	}
	h.audit.Emit(c.UserContext(), h.auditCtxForSandboxLifecycle(c, rec),
		audit.ActionSandboxPause, audit.OperationModify,
		audit.BuildSandboxPause(rec))
	return nil
}

// handleResume orchestrates resume: schedule a host, mark resuming,
// forward to chosen host with the row body. The host runs the actual
// download + spawn in a background goroutine.
func (h *Handler) HandleResume(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	ctx := c.UserContext()
	rec, err := h.repo.Get(ctx, id)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[resume] %s repo.Get: %v", id, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil || !runtimeOwnerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if rec.Status != models.StatusPaused && rec.Status != models.StatusError {
		return httpx.Fail(c, fiber.StatusConflict,
			fmt.Sprintf("sandbox is %s, expected paused or error", rec.Status))
	}
	// Resume = user explicitly interacting with the sandbox; reset idle timer.
	// Credit and quota remain attached to the durable owner. A sandbox token
	// is deliberately not inserted into the user context or api_keys table.
	if isSandboxPrincipal(c) {
		isInternal, err := h.repo.IsInternalUser(ctx, rec.CreatedBy)
		if err != nil {
			log.WithContext(c.UserContext()).Errorf("[resume] %s internal-owner lookup: %v", id, err)
			return httpx.Error(c, fiber.StatusServiceUnavailable, "internal error")
		}
		if !isInternal {
			limits := h.limits.Get(ctx, rec.CreatedBy, false)
			if !limits.HasCredit() {
				return httpx.Fail(c, fiber.StatusPaymentRequired,
					"insufficient credit; please top up to continue")
			}
			if status, msg, ok := h.checkSandboxConcurrencyQuotaExceptFor(c, rec.CreatedBy, id, limits); !ok {
				if status >= http.StatusInternalServerError {
					return httpx.Error(c, status, msg)
				}
				return httpx.Fail(c, status, msg)
			}
		}
	} else {
		// Credit gate: resuming a paused sandbox is a cost-incurring action.
		if status, msg, ok := h.checkCredit(c); !ok {
			if status >= http.StatusInternalServerError {
				return httpx.Error(c, status, msg)
			}
			return httpx.Fail(c, status, msg)
		}
		// Concurrent + per-day quota gate. The paused row being resumed is
		// excluded from the count — otherwise a free-tier user (cap=1) with
		// a single paused VM hits 429 trying to start it back up. Plan
		// downgrades that overflow the cap still block resume of the
		// SECOND paused row (count excluding it == 1 >= cap == 1).
		authType, token, hasAuthQ := middlewares.ExtractAuthToken(c)
		if !hasAuthQ {
			return httpx.Fail(c, fiber.StatusUnauthorized, "missing auth")
		}
		keyRec, lookupErr := h.repo.LookupAPIKeyByHash(c.UserContext(), authType, h.apiKeyHasher.Hash(token))
		if lookupErr != nil {
			log.WithContext(c.UserContext()).Errorf("[quota] api-key lookup: %v", lookupErr)
			return httpx.Error(c, fiber.StatusServiceUnavailable, "internal error")
		}
		if keyRec == nil {
			return httpx.Fail(c, fiber.StatusUnauthorized, "unauthorized")
		}
		if !keyRec.IsInternal {
			limits := h.limits.Get(c.UserContext(), keyRec.UserID, keyRec.IsInternal)
			if status, msg, ok := h.checkSandboxConcurrencyQuotaExceptFor(c, keyRec.UserID, id, limits); !ok {
				if status >= http.StatusInternalServerError {
					return httpx.Error(c, status, msg)
				}
				return httpx.Fail(c, status, msg)
			}
		}
	}
	// Resume goes through the scheduler — forward to the owning region's
	// control so its scheduler picks the host. Scheduling locally against
	// a remote region would double-spend reservations.
	if rec.Region != "" && rec.Region != h.region {
		return h.forwardToPeerControl(c, rec.Region, c.Method(), c.Path())
	}

	// Schedule a host. Locality hint = original cached_host_id;
	// exclude any hosts that already failed for this bundle.
	clearFailed := rec.Status == models.StatusError
	if h.schedulerClient == nil {
		return httpx.Error(c, fiber.StatusServiceUnavailable, "external scheduler not configured")
	}
	now := time.Now().UTC()
	st, err := h.repo.MarkResuming(ctx, id, clearFailed, now)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[resume] %s MarkResuming: %v", id, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if st == "" {
		return httpx.Fail(c, fiber.StatusConflict, "row state changed concurrently")
	}

	scheduleReq, berr := placementpolicy.BuildResumeScheduleRequest(ctx, h.repo, rec, placementpolicy.ResumeScheduleOpts{
		Region:      h.region,
		ClearFailed: clearFailed,
	})
	if berr != nil {
		msg := berr.Error()
		_, _ = h.repo.MarkResumeExhausted(ctx, id, &msg)
		var rbe *placementpolicy.ResumeBuildError
		if errors.As(berr, &rbe) && rbe.Retryable {
			return httpx.Error(c, fiber.StatusServiceUnavailable,
				"bundle not yet uploaded to storage; retry shortly")
		}
		return httpx.Error(c, fiber.StatusServiceUnavailable, berr.Error())
	}
	resp, err := h.schedulerClient.Schedule(ctx, scheduleReq)
	if err != nil || resp == nil {
		// Reset row to paused so user can retry later.
		schedMsg := fmt.Sprintf("scheduler: %v", err)
		_, _ = h.repo.MarkResumeExhausted(ctx, id, &schedMsg)
		log.WithContext(c.UserContext()).Warnf("[resume] %s scheduler: %v", id, err)
		return httpx.Error(c, fiber.StatusServiceUnavailable, "no host with capacity")
	}

	// Stamp host_id so next status change persists ownership.
	respHostID := resp.HostID
	if err := h.repo.SetSandboxHost(ctx, id, &respHostID); err != nil {
		rollbackMsg := "set resume host failed: " + err.Error()
		_, _ = h.repo.MarkResumeExhausted(ctx, id, &rollbackMsg)
		log.WithContext(ctx).Errorf("[resume] %s set host: %v", id, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	rec.HostID = &respHostID
	rec.Status = models.StatusResuming

	c.Set("X-Poll-After", "2")
	response, err := hostrpc.Resume(c.UserContext(), h.repo, h.http, resp.HostID, rec)
	if err != nil {
		// Host never acknowledged the kick (TLS handshake / TCP / timeout).
		// Roll the CAS-marked 'resuming' row back to 'paused' so a fresh
		// resume can run. Without this rollback the row pins forever — the
		// host never started the orchestrator goroutine, so no other actor
		// will move the row.
		rollbackMsg := fmt.Sprintf("host %s unreachable during resume kick", resp.HostID)
		if _, mErr := h.repo.MarkResumeExhausted(c.UserContext(), id, &rollbackMsg); mErr != nil {
			log.WithContext(c.UserContext()).Errorf("[resume] %s rollback to paused failed: %v", id, mErr)
		} else {
			log.WithContext(c.UserContext()).Warnf("[resume] %s rolled back resuming→paused: %s", id, rollbackMsg)
		}
		return httpx.Error(c, fiber.StatusBadGateway, "host unreachable")
	}
	defer response.Body.Close()
	if err := writeBufferedHostResponse(c, response); err != nil {
		return err
	}
	// Re-read so the audit payload reflects the resumed host_id.
	if fresh, _ := h.repo.Get(ctx, id); fresh != nil {
		h.audit.Emit(ctx, h.auditCtxForSandboxLifecycle(c, fresh),
			audit.ActionSandboxResume, audit.OperationModify,
			audit.BuildSandboxResume(fresh))
	}
	return nil
}

// handleFork creates a new sandbox by server-side copying the source bundle.
// Source must be 'paused'. Default behavior: forking → running. With
// start_paused=true: forking → paused.
func (h *Handler) HandleFork(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	// Copy off Fiber's request buffer — c.Params is only valid for the
	// duration of the handler. We hand srcID to a background goroutine
	// that outlives the request, so we must own its bytes.
	srcID := string([]byte(c.Params(middlewares.ParamSandboxID)))
	ctx := c.UserContext()

	var req forkReq
	if err := c.BodyParser(&req); err != nil {
		// Body is optional; ignore parse errors on empty bodies.
		req = forkReq{}
	}
	// A fork is a new chargeable sandbox and starts with the cluster default
	// bandwidth allowance, just like POST /v1/sandboxes. Letting callers set
	// this field would bypass the paid recharge path; inheriting it from the
	// source would duplicate any allowance the source previously purchased.
	if req.BandwidthQuotaBytes != nil {
		return httpx.Fail(c, fiber.StatusBadRequest,
			"bandwidth_quota_bytes is not settable at fork; use POST /v1/sandboxes/:id/bandwidth/recharge to grow the quota")
	}

	// Fork requires object storage for the server-side bundle copy.
	if h.storage == nil {
		return httpx.Error(c, fiber.StatusServiceUnavailable, "fork feature not enabled")
	}
	// Credit gate: fork creates a new chargeable sandbox.
	if status, msg, ok := h.checkCredit(c); !ok {
		if status >= http.StatusInternalServerError {
			return httpx.Error(c, status, msg)
		}
		return httpx.Fail(c, status, msg)
	}
	// Concurrent + per-day quota gate. Fork creates a new row that
	// counts toward the cap exactly like POST /v1/sandboxes; without
	// this check a capped user can pause-then-fork to bypass the limit.
	if status, msg, ok := h.checkSandboxConcurrencyQuota(c); !ok {
		if status >= http.StatusInternalServerError {
			return httpx.Error(c, status, msg)
		}
		return httpx.Fail(c, status, msg)
	}

	src, err := h.repo.Get(ctx, srcID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[fork] %s repo.Get: %v", srcID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if src == nil || !ownerOK(c, src) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if src.Status != models.StatusPaused {
		return httpx.Fail(c, fiber.StatusConflict, "source must be paused")
	}
	// Fork runs in the source sandbox's region, which owns scheduling and
	// lifecycle updates. Forward cross-region requests to that control.
	if src.Region != "" && src.Region != h.region {
		return h.forwardToPeerControl(c, src.Region, c.Method(), c.Path())
	}
	// A paused row must always refer to a durable bundle. Fail closed if an
	// older or corrupted row violates that invariant.
	if src.BundleUploadedAt == nil {
		return httpx.Fail(c, fiber.StatusConflict,
			"paused sandbox bundle is unavailable")
	}

	newID := vm.NewSandboxID()
	newRow := *src
	newRow.ID = newID
	newRow.Status = models.StatusForking
	newRow.HostID = nil
	newRow.IP = nil
	newRow.MAC = nil
	newRow.APISock = nil
	newRow.ContainerID = nil
	newRow.FCPid = 0
	newRow.OverlayPath = nil
	// cached_host_id, cpu_vendor, and cpu_family are inherited from the source
	// row inside insertForkRow's INSERT ... SELECT, so they can't drift; this
	// copy just keeps the returned struct accurate for the response view.
	newRow.CachedHostID = src.CachedHostID
	newRow.CachedUntil = nil
	newRow.LastResumedAt = nil
	newRow.ResumeFailedHosts = nil
	newRow.LastResumeError = nil
	newRow.LastResumeAttemptAt = nil
	newRow.LastPauseError = nil
	newRow.LastPauseAttemptAt = nil
	newRow.BandwidthQuotaBytes = h.defaultBandwidthQuotaBytes
	newRow.BandwidthUsedBytes = 0
	newRow.BandwidthCapped = false
	newRow.BandwidthIngressBytes = 0
	newRow.CreatedAt = time.Now().UTC()
	newRow.RunningAt = nil
	newRow.DestroyedAt = nil
	newRow.PausedAt = nil
	newRow.SnapshotURI = nil
	newRow.SnapshotManifest = nil
	// A fork is a new, independent sandbox — give it its own name.
	// Reusing the source's name collides on the per-user unique-name
	// index (idx_sandboxes_user_name) since both rows are non-terminal.
	forkName := generateSandboxName()
	newRow.Name = &forkName
	forkedFrom := srcID
	newRow.ForkedFrom = &forkedFrom
	if len(req.Egress) > 0 {
		newRow.Egress = req.Egress
	}
	if len(req.SSHPubkeys) > 0 {
		newRow.SSHPubkeys = req.SSHPubkeys
	}
	if req.IngressEnabled != nil {
		newRow.IngressEnabled = *req.IngressEnabled
	}
	if len(req.Envs) > 0 {
		newRow.Envs = req.Envs
	}
	created, err := h.repo.MarkForking(ctx, srcID, newRow)
	if errors.Is(err, models.ErrForkSourceUnavailable) {
		return httpx.Fail(c, fiber.StatusConflict, "source is no longer available for fork")
	}
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[fork] %s → %s MarkForking: %v", srcID, newID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}

	// Run the object copy + (optional) resume in a background goroutine
	// so the API call returns 202 quickly.
	go h.runForkBackground(strings.Clone(srcID), newID, *created, req.StartPaused)

	c.Set("X-Poll-After", "1")
	view := api.NewSandboxView(*created)
	h.audit.Emit(ctx, h.auditCtxWithSubject(c, "sandbox", created.ID),
		audit.ActionSandboxFork, audit.OperationCreate,
		audit.BuildSandboxFork(created, srcID, req.StartPaused))
	return httpx.SuccessStatus(c, fiber.StatusAccepted, view)
}

func (h *Handler) runForkBackground(srcID, newID string, src models.Sandbox, startPaused bool) {
	// Bound the copy independently of the client connection. A separate cleanup
	// context can still publish failure when the copy deadline has expired.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	published := false
	defer func() {
		if !published {
			h.cleanupFailedFork(newID)
		}
	}()
	srcPrefix, dstPrefix := storage.BundlePrefix(srcID), storage.BundlePrefix(newID)
	for _, name := range []string{storage.ArtifactMemfile, storage.ArtifactVMState, storage.ArtifactOverlay, storage.ArtifactManifest} {
		if err := ctx.Err(); err != nil {
			log.Errorf("[fork] %s copy deadline: %v", newID, err)
			return
		}
		if err := h.storage.Copy(ctx, srcPrefix+name, dstPrefix+name); err != nil {
			log.Errorf("[fork] %s → %s copy %s: %v", srcID, newID, name, err)
			return
		}
	}
	uri := "s3://" + dstPrefix
	status, err := h.repo.MarkForkPaused(ctx, newID, src.SnapshotManifest, &uri, time.Now().UTC(), h.billingEmitter)
	if err != nil {
		log.Errorf("[fork] %s MarkForkPaused: %v", newID, err)
		return
	}
	if status != string(models.StatusPaused) {
		log.Infof("[fork] %s completion skipped: state changed", newID)
		return
	}
	published = true
	if startPaused {
		log.Infof("[fork] %s → %s done (start_paused=true)", srcID, newID)
		return
	}
	resumeCtx, stop := context.WithTimeout(context.Background(), 60*time.Second)
	defer stop()
	if err := h.KickoffInternalResume(resumeCtx, newID); err != nil {
		log.Warnf("[fork] %s auto-resume: %v", newID, err)
	}
}

func (h *Handler) cleanupFailedFork(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	message := "Unable to create sandbox copy. Please try again."
	if _, err := h.repo.MarkForkFailed(ctx, id, &message, h.billingEmitter); err != nil {
		log.Errorf("[fork] %s MarkForkFailed: %v", id, err)
		return
	}
	// A successful/ambiguous publication must never lose its durable bundle.
	states, err := h.repo.StatusOfIDs(ctx, []string{id})
	if err != nil {
		log.Errorf("[fork] %s cleanup status: %v", id, err)
		return
	}
	switch models.Status(states[id]) {
	case models.StatusFailed, models.StatusDestroying, models.StatusDestroyed:
	default:
		return
	}
	for _, name := range []string{storage.ArtifactMemfile, storage.ArtifactVMState, storage.ArtifactOverlay, storage.ArtifactManifest} {
		if err := h.storage.Delete(ctx, storage.BundlePrefix(id)+name); err != nil {
			log.Warnf("[fork] %s cleanup %s: %v", id, name, err)
		}
	}
}

// KickoffInternalResume bypasses the HTTP layer to trigger a resume
// from inside control. Used by fork's auto-resume path. Delegates to
// sandboxlifecycle.KickoffResume so the sweep CronJob can run the same path.
func (h *Handler) KickoffInternalResume(ctx context.Context, id string) error {
	return sandboxlifecycle.KickoffResume(ctx, sandboxlifecycle.ResumeDeps{
		Repo:     h.repo,
		Client:   h.schedulerClient,
		HostHTTP: h.http,
		Region:   h.region,
	}, id)
}

// HandleInternalWake is the wake-on-request trigger. The ingress calls it
// (mTLS role=ingress) when a browser hits the public URL of a paused
// sandbox. It fires the resume on a detached context and returns 202
// immediately — the ingress serves the "waking" page and reloads until the
// sandbox flips to running.
//
// Idempotent: a no-op unless the sandbox is exactly `paused`. Anything else
// (pausing/resuming/creating/running/destroyed) is already in the right
// state or already transitioning, so there's nothing to kick — the resume
// CAS inside ResumeKickoff is the real double-fire guard on top of this.
func (h *Handler) HandleInternalWake(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	rec, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[wake] %s repo.Get: %v", id, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	// The ingress mTLS role proves which service made the request, but it
	// does not by itself grant permission to wake every sandbox. Re-check
	// the owner's public-ingress opt-in here so a compromised ingress peer
	// cannot resume a private sandbox by calling this endpoint directly.
	// Return the same 404 used for an unknown sandbox to avoid exposing its
	// existence to a caller that is not authorised to wake it.
	if !rec.IngressEnabled {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if rec.Status != models.StatusPaused {
		// Already running/transitioning/gone — nothing to wake.
		return httpx.SuccessStatus(c, fiber.StatusAccepted, struct{}{})
	}
	// Cross-region: resume must run in the sandbox's own region (that
	// region's scheduler owns its hosts + the snapshot is staged there).
	// Forward to the owning region's control, which repeats this handler
	// locally and resumes where rec.Region == its own region. The peer
	// accepts role=control (this dial's identity).
	if rec.Region != "" && rec.Region != h.region {
		return h.forwardToPeerControl(c, rec.Region, c.Method(), c.Path())
	}
	// Public ingress is user-triggered work: apply the same durable-owner
	// credit and quota gates as an explicit resume before scheduling it.
	isInternal, err := h.repo.IsInternalUser(c.UserContext(), rec.CreatedBy)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[wake] %s internal-owner lookup: %v", id, err)
		return httpx.Error(c, fiber.StatusServiceUnavailable, "internal error")
	}
	if !isInternal {
		limits := h.limits.Get(c.UserContext(), rec.CreatedBy, false)
		if !limits.HasCredit() {
			return httpx.Fail(c, fiber.StatusPaymentRequired,
				"insufficient credit; please top up to continue")
		}
		if status, msg, ok := h.checkSandboxConcurrencyQuotaExceptFor(c, rec.CreatedBy, id, limits); !ok {
			if status >= http.StatusInternalServerError {
				return httpx.Error(c, status, msg)
			}
			return httpx.Fail(c, status, msg)
		}
	}
	// Detached context: the resume outlives this request (the ingress got
	// its 202 and moved on). ResumeKickoff picks a host + forwards.
	reqCtx := context.WithoutCancel(c.UserContext())
	id = strings.Clone(id)
	go func() {
		bg, cancel := context.WithTimeout(reqCtx, 90*time.Second)
		defer cancel()
		if err := h.KickoffInternalResume(bg, id); err != nil {
			log.WithContext(bg).Warnf("[wake] %s kickoff: %v", id, err)
		}
	}()
	log.WithContext(c.UserContext()).Infof("[wake] %s resume kicked off (wake-on-request)", id)
	return httpx.SuccessStatus(c, fiber.StatusAccepted, struct{}{})
}

func (h *Handler) DbMarkPausing(c *fiber.Ctx) error {
	var r proto.ControlMarkPausingReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	st, err := h.repo.MarkPausing(c.UserContext(), r.ID, r.At)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.CASStatusResp{Status: st})
}

func (h *Handler) DbMarkPaused(c *fiber.Ctx) error {
	var r proto.ControlMarkPausedReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	st, err := h.repo.MarkPaused(c.UserContext(), r.ID, r.Manifest, r.URI, r.CachedHostID, r.CachedUntil, r.PausedAt, h.billingEmitter)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	// MarkPaused now emits the paused billing event atomically.
	return httpx.Success(c, proto.CASStatusResp{Status: st})
}

func (h *Handler) DbMarkPauseRolledBack(c *fiber.Ctx) error {
	var r proto.ControlMarkPauseRolledBackReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	st, err := h.repo.MarkPauseRolledBack(c.UserContext(), r.ID, r.Err, r.At)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.CASStatusResp{Status: st})
}

func (h *Handler) DbMarkResumed(c *fiber.Ctx) error {
	var r proto.ControlMarkResumedReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	st, err := h.repo.MarkResumed(c.UserContext(), r.ID, r.IP, r.MAC, r.APISock, r.ContainerID, r.OverlayPath, r.FCPid, r.RunningAt, r.Host, h.billingEmitter)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	// MarkResumed now emits the running billing event atomically.
	return httpx.Success(c, proto.CASStatusResp{Status: st})
}

func (h *Handler) DbMarkResumeFailed(c *fiber.Ctx) error {
	var r proto.ControlMarkResumeFailedReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	st, err := h.repo.MarkResumeFailed(c.UserContext(), r.ID, r.Host, r.Err, r.At)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.CASStatusResp{Status: st})
}

func (h *Handler) DbMarkDestroying(c *fiber.Ctx) error {
	var r proto.ControlIDReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	st, err := h.repo.MarkDestroying(c.UserContext(), r.ID)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.CASStatusResp{Status: st})
}

func (h *Handler) DbClearLocalCache(c *fiber.Ctx) error {
	var r proto.ControlClearLocalCacheReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if err := h.repo.ClearLocalCache(c.UserContext(), r.ID, r.Host); err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, clearedResp{Cleared: true})
}

func (h *Handler) DbListPausing(c *fiber.Ctx) error {
	host := c.Query("host", "")
	ids, err := h.repo.ListPausing(c.UserContext(), host)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if ids == nil {
		ids = []string{}
	}
	return httpx.Success(c, ids)
}

func (h *Handler) DbListPaused(c *fiber.Ctx) error {
	cachedHost := c.Query("cached_host", "")
	ids, err := h.repo.ListPaused(c.UserContext(), cachedHost)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if ids == nil {
		ids = []string{}
	}
	return httpx.Success(c, ids)
}

func parseCutoff(c *fiber.Ctx) (time.Time, error) {
	cutoffStr := c.Query("cutoff", "")
	if cutoffStr == "" {
		return time.Now(), nil
	}
	return time.Parse(time.RFC3339Nano, cutoffStr)
}

func (h *Handler) DbListStuckPausing(c *fiber.Ctx) error {
	cutoff, err := parseCutoff(c)
	if err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid timestamp")
	}
	region := c.Query("region", "")
	if region == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "region required")
	}
	recs, err := h.repo.ListStuckPausing(c.UserContext(), cutoff, region)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if recs == nil {
		recs = []models.Sandbox{}
	}
	return httpx.Success(c, recs)
}

func (h *Handler) DbListStuckResuming(c *fiber.Ctx) error {
	cutoff, err := parseCutoff(c)
	if err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid timestamp")
	}
	region := c.Query("region", "")
	if region == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "region required")
	}
	recs, err := h.repo.ListStuckResuming(c.UserContext(), cutoff, region)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if recs == nil {
		recs = []models.Sandbox{}
	}
	callerHost := middlewares.CallerHostIfHostRole(c)
	owned := make([]models.Sandbox, 0, len(recs))
	for _, rec := range recs {
		if rec.HostID != nil && *rec.HostID == callerHost {
			owned = append(owned, rec)
		}
	}
	return httpx.Success(c, owned)
}

func (h *Handler) DbLocalCacheCandidates(c *fiber.Ctx) error {
	host := c.Query("host", "")
	recs, err := h.repo.LocalCacheCandidates(c.UserContext(), host)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if recs == nil {
		recs = []models.LocalCacheCandidate{}
	}
	return httpx.Success(c, recs)
}

// DbLocalCacheState answers only whether the calling host should retain its
// local paused-snapshot directory. The host identity comes from mTLS; returning
// a boolean avoids exposing the paused sandbox row through the DB proxy.
func (h *Handler) DbLocalCacheState(c *fiber.Ctx) error {
	rec, err := h.repo.Get(c.UserContext(), c.Params(middlewares.ParamSandboxID))
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil {
		return httpx.Success(c, proto.ControlLocalCacheStateResp{})
	}
	callerHost := middlewares.CallerHostIfHostRole(c)
	cacheOwner := rec.CachedHostID != nil && *rec.CachedHostID == callerHost
	activeOwner := rec.HostID != nil && *rec.HostID == callerHost
	keep := (rec.Status == models.StatusPaused && cacheOwner) ||
		((rec.Status == models.StatusPausing || rec.Status == models.StatusResuming) &&
			(cacheOwner || activeOwner))
	return httpx.Success(c, proto.ControlLocalCacheStateResp{Keep: keep})
}
