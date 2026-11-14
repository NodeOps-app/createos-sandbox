package handlers

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/oklog/ulid"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/middlewares"
	"github.com/NodeOps-app/createos-sandbox/internal/audit"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx/types"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/internal/utils"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// networkView is the user-facing projection owned by the network handlers.
// Keeping it here makes it impossible for persistence-only fields on
// models.Network to leak onto the public wire by accident.
type networkView struct {
	ID          string                     `json:"id"`
	Name        string                     `json:"name"`
	CreatedAt   time.Time                  `json:"created_at"`
	MemberCount int                        `json:"member_count,omitempty"`
	Members     []models.NetworkMemberView `json:"members,omitempty"`
}

type networkCreateReq struct {
	Name string `json:"name"`
}

type networkHostStateData struct {
	Members []models.NetworkMember `json:"members"`
	Epoch   int64                  `json:"epoch"`
}

// newNetworkID returns a DNS-label-safe network id: "net-" prefix (no
// underscore) + lower-cased ULID.
func newNetworkID() string {
	return "net-" + strings.ToLower(ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String())
}

// ── user-facing CRUD ──────────────────────────────────────────────────────

func (h *Handler) HandleNetworkCreate(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	var req networkCreateReq
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if req.Name == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "required")
	}
	if len(req.Name) > 63 {
		return httpx.Fail(c, fiber.StatusBadRequest,
			fmt.Sprintf("network name too long: %d characters (max 63)", len(req.Name)))
	}
	if !sandboxNameRe.MatchString(req.Name) {
		return httpx.Fail(c, fiber.StatusBadRequest,
			"network name must be lowercase letters, digits and hyphens only "+
				"(no dots or underscores), and start and end with a letter or digit")
	}
	// Per-user concurrent-network cap. Internal keys bypass.
	{
		authType, token, hasAuth := middlewares.ExtractAuthToken(c)
		if !hasAuth {
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
			L := h.limits.Get(c.UserContext(), keyRec.UserID, keyRec.IsInternal)
			if !L.HasCredit() {
				return httpx.Fail(c, fiber.StatusPaymentRequired,
					"insufficient credit; please top up to continue")
			}
			if cap := L.MaxSandboxNetworks; cap >= 0 {
				n, cerr := h.repo.CountNetworksActive(c.UserContext(), userID)
				if cerr != nil {
					log.WithContext(c.UserContext()).Errorf("[quota] network count: %v", cerr)
					return httpx.Error(c, fiber.StatusServiceUnavailable, "internal error")
				}
				if n >= cap {
					return httpx.Fail(c, fiber.StatusTooManyRequests, fmt.Sprintf(
						"network quota reached (%d / %d). Delete an unused network first.", n, cap))
				}
			}
			if cap := L.MaxSandboxNetworksPerDay; cap >= 0 {
				n, cerr := h.repo.CountNetworksSince(c.UserContext(), userID, time.Now().Add(-24*time.Hour))
				if cerr != nil {
					log.WithContext(c.UserContext()).Errorf("[quota] network per-day count: %v", cerr)
					return httpx.Error(c, fiber.StatusServiceUnavailable, "internal error")
				}
				if n >= cap {
					return httpx.Fail(c, fiber.StatusTooManyRequests, fmt.Sprintf(
						"network per-day quota reached (%d / %d). Try again in 24h or contact an operator.", n, cap))
				}
			}
		}
	}
	n := models.Network{
		ID:    newNetworkID(),
		Name:  req.Name,
		Owner: userID,
	}
	if err := h.repo.CreateNetwork(c.UserContext(), n, h.region); err != nil {
		// Per-user (owner, name) unique violation — map to 409 with a
		// clean message instead of bubbling the SQLSTATE up as a 500.
		// Different users with the same name are fine; only same-user
		// duplicates collide.
		if isUniqueViolation(err) {
			return httpx.Fail(c, fiber.StatusConflict,
				fmt.Sprintf("network with name %q already exists", req.Name))
		}
		// VNI namespace for this region is exhausted. Surface a
		// generic 507 — don't leak the per-region slice math
		// (24-bit space, 4.2M/region) to end users.
		if errors.Is(err, models.ErrVNIExhausted) {
			log.WithContext(c.UserContext()).Errorf("[network-create] region %s VNI slice exhausted", h.region)
			return httpx.Error(c, fiber.StatusInsufficientStorage,
				"network capacity unavailable; contact an operator")
		}
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	// Fetch back to get assigned VNI.
	created, err := h.repo.GetNetwork(c.UserContext(), userID, n.ID)
	if err != nil || created == nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "failed to fetch created network")
	}
	h.audit.Emit(c.UserContext(), h.auditCtxWithSubject(c, "network", created.ID),
		audit.ActionNetworkCreate, audit.OperationCreate,
		audit.BuildNetworkCreate(created))
	return httpx.Success(c, networkViewFromModel(created))
}

func (h *Handler) HandleNetworkList(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
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
	nets, err := h.repo.ListNetworksPaged(c.UserContext(), userID, limit, offset)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	total, err := h.repo.CountUserNetworks(c.UserContext(), userID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] count internal error: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	views := make([]networkView, 0, len(nets))
	for i := range nets {
		views = append(views, networkViewFromModel(&nets[i]))
	}
	return httpx.Paginated(c, views, total, limit, offset, len(views))
}

func (h *Handler) HandleNetworkGet(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	n, err := h.repo.GetNetwork(c.UserContext(), userID, c.Params(middlewares.ParamSandboxID))
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if n == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "not found")
	}
	members, err := h.repo.ListNetworkMembers(c.UserContext(), n.ID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	v := networkViewFromModel(n)
	v.Members = members
	v.MemberCount = len(members)
	return httpx.Success(c, v)
}

func (h *Handler) HandleNetworkDelete(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	err := h.repo.DeleteNetwork(c.UserContext(), userID, c.Params(middlewares.ParamSandboxID))
	if err != nil {
		if errors.Is(err, models.ErrHasMembers) {
			return httpx.Fail(c, fiber.StatusConflict, "has active members; detach all sandboxes first")
		}
		if err.Error() == "network not found" {
			return httpx.Fail(c, fiber.StatusNotFound, "not found")
		}
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, okResp{OK: true})
}

// ── sandbox attach/detach ─────────────────────────────────────────────────

func (h *Handler) HandleNetworkAttach(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	sandboxID := c.Params(middlewares.ParamSandboxID)
	// Body matches CreateReq.Networks entries (`id` = network name or
	// net_<ulid>) so attach-at-create and attach-at-runtime speak the
	// same shape.
	var req proto.NetworkEntry
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if req.ID == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "required")
	}
	// Verify sandbox ownership BEFORE network lookup — otherwise a
	// caller could attach another tenant's sandbox to their own
	// network, putting the victim's VM IP into the attacker's overlay
	// VNI and bypassing the BPF intersection gate.
	sb, err := h.repo.Get(c.UserContext(), sandboxID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if sb == nil || !ownerOK(c, sb) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if sb.Region != "" && sb.Region != h.region {
		return h.forwardToPeerControl(c, sb.Region, c.Method(), c.Path())
	}
	// Verify network ownership.
	n, err := h.repo.GetNetwork(c.UserContext(), userID, req.ID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if n == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "not found")
	}
	if err := h.repo.AttachNetwork(c.UserContext(), sandboxID, n.ID); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	// Kick the owning host's reconciler so the new tenant bit appears in
	// BPF maps within milliseconds. Without this the next periodic tick
	// closes it in ≤5s, leaving a brief window where the new attachment
	// works at the DB layer but the BPF gate hasn't seen it yet.
	h.kickReconcilerForSandbox(c.UserContext(), sandboxID)
	h.audit.Emit(c.UserContext(), h.auditCtxWithSubject(c, "network", n.ID),
		audit.ActionNetworkAttach, audit.OperationModify,
		audit.BuildNetworkAttach(n, sandboxID, ""))
	return httpx.Success(c, okResp{OK: true})
}

func (h *Handler) HandleNetworkDetach(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	sandboxID := c.Params(middlewares.ParamSandboxID)
	networkID := c.Params(middlewares.ParamNetwork)
	// Verify sandbox ownership BEFORE network lookup. Detach against a
	// sandbox the caller doesn't own must 404, never reveal whether the
	// (sandbox, network) pairing exists.
	sb, err := h.repo.Get(c.UserContext(), sandboxID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if sb == nil || !ownerOK(c, sb) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if sb.Region != "" && sb.Region != h.region {
		return h.forwardToPeerControl(c, sb.Region, c.Method(), c.Path())
	}
	// Verify network ownership before detach.
	n, err := h.repo.GetNetwork(c.UserContext(), userID, networkID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if n == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "not found")
	}
	if err := h.repo.DetachNetwork(c.UserContext(), sandboxID, n.ID); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	// Kick the owning host's reconciler so revoked tenant access lands in
	// BPF immediately instead of lagging up to one reconciler tick (~5s).
	// Without the kick a just-detached VM could still reach the network's
	// other members for several seconds.
	h.kickReconcilerForSandbox(c.UserContext(), sandboxID)
	h.audit.Emit(c.UserContext(), h.auditCtxWithSubject(c, "network", n.ID),
		audit.ActionNetworkDetach, audit.OperationModify,
		audit.BuildNetworkDetach(n, sandboxID))
	return httpx.Success(c, okResp{OK: true})
}

// kickReconcilerForSandbox invalidates the host-state cache and fires a
// non-blocking POST to the owning host's /v1/internal/net-reconcile-kick
// endpoint so its reconciler runs immediately. Used by live attach/detach
// to close the BPF-vs-DB consistency window that otherwise lasts ≤5s.
// Best-effort: errors are logged; the periodic 5s tick is the safety net.
func (h *Handler) kickReconcilerForSandbox(ctx context.Context, sandboxID string) {
	rec, err := h.repo.Get(ctx, sandboxID)
	if err != nil || rec == nil || rec.HostID == nil || *rec.HostID == "" {
		return
	}
	host, err := h.repo.GetHost(ctx, *rec.HostID)
	if err != nil || host == nil {
		return
	}
	invalidateHostStateCache(host.ID)
	go func() {
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		if err := kickHostNetReconciler(bg, *host, h.http); err != nil {
			log.WithContext(ctx).Warnf("[control] net-reconcile kick host=%s: %v (next tick will catch up)", host.ID, err)
		}
	}()
}

// ── internal: host-state for reconciler ──────────────────────────────────

// hostStateCache is a per-host 1-second response cache so 10k hosts ticking
// simultaneously don't generate 10k QPS on the DB.
var hostStateCache struct {
	mu        sync.RWMutex
	entries   map[string]hostStateCacheEntry
	lastSweep time.Time
}

type hostStateCacheEntry struct {
	members []models.NetworkMember
	epoch   int64
	expiry  time.Time
}

func init() {
	hostStateCache.entries = make(map[string]hostStateCacheEntry)
}

// invalidateHostStateCache drops one host's cached entry so the next
// reconciler fetch goes back to the DB. Called from attachNetworks /
// detachNetwork after a sandbox_networks write so the kick-triggered
// reconcile sees fresh data instead of the 1-second-stale snapshot.
func invalidateHostStateCache(hostID string) {
	if hostID == "" {
		return
	}
	hostStateCache.mu.Lock()
	delete(hostStateCache.entries, hostID)
	hostStateCache.mu.Unlock()
}

// storeHostStateCache removes expired values before inserting. Expiry alone
// only makes an entry unreadable; deletion is what releases its key and member
// slice from control-plane memory.
func storeHostStateCache(hostID string, entry hostStateCacheEntry, now time.Time) {
	hostStateCache.mu.Lock()
	defer hostStateCache.mu.Unlock()

	// At the stated 10k-host scale, scanning on every poll would turn a
	// one-second cache into O(hosts²) work. One caller performs the sweep at
	// most once per cache TTL; all other inserts remain O(1).
	if now.Sub(hostStateCache.lastSweep) >= time.Second {
		for key, cached := range hostStateCache.entries {
			if !now.Before(cached.expiry) {
				delete(hostStateCache.entries, key)
			}
		}
		hostStateCache.lastSweep = now
	}

	hostStateCache.entries[hostID] = entry
}

func (h *Handler) HandleInternalNetworkHostState(c *fiber.Ctx) error {
	hostID := c.Query(middlewares.QueryHostID)
	if hostID == "" {
		return httpx.Fail(c, fiber.StatusBadRequest,
			types.FieldError{middlewares.QueryHostID: "required"})
	}

	now := time.Now()
	hostStateCache.mu.RLock()
	entry, ok := hostStateCache.entries[hostID]
	hostStateCache.mu.RUnlock()
	if ok && now.Before(entry.expiry) {
		return httpx.Success(c, networkHostStateData{Members: entry.members, Epoch: entry.epoch})
	}

	members, err := h.repo.NetworkHostState(c.UserContext(), hostID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if members == nil {
		members = []models.NetworkMember{}
	}

	epoch := now.UnixMilli()
	storeHostStateCache(hostID, hostStateCacheEntry{
		members: members,
		epoch:   epoch,
		expiry:  now.Add(time.Second),
	}, now)

	return httpx.Success(c, networkHostStateData{Members: members, Epoch: epoch})
}

// ── view helpers ──────────────────────────────────────────────────────────

func networkViewFromModel(n *models.Network) networkView {
	return networkView{
		ID:          n.ID,
		Name:        n.Name,
		CreatedAt:   n.CreatedAt,
		MemberCount: n.MemberCount,
	}
}
