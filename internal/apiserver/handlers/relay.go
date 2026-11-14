// Relay-side control-plane handlers: user-facing device VPN CRUD plus
// the internal /v1/internal/relay-state poll that replaces a direct
// Postgres DSN on relay boxes. See docs/device-vpn.md.
//
// Routes (all live in routes/main.go):
//
//	POST   /v1/devices                          mint a device
//	GET    /v1/devices                          list user's devices
//	GET    /v1/devices/:id                      get
//	DELETE /v1/devices/:id                      revoke
//	POST   /v1/devices/:id/networks             attach to a network
//	GET    /v1/devices/:id/networks             list attached networks
//	DELETE /v1/devices/:id/networks/:nid        detach
//	POST   /v1/devices/:id/sessions             open a session (returns wg-quick config)
//	GET    /v1/devices/:id/sessions             list active sessions
//	DELETE /v1/devices/:id/sessions/:sid        close a session
//	GET    /v1/internal/relay-state             relay reconciler poll (mTLS)
//
// Authz convention: every user-facing route gates on `userID != ""`
// plus a per-row `GetDeviceForUser` (cross-tenant ids → 404). The
// internal relay-state endpoint binds the caller's SPIFFE host_id to
// the query host_id and rejects unless the host row is role='relay'.
package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
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

type deviceViewJSON struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	ClientIP   string     `json:"client_ip"`
	Pubkey     string     `json:"pubkey"`
	Hostname   string     `json:"hostname,omitempty"`
	OS         string     `json:"os,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
}

type deviceAttachmentView struct {
	DeviceID   string    `json:"device_id"`
	NetworkID  string    `json:"network_id"`
	AttachedAt time.Time `json:"attached_at"`
}

type deviceNetworkAttachmentView struct {
	NetworkID   string    `json:"network_id"`
	NetworkName string    `json:"network_name"`
	AttachedAt  time.Time `json:"attached_at"`
}

type deviceSessionView struct {
	SessionID    string    `json:"session_id"`
	DeviceID     string    `json:"device_id"`
	RelayHostID  string    `json:"relay_host_id"`
	ClientConfig string    `json:"client_config"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type deviceSessionListView struct {
	SessionID   string    `json:"session_id"`
	DeviceID    string    `json:"device_id"`
	RelayHostID string    `json:"relay_host_id"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type deviceCreateReq struct {
	Name     string `json:"name"`
	Pubkey   string `json:"pubkey"` // base64 (WireGuard's canonical form)
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
}

type deviceAttachNetworkReq struct {
	NetworkID string `json:"network_id"`
}

// defaultSessionTTL is the sliding-window lifetime of a device session.
// The CLI renews at ~TTL/2 via PUT /v1/devices/:id/sessions/:sid; if
// renewal stops (network drop, client crash, intentional disconnect),
// the row expires within this window and the sweeper deletes it.
// 90s keeps dead-client cleanup fast without putting renewal so close
// to the keepalive interval (25s) that a single missed renew kills a
// live tunnel.
const defaultSessionTTL = 90 * time.Second

// devicePubkeyBytes is the size of a raw Curve25519 public key.
const devicePubkeyBytes = 32

func newDeviceID() string {
	return "dev-" + strings.ToLower(ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String())
}

func newSessionID() string {
	return "wgs-" + strings.ToLower(ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String())
}

// ── /v1/internal/relay-state ───────────────────────────────────────────

// HandleInternalRelayState serves the per-tick reconcile state for one
// relay (sessions + BPF policy pairs). Authz already enforced two ways:
//
//  1. The route gate (`MustBePeerRoleMTLS("host")`) verified the caller
//     presented a valid mTLS leaf with a SPIFFE URI of
//     `spiffe://createos/host/<id>`.
//  2. This handler binds the caller's SPIFFE host_id to the query
//     host_id (so relay-A can't read relay-B's state) AND asserts the
//     requested host's `hosts.role` column is 'relay' (so a compute
//     host can't read its own row through this endpoint).
func (h *Handler) HandleInternalRelayState(c *fiber.Ctx) error {
	hostID := c.Query(middlewares.QueryHostID)
	if hostID == "" {
		return httpx.Fail(c, fiber.StatusBadRequest,
			types.FieldError{middlewares.QueryHostID: "required"})
	}
	ctx := c.UserContext()

	iden, _ := c.Locals(middlewares.MTLSIdentityLocalsKey).(string)
	callerHost := ""
	if i := strings.Index(iden, "/host/"); i >= 0 {
		callerHost = iden[i+len("/host/"):]
	}
	if callerHost == "" || callerHost != hostID {
		return httpx.Fail(c, fiber.StatusForbidden,
			types.AuthError{Auth: "caller host_id does not match query host_id"})
	}

	host, err := h.repo.GetHost(ctx, hostID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[relay-state] get host %s: %v", hostID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if host == nil || host.Role != models.HostRoleRelay {
		return httpx.Fail(c, fiber.StatusForbidden,
			types.AuthError{Auth: "host is not a relay"})
	}

	sessions, err := h.repo.ListSessionsForRelay(ctx, hostID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[relay-state] sessions: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	devicePairs, err := h.repo.ListDevicePairsForRelay(ctx, hostID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[relay-state] device pairs: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	vmPairs, err := h.repo.ListDeviceVMPairsForRelay(ctx, hostID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[relay-state] device-vm pairs: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}

	sv := make([]proto.RelaySessionView, 0, len(sessions))
	for _, s := range sessions {
		sv = append(sv, proto.RelaySessionView{
			SessionID:     s.SessionID,
			Pubkey:        base64.StdEncoding.EncodeToString(s.Pubkey),
			ClientIP:      s.ClientIP,
			ExpiresAtUnix: s.ExpiresAt.Unix(),
		})
	}
	dp := make([]proto.RelayPairView, 0, len(devicePairs))
	for _, p := range devicePairs {
		dp = append(dp, proto.RelayPairView{SrcIP: p.SrcIP, DstIP: p.DstIP})
	}
	vp := make([]proto.RelayPairView, 0, len(vmPairs))
	for _, p := range vmPairs {
		vp = append(vp, proto.RelayPairView{SrcIP: p.SrcIP, DstIP: p.DstIP})
	}
	return httpx.Success(c, proto.RelayStateResp{
		Sessions:      sv,
		DevicePairs:   dp,
		DeviceVMPairs: vp,
	})
}

// ── user-facing /v1/devices CRUD ───────────────────────────────────────

// HandleDeviceCreate registers a machine as a device, allocates a
// permanent CGNAT IP, and returns the device row. Pubkey is required —
// we don't mint server-side keypairs (see docs/device-vpn.md: clients
// generate their own key, server only ever sees the pubkey).
func (h *Handler) HandleDeviceCreate(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	if h.deviceRegistrationDisabled {
		return httpx.Fail(c, fiber.StatusServiceUnavailable,
			"device registration is temporarily unavailable")
	}
	if h.region != models.EuropeRegion {
		return h.forwardToPeerControl(c, models.EuropeRegion, c.Method(), c.Path())
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	var req deviceCreateReq
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, types.FieldError{"body": "invalid JSON"})
	}
	if strings.TrimSpace(req.Name) == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, types.FieldError{"name": "required"})
	}
	pubkey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.Pubkey))
	if err != nil || len(pubkey) != devicePubkeyBytes {
		return httpx.Fail(c, fiber.StatusBadRequest,
			types.FieldError{"pubkey": "must be base64-encoded 32-byte WireGuard public key"})
	}

	ctx := c.UserContext()

	// Per-user device cap. Internal keys bypass (Get returns -1 for all
	// caps when isInternal=true). Without this, one user could spam-
	// register devices and exhaust the CGNAT /16 pool fleet-wide.
	{
		authType, token, hasAuth := middlewares.ExtractAuthToken(c)
		if hasAuth {
			keyRec, _ := h.repo.LookupAPIKeyByHash(ctx, authType, h.apiKeyHasher.Hash(token))
			if keyRec != nil && !keyRec.IsInternal {
				L := h.limits.Get(ctx, keyRec.UserID, keyRec.IsInternal)
				if cap := L.MaxDevices; cap >= 0 {
					n, cerr := h.repo.CountDevicesForUser(ctx, userID)
					if cerr != nil {
						log.WithContext(c.UserContext()).Errorf("[quota] device count: %v", cerr)
						return httpx.Error(c, fiber.StatusServiceUnavailable, "internal error")
					}
					if n >= cap {
						return httpx.Fail(c, fiber.StatusTooManyRequests, fmt.Sprintf(
							"device quota reached (%d / %d). Unregister an unused device first.", n, cap))
					}
				}
			}
		}
	}

	rec := models.Device{
		ID:     newDeviceID(),
		UserID: userID,
		Name:   strings.TrimSpace(req.Name),
		Pubkey: pubkey,
	}
	if s := strings.TrimSpace(req.Hostname); s != "" {
		rec.Hostname = &s
	}
	if s := strings.TrimSpace(req.OS); s != "" {
		rec.OS = &s
	}

	created, err := h.repo.CreateDevice(ctx, rec, h.region)
	if err != nil {
		if errors.Is(err, models.ErrDeviceIPExhausted) {
			return httpx.Fail(c, fiber.StatusServiceUnavailable,
				types.FieldError{"capacity": "device IP pool exhausted in region"})
		}
		if errors.Is(err, models.ErrDeviceIPAllocation) {
			log.WithContext(ctx).Errorf("[devices] assign IP: %v", err)
			return httpx.Error(c, fiber.StatusServiceUnavailable, "internal error")
		}
		// 23505 = unique_violation. Could be name (per-user) or pubkey.
		// Differentiate via message so the user knows which to change.
		msg := err.Error()
		if strings.Contains(msg, "devices_user_name_idx") {
			return httpx.Fail(c, fiber.StatusConflict,
				types.FieldError{"name": "a device with this name already exists"})
		}
		if strings.Contains(msg, "devices_pubkey_idx") {
			return httpx.Fail(c, fiber.StatusConflict,
				types.FieldError{"pubkey": "this public key is already registered"})
		}
		log.WithContext(c.UserContext()).Errorf("[devices] create: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	h.audit.Emit(ctx, h.auditCtxWithSubject(c, "device", created.ID),
		audit.ActionDeviceRegister, audit.OperationCreate,
		audit.BuildDeviceRegister(created))
	return httpx.Success(c, deviceView(*created))
}

func (h *Handler) HandleDeviceList(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	if h.region != models.EuropeRegion {
		return h.forwardToPeerControl(c, models.EuropeRegion, c.Method(), c.Path())
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	limit := c.QueryInt(middlewares.QueryLimit, 50)
	offset := c.QueryInt(middlewares.QueryOffset, 0)
	if limit < 1 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	ctx := c.UserContext()
	recs, err := h.repo.ListDevicesForUser(ctx, userID, limit, offset)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[devices] list: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	total, err := h.repo.CountDevicesForUser(ctx, userID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[devices] count: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	views := make([]deviceViewJSON, 0, len(recs))
	for _, r := range recs {
		views = append(views, deviceView(r))
	}
	return httpx.Paginated(c, views, total, limit, offset, len(views))
}

func (h *Handler) HandleDeviceGet(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	if h.region != models.EuropeRegion {
		return h.forwardToPeerControl(c, models.EuropeRegion, c.Method(), c.Path())
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	id := c.Params(middlewares.ParamSandboxID)
	dev, err := h.repo.GetDeviceForUser(c.UserContext(), id, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return httpx.Fail(c, fiber.StatusNotFound, types.FieldError{"device": "not found"})
		}
		log.WithContext(c.UserContext()).Errorf("[devices] get: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, deviceView(*dev))
}

// HandleDeviceDelete revokes the device, dropping all attachments and
// active sessions atomically. Kicks reconcilers on affected hosts so
// existing tunnels' /32 routes are removed quickly.
func (h *Handler) HandleDeviceDelete(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	if h.region != models.EuropeRegion {
		return h.forwardToPeerControl(c, models.EuropeRegion, c.Method(), c.Path())
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	id := c.Params(middlewares.ParamSandboxID)
	ctx := c.UserContext()

	dev, err := h.repo.GetDeviceForUser(ctx, id, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return httpx.Fail(c, fiber.StatusNotFound, types.FieldError{"device": "not found"})
		}
		log.WithContext(c.UserContext()).Errorf("[devices] get for delete: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}

	// Snapshot the device's attached networks BEFORE revoke deletes the
	// device_networks rows — we need them to know which hosts to kick.
	atts, _ := h.repo.ListNetworksForDevice(ctx, dev.ID)

	if err := h.repo.RevokeDevice(ctx, dev.ID, userID); err != nil {
		log.WithContext(c.UserContext()).Errorf("[devices] revoke: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	h.audit.Emit(ctx, h.auditCtxWithSubject(c, "device", dev.ID),
		audit.ActionDeviceUnregister, audit.OperationRemove,
		audit.BuildDeviceUnregister(dev))
	h.kickReconcilersForNetworks(ctx, atts)
	return httpx.Success(c, okResp{OK: true})
}

// ── attachments ───────────────────────────────────────────────────────

func (h *Handler) HandleDeviceAttachNetwork(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	if h.region != models.EuropeRegion {
		return h.forwardToPeerControl(c, models.EuropeRegion, c.Method(), c.Path())
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	deviceID := c.Params(middlewares.ParamSandboxID)
	var req deviceAttachNetworkReq
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.NetworkID) == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, types.FieldError{"network_id": "required"})
	}
	ctx := c.UserContext()

	dev, err := h.repo.GetDeviceForUser(ctx, deviceID, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return httpx.Fail(c, fiber.StatusNotFound, types.FieldError{"device": "not found"})
		}
		log.WithContext(c.UserContext()).Errorf("[devices] attach: get device: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	net, err := h.repo.GetNetwork(ctx, userID, req.NetworkID)
	if err != nil || net == nil {
		return httpx.Fail(c, fiber.StatusNotFound, types.FieldError{"network": "not found"})
	}
	// Layer-1 isolation: reject cross-tenant attach before any WG state.
	if net.Owner != userID {
		return httpx.Fail(c, fiber.StatusForbidden,
			types.FieldError{"network": "not yours"})
	}

	if err := h.repo.AttachDeviceToNetwork(ctx, dev.ID, net.ID); err != nil {
		log.WithContext(c.UserContext()).Errorf("[devices] attach: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	h.audit.Emit(ctx, h.auditCtxWithSubject(c, "device", dev.ID),
		audit.ActionDeviceNetworkAttach, audit.OperationModify,
		audit.BuildDeviceNetworkAttach(dev, net.ID))
	h.kickReconcilersForNetworkIDs(ctx, []string{net.ID})

	return httpx.Success(c, deviceAttachmentView{
		DeviceID:   dev.ID,
		NetworkID:  net.ID,
		AttachedAt: time.Now().UTC(),
	})
}

func (h *Handler) HandleDeviceListNetworks(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	if h.region != models.EuropeRegion {
		return h.forwardToPeerControl(c, models.EuropeRegion, c.Method(), c.Path())
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	deviceID := c.Params(middlewares.ParamSandboxID)
	ctx := c.UserContext()

	if _, err := h.repo.GetDeviceForUser(ctx, deviceID, userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return httpx.Fail(c, fiber.StatusNotFound, types.FieldError{"device": "not found"})
		}
		log.WithContext(c.UserContext()).Errorf("[devices] list networks: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	rows, err := h.repo.ListNetworksForDevice(ctx, deviceID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[devices] list networks: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	views := make([]deviceNetworkAttachmentView, 0, len(rows))
	for _, r := range rows {
		views = append(views, deviceNetworkAttachmentView{
			NetworkID:   r.Network.ID,
			NetworkName: r.Network.Name,
			AttachedAt:  r.AttachedAt,
		})
	}
	return httpx.Success(c, views)
}

func (h *Handler) HandleDeviceDetachNetwork(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	if h.region != models.EuropeRegion {
		return h.forwardToPeerControl(c, models.EuropeRegion, c.Method(), c.Path())
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	deviceID := c.Params(middlewares.ParamSandboxID)
	networkID := c.Params(middlewares.ParamNetworkID)
	ctx := c.UserContext()

	dev, err := h.repo.GetDeviceForUser(ctx, deviceID, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return httpx.Fail(c, fiber.StatusNotFound, types.FieldError{"device": "not found"})
		}
		log.WithContext(c.UserContext()).Errorf("[devices] detach: get device: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	net, err := h.repo.GetNetwork(ctx, userID, networkID)
	if err != nil || net == nil {
		return httpx.Fail(c, fiber.StatusNotFound, types.FieldError{"network": "not found"})
	}
	if err := h.repo.DetachDeviceFromNetwork(ctx, dev.ID, net.ID); err != nil {
		log.WithContext(c.UserContext()).Errorf("[devices] detach: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	h.audit.Emit(ctx, h.auditCtxWithSubject(c, "device", dev.ID),
		audit.ActionDeviceNetworkDetach, audit.OperationModify,
		audit.BuildDeviceNetworkDetach(dev, net.ID))
	h.kickReconcilersForNetworkIDs(ctx, []string{net.ID})
	return httpx.Success(c, okResp{OK: true})
}

// ── sessions ──────────────────────────────────────────────────────────

func (h *Handler) HandleDeviceSessionCreate(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	if h.region != models.EuropeRegion {
		return h.forwardToPeerControl(c, models.EuropeRegion, c.Method(), c.Path())
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	deviceID := c.Params(middlewares.ParamSandboxID)
	ctx := c.UserContext()

	dev, err := h.repo.GetDeviceForUser(ctx, deviceID, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return httpx.Fail(c, fiber.StatusNotFound, types.FieldError{"device": "not found"})
		}
		log.WithContext(c.UserContext()).Errorf("[devices] session create: get device: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	atts, err := h.repo.ListNetworksForDevice(ctx, dev.ID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[devices] list networks: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if len(atts) == 0 {
		return httpx.Fail(c, fiber.StatusBadRequest,
			types.FieldError{"networks": "attach this device to at least one network first"})
	}

	endpoint := strings.TrimSpace(c.IP() + ":0")

	// Sticky-relay: if the device already has an unexpired session, renew
	// THAT session and reuse its relay. POST /sessions becomes idempotent
	// — a reconnect doesn't fragment the device across relays and doesn't
	// leave two competing rows pointing at different next-hops until the
	// older one TTLs out.
	var sess *models.DeviceSession
	var relayHost *models.Host
	if existing, lerr := h.repo.GetActiveSessionForDevice(ctx, dev.ID); lerr == nil && existing != nil {
		if rh, gerr := h.repo.GetHost(ctx, existing.RelayHostID); gerr == nil && rh != nil {
			renewed, rerr := h.repo.RenewDeviceSession(ctx, existing.ID, dev.ID, int(defaultSessionTTL.Seconds()))
			if rerr == nil && renewed != nil {
				sess = renewed
				relayHost = rh
			}
		}
	} else if lerr != nil && !errors.Is(lerr, pgx.ErrNoRows) {
		log.WithContext(c.UserContext()).Errorf("[devices] active session lookup: %v", lerr)
		// non-fatal — fall through to fresh pick
	}

	if sess == nil {
		// No existing session (or its relay was decommissioned) — pick
		// least-loaded relay + insert fresh.
		relayID, perr := h.repo.PickLeastLoadedRelay(ctx, h.region)
		if perr != nil && !errors.Is(perr, pgx.ErrNoRows) {
			log.WithContext(c.UserContext()).Errorf("[devices] pick relay: %v", perr)
			return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
		}
		if relayID == "" && h.relayCrossRegionFallback {
			// In-region has no active relay; operator has opted into
			// cross-region fallback (typical during initial bring-up of
			// a fresh region). Log loudly so this doesn't quietly become
			// steady state — every fallback hop is a trans-region packet.
			fbID, ferr := h.repo.PickLeastLoadedRelayAnyRegion(ctx, h.region)
			if ferr != nil && !errors.Is(ferr, pgx.ErrNoRows) {
				log.WithContext(c.UserContext()).Errorf("[devices] pick relay (fallback): %v", ferr)
				return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
			}
			if fbID != "" {
				log.WithContext(c.UserContext()).Warnf("[devices] cross-region relay fallback used: caller_region=%s picked=%s", h.region, fbID)
				relayID = fbID
			}
		}
		if relayID == "" {
			return httpx.Fail(c, fiber.StatusServiceUnavailable,
				types.FieldError{"relay": "no relay available; try again shortly"})
		}
		relayHost, err = h.repo.GetHost(ctx, relayID)
		if err != nil || relayHost == nil {
			return httpx.Error(c, fiber.StatusInternalServerError, "relay metadata missing")
		}
		sess, err = h.repo.CreateDeviceSession(ctx, models.DeviceSession{
			ID:           newSessionID(),
			DeviceID:     dev.ID,
			RelayHostID:  relayHost.ID,
			EndpointAddr: &endpoint,
			ExpiresAt:    time.Now().UTC().Add(defaultSessionTTL),
		})
		if err != nil {
			log.WithContext(c.UserContext()).Errorf("[devices] create session: %v", err)
			return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
		}
	}
	h.audit.Emit(ctx, h.auditCtxWithSubject(c, "device", dev.ID),
		audit.ActionDeviceSessionCreate, audit.OperationCreate,
		audit.BuildDeviceSessionCreate(sess, dev))
	h.kickReconcilersForNetworks(ctx, atts)

	// Build wg-quick config. Server-side pubkey is the relay's wg-devices
	// pubkey (set in hosts.relay_devices_pubkey at register time —
	// distinct from wg_public_key which is the wg-hosts mesh key). Fall
	// back to wg_public_key only for legacy pre-migration rows.
	relayPubkey := ""
	if len(relayHost.RelayDevicesPubkey) > 0 {
		relayPubkey = base64.StdEncoding.EncodeToString(relayHost.RelayDevicesPubkey)
	} else if len(relayHost.WGPublicKey) > 0 {
		relayPubkey = base64.StdEncoding.EncodeToString(relayHost.WGPublicKey)
	}
	// AllowedIPs covers two destination classes:
	//   1. VM subnets (host.subnet_cidr per host running VMs in any
	//      network this device is attached to) — for device→VM traffic.
	//   2. The full CGNAT device pool (100.64.0.0/10) — so the client
	//      kernel routes device→device traffic through the tunnel.
	//      The relay still enforces cross-tenant blocking server-side
	//      (BPF/policy on the relay's wg-devices ingress); the client
	//      AllowedIPs only decides what gets sent INTO the tunnel.
	//
	// Empty VM subnets is legitimate (device attached to a network with
	// no live VMs yet); wg-quick still degrades to the /32 + device pool.
	allowed, err := h.repo.ListSubnetsForDeviceNetworks(ctx, dev.ID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[devices] list subnets: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	allowed = append(allowed, "100.64.0.0/10")
	cfg, err := buildWgQuickConfig(dev.ClientIP, relayPubkey, relayHost.Addr, allowed)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[devices] unsafe relay endpoint for %s: %v", relayHost.ID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}

	return httpx.Success(c, deviceSessionView{
		SessionID:    sess.ID,
		DeviceID:     dev.ID,
		RelayHostID:  relayHost.ID,
		ClientConfig: cfg,
		ExpiresAt:    sess.ExpiresAt,
	})
}

func (h *Handler) HandleDeviceSessionDelete(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	if h.region != models.EuropeRegion {
		return h.forwardToPeerControl(c, models.EuropeRegion, c.Method(), c.Path())
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	deviceID := c.Params(middlewares.ParamSandboxID)
	sessionID := c.Params(middlewares.ParamSessionID)
	ctx := c.UserContext()

	dev, err := h.repo.GetDeviceForUser(ctx, deviceID, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return httpx.Fail(c, fiber.StatusNotFound, types.FieldError{"device": "not found"})
		}
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	// DeleteDeviceSession is scoped on (sessionID, dev.ID) — a bad
	// sessionID is a silent no-op, which is fine. Run the delete first so
	// the audit row only logs an event that actually committed.
	if err := h.repo.DeleteDeviceSession(ctx, sessionID, dev.ID); err != nil {
		log.WithContext(c.UserContext()).Errorf("[devices] delete session: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	h.audit.Emit(ctx, h.auditCtxWithSubject(c, "device", dev.ID),
		audit.ActionDeviceSessionDelete, audit.OperationRemove,
		audit.BuildDeviceSessionDelete(sessionID, dev))
	atts, _ := h.repo.ListNetworksForDevice(ctx, dev.ID)
	h.kickReconcilersForNetworks(ctx, atts)
	return httpx.Success(c, okResp{OK: true})
}

// HandleDeviceSessionRenew slides expires_at forward on an existing
// session by exactly one TTL. The CLI's renewal goroutine calls this
// every ~TTL/2 to keep a live tunnel alive. Returns 404 if the session
// has expired / been deleted — that's the signal to the CLI that its
// local WG iface is now orphan and must be torn down.
//
// Authz: same shape as Delete — caller must own the device; the SQL
// renewal is scoped on (id, device_id) so a session can't be renewed
// against the wrong device even if the API ID is guessed.
func (h *Handler) HandleDeviceSessionRenew(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	if h.region != models.EuropeRegion {
		return h.forwardToPeerControl(c, models.EuropeRegion, c.Method(), c.Path())
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	deviceID := c.Params(middlewares.ParamSandboxID)
	sessionID := c.Params(middlewares.ParamSessionID)
	ctx := c.UserContext()

	dev, err := h.repo.GetDeviceForUser(ctx, deviceID, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return httpx.Fail(c, fiber.StatusNotFound, types.FieldError{"device": "not found"})
		}
		log.WithContext(c.UserContext()).Errorf("[devices] session renew: get device: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	sess, err := h.repo.RenewDeviceSession(ctx, sessionID, dev.ID, int(defaultSessionTTL.Seconds()))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Session gone — tell the CLI plainly so it stops pretending
			// the tunnel still works.
			return httpx.Fail(c, fiber.StatusNotFound, types.FieldError{"session": "not found or expired"})
		}
		log.WithContext(c.UserContext()).Errorf("[devices] renew session: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, deviceSessionListView{
		SessionID:   sess.ID,
		DeviceID:    sess.DeviceID,
		RelayHostID: sess.RelayHostID,
		CreatedAt:   sess.CreatedAt,
		ExpiresAt:   sess.ExpiresAt,
	})
}

// HandleDeviceSessionList returns the device's currently-active wg
// sessions (each row in device_sessions whose expires_at is in the
// future). Authz: GetDeviceForUser scopes the cross-tenant check; only
// THIS user's device can be queried. Client-config is intentionally NOT
// re-serialized — that's a create-time artifact.
func (h *Handler) HandleDeviceSessionList(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	if h.region != models.EuropeRegion {
		return h.forwardToPeerControl(c, models.EuropeRegion, c.Method(), c.Path())
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	deviceID := c.Params(middlewares.ParamSandboxID)
	ctx := c.UserContext()

	dev, err := h.repo.GetDeviceForUser(ctx, deviceID, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return httpx.Fail(c, fiber.StatusNotFound, types.FieldError{"device": "not found"})
		}
		log.WithContext(c.UserContext()).Errorf("[devices] session list: get device: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	rows, err := h.repo.ListSessionsForDevice(ctx, dev.ID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[devices] session list: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	views := make([]deviceSessionListView, 0, len(rows))
	for _, s := range rows {
		views = append(views, deviceSessionListView{
			SessionID:   s.ID,
			DeviceID:    s.DeviceID,
			RelayHostID: s.RelayHostID,
			CreatedAt:   s.CreatedAt,
			ExpiresAt:   s.ExpiresAt,
		})
	}
	return httpx.Success(c, views)
}

// ── helpers ───────────────────────────────────────────────────────────

func deviceView(d models.Device) deviceViewJSON {
	v := deviceViewJSON{
		ID:        d.ID,
		Name:      d.Name,
		ClientIP:  d.ClientIP,
		Pubkey:    base64.StdEncoding.EncodeToString(d.Pubkey),
		CreatedAt: d.CreatedAt,
	}
	if d.Hostname != nil {
		v.Hostname = *d.Hostname
	}
	if d.OS != nil {
		v.OS = *d.OS
	}
	if d.LastSeenAt != nil {
		v.LastSeenAt = d.LastSeenAt
	}
	return v
}

// buildWgQuickConfig renders the .conf the client feeds to wg-quick.
// PrivateKey is intentionally absent — the client generated it locally
// and never shipped it to us. The CLI writes its local privkey into the
// config before invoking wg-quick.
func buildWgQuickConfig(clientIP, relayPubkey, endpoint string, allowedIPs []string) (string, error) {
	// Defend at the output boundary too: this blocks legacy/corrupted rows and
	// prevents a future registration path from turning config data into
	// executable wg-quick directives.
	if err := validateRelayEndpoint(endpoint); err != nil {
		return "", fmt.Errorf("invalid relay endpoint: %w", err)
	}
	// Empty allowedIPs = no VMs in any of the device's networks yet.
	// Default to the device's own /32 so wg-quick still installs the
	// tunnel iface (caller can ping their own client_ip to verify the
	// link is up). We deliberately AVOID `0.0.0.0/0` — that would
	// silently capture all the user's internet traffic, a surprising
	// blast radius if AllowedIPs ever resolves wrong.
	allowed := clientIP + "/32"
	if len(allowedIPs) > 0 {
		allowed = strings.Join(allowedIPs, ", ")
	}
	return fmt.Sprintf(`[Interface]
Address = %s/32

[Peer]
PublicKey = %s
AllowedIPs = %s
Endpoint = %s
PersistentKeepalive = 25
`, clientIP, relayPubkey, allowed, endpoint), nil
}

// kickReconcilersForNetworks fans out one /v1/internal/net-reconcile-kick
// per host that owns a VM in any of `attachments`'s networks. Best-effort.
func (h *Handler) kickReconcilersForNetworks(ctx context.Context, attachments []models.DeviceNetworkView) {
	ids := make([]string, 0, len(attachments))
	for _, a := range attachments {
		ids = append(ids, a.Network.ID)
	}
	h.kickReconcilersForNetworkIDs(ctx, ids)
}

func (h *Handler) kickReconcilersForNetworkIDs(ctx context.Context, networkIDs []string) {
	if len(networkIDs) == 0 {
		return
	}
	// Look up sandboxes (and thus hosts) that share any of these networks.
	// Use a single distinct-hosts query if many networks; for v1, loop —
	// network count per attach is small (1-2 typical).
	hostSet := make(map[string]struct{})
	for _, nid := range networkIDs {
		sbs, err := h.repo.List(ctx, "", "", "", 500)
		if err != nil {
			continue
		}
		for _, sb := range sbs {
			if sb.HostID == nil || *sb.HostID == "" {
				continue
			}
			// Cheap-but-correct: rely on existing kick-by-sandbox path,
			// which dedupes by sandbox; the host's reconciler is mutex-
			// guarded so duplicate kicks coalesce harmlessly.
			_ = nid
			hostSet[*sb.HostID] = struct{}{}
		}
	}
	for hostID := range hostSet {
		invalidateHostStateCache(hostID)
		go func(id string) {
			bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer cancel()
			host, err := h.repo.GetHost(bg, id)
			if err != nil || host == nil {
				return
			}
			if err := kickHostNetReconciler(bg, *host, h.http); err != nil {
				log.WithContext(ctx).Debugf("[devices] kick %s: %v", id, err)
			}
		}(hostID)
	}
}
