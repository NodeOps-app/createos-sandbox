package handlers

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/oklog/ulid"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/middlewares"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/models"
)

type bootstrapResp struct {
	Bootstrap bool `json:"bootstrap"`
}

func (h *Handler) HandleHostRegister(c *fiber.Ctx) error {
	var req proto.ControlHostRegisterReq
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if strings.TrimSpace(req.ID) == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "required")
	}
	if strings.TrimSpace(req.Addr) == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "required")
	}
	// Bind requested role to the bootstrap token that authenticated this
	// request: relay token can only mint relay hosts; compute token can
	// only mint compute hosts (or legacy unset-role registrations).
	kind := middlewares.BootstrapKindFromCtx(c)
	switch {
	case kind == middlewares.BootstrapKindRelay && req.Role != models.HostRoleRelay:
		return httpx.Fail(c, fiber.StatusForbidden,
			"relay bootstrap token cannot register role=\""+req.Role+"\"")
	case kind == middlewares.BootstrapKindCompute && req.Role == models.HostRoleRelay:
		return httpx.Fail(c, fiber.StatusForbidden,
			"compute bootstrap token cannot register role=relay")
	}
	if req.Role == models.HostRoleRelay {
		if err := validateRelayEndpoint(req.Addr); err != nil {
			return httpx.Fail(c, fiber.StatusBadRequest, "invalid relay address")
		}
	}

	// Relays don't run VMs, so mem capacity is N/A for them. Only
	// require for compute hosts (default role when unset).
	if req.Role != models.HostRoleRelay && req.MemCapacityMib <= 0 {
		return httpx.Fail(c, fiber.StatusBadRequest, "must be > 0")
	}
	if strings.TrimSpace(req.Region) == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "required")
	}
	region, err := h.repo.GetRegion(c.UserContext(), req.Region)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "region lookup")
	}
	if region == nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "does not exist")
	}
	if !region.IsActive() {
		return httpx.Fail(c, fiber.StatusBadRequest, "region is disabled")
	}
	// Validate the optional pubkey at the door. Reject malformed bytes
	// here so hosts.public_key never holds anything other than a real
	// Ed25519 key (or NULL for legacy callers).
	if len(req.PublicKey) != 0 && len(req.PublicKey) != ed25519.PublicKeySize {
		return httpx.Fail(c, fiber.StatusBadRequest,
			fmt.Sprintf("must be %d bytes", ed25519.PublicKeySize))
	}
	// WG mesh pubkey: 32-byte Curve25519. Optional (empty for hosts that
	// haven't started a WG-aware serve yet); rejected if present-but-wrong-size.
	if len(req.WGPublicKey) != 0 && len(req.WGPublicKey) != 32 {
		return httpx.Fail(c, fiber.StatusBadRequest, "wg_public_key must be 32 bytes")
	}
	// First enrollment is bootstrap-token authenticated because the host
	// does not have a durable identity yet. Re-registration is different:
	// the bootstrap token is fleet-shared, so it must not be sufficient to
	// overwrite an existing host's address or capacity metadata. Require a
	// verified host leaf whose SPIFFE host id matches req.ID before allowing
	// any update to an existing row.
	//
	// Keep the key comparisons as defense in depth: even the authenticated
	// host may not replace its Ed25519 or WireGuard identity through this
	// endpoint. Key rotation remains an explicit operator action.
	if existing, err := h.repo.GetHost(c.UserContext(), req.ID); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] GetHost(%s): %v", req.ID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	} else if existing != nil {
		if msg := peerCertMismatchReason(c, req.ID); msg != "" {
			return httpx.Fail(c, fiber.StatusForbidden, msg)
		}
		if len(existing.PublicKey) > 0 && len(req.PublicKey) > 0 &&
			!bytes.Equal(existing.PublicKey, req.PublicKey) {
			log.WithContext(c.UserContext()).Warnf("[registry] reject pubkey change for host %q (existing=%x new=%x)",
				req.ID, existing.PublicKey[:8], req.PublicKey[:8])
			return httpx.Fail(c, fiber.StatusConflict,
				"host id already claimed; rotate via admin API")
		}
		if len(existing.WGPublicKey) > 0 && len(req.WGPublicKey) > 0 &&
			!bytes.Equal(existing.WGPublicKey, req.WGPublicKey) {
			log.WithContext(c.UserContext()).Warnf("[registry] reject wg pubkey change for host %q", req.ID)
			return httpx.Fail(c, fiber.StatusConflict,
				"host id already claimed; rotate via admin API")
		}
	}
	now := time.Now().UTC()
	rec := models.Host{
		ID:                 req.ID,
		Addr:               req.Addr,
		MemCapacityMib:     req.MemCapacityMib,
		Status:             models.HostStatusActive,
		Role:               req.Role,
		RelayDevicesPubkey: req.RelayDevicesPubkey,
		RegisteredAt:       now,
		LastSeen:           now,
		CPUCount:           req.CPUCount,
		DiskTotalMib:       req.DiskTotalMib,
		DiskUsedMib:        req.DiskUsedMib,
		MaxVMs:             req.MaxVMs,
		Rootfses:           req.Rootfses,
		Labels:             req.Labels,
		PublicKey:          req.PublicKey,
		Region:             req.Region,
		CPUVendor:          req.CPUVendor,
		CPUFamily:          req.CPUFamily,
		WGPublicKey:        req.WGPublicKey,
		CPUOvercommitX10:   req.CPUOvercommitX10,
		MemOvercommitX10:   req.MemOvercommitX10,
		DiskOvercommitX10:  req.DiskOvercommitX10,
	}
	if err := h.repo.UpsertHost(c.UserContext(), rec); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}

	// Invalidate the pubkey cache so the new pubkey is picked up
	// immediately rather than waiting on the 30s TTL.
	if h.hostPubkeys != nil {
		h.hostPubkeys.Invalidate(req.ID)
	}
	// Invalidate the rootfs union cache — a newly-registered host may
	// advertise a rootfs name that wasn't in the union yet, and we
	// want /v1/rootfs + create-time validation to reflect it on the
	// next call instead of waiting up to 30s for TTL.
	if h.rootfsCache != nil {
		h.rootfsCache.Invalidate()
	}

	// Assign a /22 overlay subnet to this host (idempotent — returns existing
	// value on re-register). Skip if no underlay IP was provided (legacy host).
	var subnetCIDR string
	if req.UnderlayIP != "" {
		cidr, err := h.repo.AssignHostSubnet(c.UserContext(), req.ID, req.UnderlayIP, h.region)
		if err != nil {
			log.WithContext(c.UserContext()).Warnf("[registry] AssignHostSubnet(%s): %v", req.ID, err)
		} else {
			subnetCIDR = cidr
		}
	}

	// Allocate a WG mesh /32 to this host (idempotent). Required for any
	// host participating in the encrypted underlay. Empty return = allocator
	// exhausted (>254 hosts in region) — surface as 503 so the operator can
	// widen the subnet before adding more hosts.
	var wgIP string
	if len(req.WGPublicKey) == 32 {
		ip, err := h.repo.AssignHostWGIP(c.UserContext(), req.ID, h.region)
		if err != nil {
			log.WithContext(c.UserContext()).Warnf("[registry] AssignHostWGIP(%s): %v", req.ID, err)
		} else if ip == "" {
			return httpx.Error(c, fiber.StatusServiceUnavailable,
				"WG mesh allocator exhausted; >16,384 hosts in this region")
		} else {
			wgIP = ip
		}
	}

	resp := proto.HostRegisterResp{
		ID:         req.ID,
		SubnetCIDR: subnetCIDR,
		UnderlayIP: req.UnderlayIP,
		WGIP:       wgIP,
		Shapes:     h.shapes.Shapes(c.UserContext()),
	}
	if h.hostStorage.Bucket != "" {
		resp.Storage = &proto.HostStorageInfo{
			Bucket:          h.hostStorage.Bucket,
			Endpoint:        h.hostStorage.Endpoint,
			Region:          h.hostStorage.Region,
			AccessKeyID:     h.hostStorage.AccessKeyID,
			SecretAccessKey: h.hostStorage.SecretAccessKey,
			Secure:          h.hostStorage.Secure,
		}
	}
	return httpx.Success(c, resp)
}

func (h *Handler) DbUpsertHost(c *fiber.Ctx) error {
	var rec models.Host
	if err := c.BodyParser(&rec); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if err := h.repo.UpsertHost(c.UserContext(), rec); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.NewIDResp(rec.ID))
}

func (h *Handler) DbHeartbeatHost(c *fiber.Ctx) error {
	var r proto.ControlHeartbeatHostReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	hostID := c.Params(middlewares.ParamSandboxID)
	if err := h.repo.HeartbeatHost(c.UserContext(), hostID, r.InUseMib, r.VMCount, r.Status, r.DiskUsedMib, r.At); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.NewIDResp(hostID))
}

func (h *Handler) DbListHosts(c *fiber.Ctx) error {
	hosts, err := h.repo.ListHosts(c.UserContext())
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if hosts == nil {
		hosts = []models.Host{}
	}
	return httpx.Success(c, hosts)
}

func (h *Handler) DbGetHost(c *fiber.Ctx) error {
	host, err := h.repo.GetHost(c.UserContext(), c.Params(middlewares.ParamSandboxID))
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if host == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "host not found")
	}
	return httpx.Success(c, host)
}

func (h *Handler) DbBootstrap(c *fiber.Ctx) error {
	if err := h.repo.Bootstrap(c.UserContext()); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, bootstrapResp{Bootstrap: true})
}

// validateRelayEndpoint accepts exactly one WireGuard endpoint. Relay-provided
// values are later embedded in a wg-quick config, where a newline could inject
// shell-backed directives such as PostUp, so this must remain deliberately
// stricter than a generic non-empty address check.
func validateRelayEndpoint(endpoint string) error {
	if endpoint == "" || strings.TrimSpace(endpoint) != endpoint ||
		strings.IndexFunc(endpoint, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return fmt.Errorf("invalid characters")
	}

	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" {
		return fmt.Errorf("must be host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port")
	}
	if net.ParseIP(host) == nil && !validRelayHostname(host) {
		return fmt.Errorf("invalid host")
	}
	return nil
}

func validRelayHostname(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') &&
				(r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func (h *Handler) HandleHostHeartbeat(c *fiber.Ctx) error {
	var req proto.ControlHostHeartbeatReq
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if strings.TrimSpace(req.ID) == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "required")
	}
	status := req.Status
	if status == "" {
		status = models.HostStatusActive
	}
	if status != models.HostStatusActive && status != models.HostStatusDraining {
		return httpx.Fail(c, fiber.StatusBadRequest, "must be active|draining")
	}
	if err := h.repo.HeartbeatHost(c.UserContext(), req.ID, req.InUseMib, req.VMCount, status, req.DiskUsedMib, time.Now().UTC(), snapshotCacheHints(req.CachedSnapshots, time.Now().UTC())); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	// Invalidate the forward-path host cache so status/last_seen updates
	// are visible on the next getHostCached call without waiting for TTL.
	if h.hostCache != nil {
		h.hostCache.Invalidate(req.ID)
	}
	// Heartbeat is liveness-only as far as the scheduler is concerned.
	// Capacity counters are derived by the scheduler from SUM(sandboxes)
	// every second — no fan-out RPC, no ack, no coordination.
	//
	// We piggy-back the resolved shape catalog on every heartbeat so
	// operator edits to control's `shapes:` YAML propagate to live
	// hosts within one heartbeat tick (~5s) without a host restart.
	return httpx.Success(c, proto.HostHeartbeatResp{Shapes: h.shapes.Shapes(c.UserContext())})
}

func (h *Handler) HandleListHosts(c *fiber.Ctx) error {
	hosts, err := h.repo.ListHosts(c.UserContext())
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, hosts)
}

// Bound host-reported metadata and its lifetime. These hints never authorize a
// restore; the existing mTLS self-host middleware binds this report to req.ID.
func snapshotCacheHints(hints []proto.CachedSnapshot, now time.Time) []proto.CachedSnapshot {
	out := make([]proto.CachedSnapshot, 0, min(len(hints), proto.MaxCachedSnapshotHints))
	seen := make(map[string]bool)
	for _, hint := range hints {
		if len(out) == proto.MaxCachedSnapshotHints {
			break
		}
		if len(hint.ID) != 31 || !strings.HasPrefix(hint.ID, "snap_") || seen[hint.ID] || !hint.ExpiresAt.After(now) {
			continue
		}
		if _, err := ulid.ParseStrict(hint.ID[5:]); err != nil {
			continue
		}
		if maxExpiry := now.Add(10 * time.Minute); hint.ExpiresAt.After(maxExpiry) {
			hint.ExpiresAt = maxExpiry
		}
		seen[hint.ID] = true
		out = append(out, hint)
	}
	return out
}
