package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/middlewares"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/vm"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/utils"
	"github.com/oklog/ulid"
	log "github.com/sirupsen/logrus"
	"io"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/internal/storage"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// parseSnapshotCreate rejects unknown fields so public callers cannot supply
// internal ownership, status, placement or storage metadata. It accepts one JSON
// object only. Capture is executed asynchronously by the assigned host.
func parseSnapshotCreate(body []byte) (*proto.SnapshotCreateReq, string, string) {
	var req *proto.SnapshotCreateReq
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req == nil {
		return nil, "body", "expected a JSON object containing only name and type"
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, "body", "expected a single JSON object"
	}
	if req.Type != string(models.SnapshotTypeDisk) && req.Type != string(models.SnapshotTypeFull) {
		return nil, "type", "must be disk or full"
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if msg := validateSnapshotName(name); msg != "" {
			return nil, "name", msg
		}
		if name == "" {
			req.Name = nil
		} else {
			req.Name = &name
		}
	}
	return req, "", ""
}

// Snapshot names are display labels, not DNS names or lookup keys. Unlike
// sandbox/template names, uppercase letters and underscores are allowed.
func validateSnapshotName(name string) string {
	if name == "" {
		return ""
	}
	if len(name) > 63 {
		return "must not exceed 63 characters"
	}
	for i, c := range name {
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && (c != '-' && c != '_' || i == 0 || i == len(name)-1) {
			return "must contain only letters, digits, hyphens and underscores, and start and end with a letter or digit"
		}
	}
	return ""
}

// validateSnapshotSource is a preflight check, not an operation lock. The
// handler authenticates ownership and forwards to the source's owning region
// before loading attachments and rechecking state under capture coordination.
// Storage integrity and running-host availability still need worker-side checks.
func validateSnapshotSource(src *models.Sandbox, disks []models.SandboxDisk) (int, string) {
	if src == nil {
		return fiber.StatusNotFound, "sandbox not found"
	}
	if src.Status != models.StatusRunning {
		return fiber.StatusConflict, "sandbox must be running; resume it before creating a snapshot"
	}
	if len(disks) != 0 {
		return fiber.StatusConflict, "snapshot capture does not support attached external disks"
	}
	if src.Rootfs == nil || strings.TrimSpace(*src.Rootfs) == "" ||
		src.VCPU <= 0 || src.MemMib <= 0 || src.DiskMib <= 0 || src.Region == "" {
		return fiber.StatusConflict, "a snapshot cannot be created from this sandbox right now"
	}
	if src.HostID == nil || strings.TrimSpace(*src.HostID) == "" {
		return fiber.StatusServiceUnavailable, "sandbox is temporarily unavailable; please try again"
	}

	return 0, ""
}

// snapshotViewJSON deliberately omits internal storage paths, host placement,
// worker error codes and raw failure details. Never return the model directly
// from public snapshot endpoints.
// The immutable ID is the lookup key; display names are not unique.
type snapshotViewJSON struct {
	ID        string                `json:"id"`
	SandboxID string                `json:"sandbox_id"`
	Name      *string               `json:"name,omitempty"`
	Type      models.SnapshotType   `json:"type"`
	Status    models.SnapshotStatus `json:"status"`
	CreatedAt time.Time             `json:"created_at"`
	Shape     string                `json:"shape"`
	VCPU      int                   `json:"vcpu"`
	MemMib    int                   `json:"mem_mib"`
	DiskMib   int64                 `json:"disk_mib"`
	SizeBytes int64                 `json:"size_bytes"`
	ReadyAt   *time.Time            `json:"ready_at,omitempty"`
}

// HandleSnapshotCreate follows the fork controller's ownership and forwarding
// order. The assigned host reconciler completes or recovers the reservation.
func (h *Handler) HandleSnapshotCreate(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	userID := utils.UserIDFromContext(c.UserContext())
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, "invalid api key")
	}
	id := c.Params(middlewares.ParamSandboxID)
	src, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		log.WithContext(c.UserContext()).WithError(err).Error("[snapshot] source lookup")
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if src == nil || !ownerOK(c, src) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if src.Region != "" && src.Region != h.region {
		return h.forwardToPeerControl(c, src.Region, c.Method(), c.Path())
	}
	req, field, msg := parseSnapshotCreate(c.Body())
	if req == nil {
		return httpx.Fail(c, fiber.StatusBadRequest, map[string]string{field: msg})
	}
	if h.storage == nil {
		return httpx.Error(c, fiber.StatusServiceUnavailable, "snapshot service is temporarily unavailable; please try again")
	}
	disks, err := h.repo.ListSandboxDisks(c.UserContext(), id)
	if err != nil {
		log.WithContext(c.UserContext()).WithError(err).Error("[snapshot] disk lookup")
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if code, msg := validateSnapshotSource(src, disks); code != 0 {
		return httpx.Fail(c, code, msg)
	}
	host, err := h.repo.GetHost(c.UserContext(), *src.HostID)
	if err != nil {
		log.WithContext(c.UserContext()).WithError(err).Error("[snapshot] host lookup")
		return httpx.Error(c, fiber.StatusServiceUnavailable, "sandbox is temporarily unavailable; please try again")
	}
	if host == nil || host.Region != h.region || host.Status != models.HostStatusActive {
		return httpx.Error(c, fiber.StatusServiceUnavailable, "sandbox is temporarily unavailable; please try again")
	}
	// Match sandbox quota admission: count first, without a quota lock. Concurrent
	// creates and peer replication lag may temporarily exceed the limit.
	count, err := h.repo.CountQuotaSnapshots(c.UserContext(), userID)
	if err != nil {
		log.WithContext(c.UserContext()).WithError(err).Error("[quota] snapshot count")
		return httpx.Error(c, fiber.StatusServiceUnavailable, "internal error")
	}
	if count >= 5 {
		return httpx.Fail(c, fiber.StatusTooManyRequests, "maximum of five snapshots reached; delete an existing snapshot before creating another")
	}
	rec, err := h.repo.ReserveSnapshotCapture(c.UserContext(), models.Snapshot{
		ID:        models.SnapshotIDPrefix + ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String(),
		SandboxID: id, UserID: userID, Name: req.Name, Type: models.SnapshotType(req.Type), Region: h.region,
	})
	if errors.Is(err, models.ErrSnapshotCaptureConflict) {
		return httpx.Fail(c, fiber.StatusConflict, "sandbox is busy; wait for the current operation to finish and try again")
	}
	if err != nil {
		log.WithContext(c.UserContext()).WithError(err).Error("[snapshot] reserve capture")
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	c.Set("X-Poll-After", "2")
	return httpx.SuccessStatus(c, fiber.StatusAccepted, snapshotView(*rec))
}

// HandleSnapshotDelete hides the row in its owning region. Bucket artifacts are
// retained so in-flight and lagging cross-region restores can finish safely.
// Do not hard-delete bucket objects here: an accepted restore may still be
// downloading them, and a peer with replication lag may still accept a restore
// from its ready row. A local database check cannot rule out either case.
// Any future object cleanup must first prevent new restores across all regions
// and ensure every accepted restore has finished using the artifacts.
func (h *Handler) HandleSnapshotDelete(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	userID := utils.UserIDFromContext(c.UserContext())
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, "invalid api key")
	}
	id := c.Params(middlewares.ParamSnapshotID)
	rec, err := h.repo.GetSnapshot(c.UserContext(), id, userID)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "snapshot not found")
	}
	if rec.Region != h.region {
		return h.forwardToPeerControl(c, rec.Region, c.Method(), c.Path())
	}
	status, err := h.repo.SoftDeleteSnapshot(c.UserContext(), id, userID, h.region)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if status == "" {
		return httpx.Fail(c, fiber.StatusConflict, "snapshot cannot be deleted yet; wait for creation to finish and try again")
	}
	log.WithContext(c.UserContext()).WithField("snapshot_id", id).Info("[snapshot] metadata deleted; bucket artifacts retained")
	return httpx.SuccessStatus(c, fiber.StatusAccepted, struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}{id, status})
}

func snapshotView(s models.Snapshot) snapshotViewJSON {
	return snapshotViewJSON{ID: s.ID, SandboxID: s.SandboxID, Name: s.Name, Type: s.Type,
		Status: s.Status, CreatedAt: s.CreatedAt, Shape: s.Shape, VCPU: s.VCPU, MemMib: s.MemMib,
		DiskMib: s.DiskMib, SizeBytes: s.SizeBytes, ReadyAt: s.ReadyAt}
}

func (h *Handler) HandleSnapshotGet(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	user := utils.UserIDFromContext(c.UserContext())
	if user == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, "invalid api key")
	}
	rec, err := h.repo.GetSnapshot(c.UserContext(), c.Params(middlewares.ParamSnapshotID), user)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "snapshot not found")
	}
	// Poll the writer's region so a locally stale creating row does not delay readiness.
	if rec.Region != h.region {
		return h.forwardToPeerControl(c, rec.Region, c.Method(), c.Path())
	}
	return httpx.Success(c, snapshotView(*rec))
}

func (h *Handler) HandleSnapshotList(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	user := utils.UserIDFromContext(c.UserContext())
	if user == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, "invalid api key")
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
	recs, err := h.repo.ListUserSnapshots(c.UserContext(), user, limit, offset)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	total, err := h.repo.CountUserSnapshots(c.UserContext(), user)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	out := make([]snapshotViewJSON, 0, len(recs))
	for _, rec := range recs {
		out = append(out, snapshotView(rec))
	}
	return httpx.Paginated(c, out, total, limit, offset, len(out))
}

// prepareSnapshotRestore only resolves public inputs. It never starts a VM or
// trusts a caller-supplied storage URI. Normal create credit/plan gates still apply.
func prepareSnapshotRestore(req *proto.CreateReq, snap *models.Snapshot, shapes []proto.Shape) (int, string) {
	if snap == nil {
		return fiber.StatusNotFound, "snapshot not found"
	}
	if snap.Status != models.SnapshotStatusReady {
		return fiber.StatusConflict, "snapshot is not ready"
	}
	if snap.Type != models.SnapshotTypeDisk && snap.Type != models.SnapshotTypeFull {
		return fiber.StatusConflict, "snapshot type is unsupported"
	}
	if snap.VCPU <= 0 || snap.MemMib <= 0 || snap.DiskMib <= 0 || snap.Rootfs == "" {
		return fiber.StatusConflict, "this snapshot is unavailable for creating a sandbox"
	}
	if req.Rootfs != nil {
		return fiber.StatusBadRequest, "rootfs and snapshot_id cannot be combined"
	}
	if req.Shape == "" {
		req.Shape = snap.Shape
	}
	var shape *proto.Shape
	for i := range shapes {
		if shapes[i].ID == req.Shape {
			shape = &shapes[i]
			break
		}
	}
	if shape == nil {
		return fiber.StatusBadRequest, "unknown shape"
	}
	if snap.Type == models.SnapshotTypeFull && (shape.VCPU != snap.VCPU || shape.MemMib != snap.MemMib) {
		return fiber.StatusBadRequest, "full snapshots require the captured CPU and memory size"
	}
	if req.DiskMib == 0 {
		req.DiskMib = snap.DiskMib
	}
	if req.DiskMib < snap.DiskMib {
		return fiber.StatusBadRequest, "disk_mib cannot be smaller than the snapshot disk"
	}
	if !vm.IsAllowedDiskMib(req.DiskMib) {
		return fiber.StatusBadRequest, "disk_mib must be an allowed disk size"
	}
	if snap.Type == models.SnapshotTypeFull && req.DiskMib != snap.DiskMib {
		return fiber.StatusBadRequest, "disk resizing for full snapshots is not supported yet"
	}
	rootfs := snap.Rootfs
	req.Rootfs = &rootfs
	return 0, ""
}

// snapshotWorkerHost accepts only the host identity established by the mTLS
// role gate. Never accept identity from body, query, or forwarded user headers.
func snapshotWorkerHost(c *fiber.Ctx) string {
	return middlewares.CallerHostIfHostRole(c)
}
func (h *Handler) DbListSnapshotJobs(c *fiber.Ctx) error {
	host := snapshotWorkerHost(c)
	if host == "" {
		return httpx.Fail(c, fiber.StatusForbidden, "host identity required")
	}
	rows, err := h.repo.ListHostSnapshotJobs(c.UserContext(), host, h.region)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, rows)
}
func (h *Handler) DbGetHostSnapshot(c *fiber.Ctx) error {
	host := snapshotWorkerHost(c)
	if host == "" {
		return httpx.Fail(c, fiber.StatusForbidden, "host identity required")
	}
	row, err := h.repo.GetHostSnapshot(c.UserContext(), c.Params(middlewares.ParamSnapshotID), host, h.region)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if row == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "snapshot not found")
	}
	return httpx.Success(c, row)
}
func (h *Handler) DbSnapshotSource(c *fiber.Ctx) error {
	host := snapshotWorkerHost(c)
	if host == "" {
		return httpx.Fail(c, fiber.StatusForbidden, "host identity required")
	}
	src, err := h.repo.SnapshotCaptureSource(c.UserContext(), c.Params(middlewares.ParamSnapshotID), host, h.region)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if src == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "capture source unavailable")
	}
	return httpx.Success(c, src)
}
func (h *Handler) DbSnapshotProgress(c *fiber.Ctx) error {
	host := snapshotWorkerHost(c)
	if host == "" {
		return httpx.Fail(c, fiber.StatusForbidden, "host identity required")
	}
	id := c.Params(middlewares.ParamSnapshotID)
	rec, err := h.repo.GetHostSnapshot(c.UserContext(), id, host, h.region)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "snapshot not found")
	}
	var req proto.ControlSnapshotProgressReq
	dec := json.NewDecoder(bytes.NewReader(c.Body()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid progress body")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid progress body")
	}
	var status string
	switch c.Params(middlewares.ParamSnapshotAction) {
	case proto.SnapshotActionCaptured:
		if rec.Status == models.SnapshotStatusCreating && rec.CapturedAt != nil {
			status = string(rec.Status)
		} else {
			status, err = h.repo.MarkSnapshotCaptured(c.UserContext(), id, rec.UserID, h.region, host)
		}
	case proto.SnapshotActionReady:
		manifest, e := storage.ParseCaptureManifest(req.Manifest, rec.Type == models.SnapshotTypeFull)
		if e != nil {
			return httpx.Fail(c, fiber.StatusBadRequest, "invalid snapshot manifest")
		}
		var size int64
		for _, a := range manifest.Artifacts {
			if a.Size > 1<<50 || size > (1<<50)-a.Size {
				return httpx.Fail(c, fiber.StatusBadRequest, "invalid snapshot size")
			}
			size += a.Size
		}
		status, err = h.repo.MarkSnapshotReady(c.UserContext(), id, rec.UserID, h.region, host, "s3://"+storage.BundlePrefix(id), req.Manifest, size)
	case proto.SnapshotActionFailed:
		switch req.ErrorCode {
		case proto.SnapshotErrorCaptureFailed, proto.SnapshotErrorSourceUnavailable, proto.SnapshotErrorUploadTimeout, proto.SnapshotErrorCheckpointMissing:
		default:
			return httpx.Fail(c, fiber.StatusBadRequest, "invalid snapshot error code")
		}
		status, err = h.repo.MarkSnapshotFailed(c.UserContext(), id, rec.UserID, h.region, host, req.ErrorCode)
	default:
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid snapshot action")
	}
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if status == "" {
		return httpx.Fail(c, fiber.StatusConflict, "snapshot state changed")
	}
	return httpx.Success(c, proto.CASStatusResp{Status: status})
}
