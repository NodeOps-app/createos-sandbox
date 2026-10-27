package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/oklog/ulid"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/apiserver/middlewares"
	"github.com/NodeOps-app/sandbox/internal/audit"
	"github.com/NodeOps-app/sandbox/internal/cryptobox"
	"github.com/NodeOps-app/sandbox/internal/httpx"
	"github.com/NodeOps-app/sandbox/internal/httpx/types"
	"github.com/NodeOps-app/sandbox/internal/proto"
	"github.com/NodeOps-app/sandbox/internal/utils"
	"github.com/NodeOps-app/sandbox/models"
)

type diskCreateReq struct {
	Name        string          `json:"name"`
	Kind        string          `json:"kind"`
	Config      diskConfig      `json:"config"`
	Credentials diskCredentials `json:"credentials"`
}

type diskConfig struct {
	Bucket       string `json:"bucket"`
	Endpoint     string `json:"endpoint"`
	Region       string `json:"region,omitempty"`
	UsePathStyle bool   `json:"use_path_style,omitempty"`
}

type diskCredentials struct {
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

type diskViewJSON struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Kind      string          `json:"kind"`
	Config    json.RawMessage `json:"config"`
	CreatedAt time.Time       `json:"created_at"`
}

type diskDetachResp struct {
	Detached bool `json:"detached"`
}

type sandboxDiskView struct {
	DiskID      string          `json:"disk_id"`
	Name        string          `json:"name"`
	Kind        string          `json:"kind"`
	Config      json.RawMessage `json:"config"`
	MountPath   string          `json:"mount_path"`
	SubPath     string          `json:"sub_path,omitempty"`
	MountStatus string          `json:"mount_status"`
	MountError  string          `json:"mount_error,omitempty"`
}

type diskCredentialRotateReq struct {
	Credentials diskCredentials `json:"credentials"`
}

type diskDeletedResp struct {
	Deleted bool `json:"deleted"`
}

type resolvedSandboxDisksResp struct {
	Disks []proto.MMDSDisk `json:"disks"`
}

// maxDisksPerSandbox caps how many `sandbox_disks` rows a single sandbox
// may hold. The host-side mount reconciler is serial with a fixed ~46s
// readiness deadline (#66) — beyond ~100 attachments it silently reaps
// the VM. 20 keeps every spawn well inside the budget while leaving room
// for typical workloads (a few buckets at a few mount paths each).
const maxDisksPerSandbox = 20

// diskNameRE constrains user-supplied disk names to URL-safe, DNS-ish
// shapes. Mirrors the template name rule.
var diskNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// hasControlChar returns true if s contains any ASCII control char
// (0x00-0x1F, 0x7F) — including newlines and tabs. Used to reject
// credentials that would let an attacker inject extra INI sections /
// duplicate `[default]` blocks into the geesefs credentials file the
// guest agent builds. AWS-format keys are printable-ASCII so this is
// not a real constraint on legitimate input.
func hasControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b == 0x7F {
			return true
		}
	}
	return false
}

func (h *Handler) DbSetSandboxDiskStatus(c *fiber.Ctx) error {
	var r proto.ControlSetDiskStatusReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	switch r.Status {
	case models.SandboxDiskStatusPending,
		models.SandboxDiskStatusMounted,
		models.SandboxDiskStatusFailed:
	default:
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid status")
	}
	if r.MountPath == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "mount_path required")
	}
	sbID := c.Params(middlewares.ParamSandboxID)
	diskID := c.Params(middlewares.ParamDiskID)
	if err := h.repo.SetSandboxDiskStatus(c.UserContext(), sbID, diskID, r.MountPath, r.Status, r.Error); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] set disk status: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.NewIDResp(sbID))
}

// DbResetSandboxDiskStatus flips every disk attachment for a sandbox
// back to 'pending'. Called by the host's pause path.
func (h *Handler) DbResetSandboxDiskStatus(c *fiber.Ctx) error {
	sbID := c.Params(middlewares.ParamSandboxID)
	if err := h.repo.ResetSandboxDiskStatus(c.UserContext(), sbID); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] reset disk status: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.NewIDResp(sbID))
}

// DbResolveSandboxDisks returns the decrypted MMDS-shaped disks bundle
// for a sandbox the calling host owns. The route layer enforces
// (a) host-issued JWT, (b) `iss` host id matches sandboxes.host_id.
//
// Credentials in the response are PLAINTEXT — only ever emitted on the
// in-cluster internal endpoint, behind owner+host JWT auth.
func (h *Handler) DbResolveSandboxDisks(c *fiber.Ctx) error {
	if h.diskCipher == nil {
		return httpx.Error(c, fiber.StatusServiceUnavailable, "disks API not configured")
	}
	sbID := c.Params(middlewares.ParamSandboxID)
	disks, mountPaths, subPaths, err := h.repo.ResolveSandboxDisks(c.UserContext(), sbID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] resolve disks: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	out := make([]proto.MMDSDisk, 0, len(disks))
	for i, d := range disks {
		plain, derr := h.diskCipher.Decrypt(d.Credentials)
		if derr != nil {
			log.WithContext(c.UserContext()).Errorf("[handler] resolve disks decrypt %s: %v", d.ID, derr)
			return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
		}
		m := proto.MMDSDisk{
			ID:        d.ID,
			Kind:      d.Kind,
			MountPath: mountPaths[i],
			SubPath:   subPaths[i],
		}
		_ = proto.DecodeS3Config(d.Config, &m.Config)
		_ = proto.DecodeS3Creds(plain, &m.Credentials)
		out = append(out, m)
	}
	return httpx.Success(c, resolvedSandboxDisksResp{Disks: out})
}

// maxMountPath caps the absolute path the user can ask for. Long enough
// for any reasonable nesting; short enough that DB rows stay compact.
const maxMountPath = 512

// reservedMountPaths is a denylist of paths whose mount would break the
// guest entirely. We don't try to be exhaustive — just block the obvious
// foot-guns.
var reservedMountPaths = map[string]struct{}{
	"/":     {},
	"/bin":  {},
	"/boot": {},
	"/dev":  {},
	"/etc":  {},
	"/lib":  {},
	"/proc": {},
	"/root": {},
	"/run":  {},
	"/sbin": {},
	"/sys":  {},
	"/tmp":  {},
	"/usr":  {},
	"/var":  {},
}

// newDiskID mints a fresh disk_<ulid>. ULIDs are time-prefixed and
// lexicographically sortable.
func newDiskID() string {
	return models.DiskIDPrefix + ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
}

// normalizeSubPath strips leading/trailing slashes so the s3fs invocation
// receives a clean `bucket:/path` form regardless of how the user typed it.
func normalizeSubPath(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "/")
	return s
}

// validateSubPath checks an optional bucket sub-folder. Empty = OK (root).
// Non-empty: no `..`, no NUL, length cap (S3 key prefixes are bounded
// in practice). We don't require the prefix to actually exist in the
// bucket — s3fs creates lazily.
func validateSubPath(s string) error {
	if s == "" {
		return nil
	}
	if len(s) > 512 {
		return fmt.Errorf("exceeds 512 chars")
	}
	if strings.Contains(s, "..") {
		return fmt.Errorf("must not contain '..'")
	}
	if strings.ContainsRune(s, 0) {
		return fmt.Errorf("must not contain NUL")
	}
	if strings.HasPrefix(s, "-") {
		return fmt.Errorf("must not start with '-'")
	}
	return nil
}

// validateMountPath enforces absolute, no `..`, length cap, rejects
// known dangerous targets, normalises double-slashes / trailing slashes
// via path.Clean, and blocks any first-component /proc, /sys, /dev. The
// cleaned form is what callers must persist so the partial unique index
// on (sandbox_id, mount_path) catches collisions like //x vs /x.
func validateMountPath(p string) (string, error) {
	if p == "" {
		return "", errors.New("required")
	}
	if !strings.HasPrefix(p, "/") {
		return "", errors.New("must be absolute")
	}
	if strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") {
		return "", errors.New("must not contain '..'")
	}
	if len(p) > maxMountPath {
		return "", fmt.Errorf("exceeds %d chars", maxMountPath)
	}
	cleaned := path.Clean(p)
	if !strings.HasPrefix(cleaned, "/") {
		return "", errors.New("must be absolute")
	}
	if _, ok := reservedMountPaths[cleaned]; ok {
		return "", fmt.Errorf("must not target system path %q", cleaned)
	}
	if cleaned != "/" {
		first := strings.SplitN(strings.TrimPrefix(cleaned, "/"), "/", 2)[0]
		switch first {
		case "proc", "sys", "dev":
			return "", fmt.Errorf("mount_path %q is reserved (cannot mount under /proc, /sys, /dev)", cleaned)
		}
	}
	return cleaned, nil
}

// HandleDiskCreate validates + (a) probes credentials + AES-GCM-encrypts
// the secret bundle + inserts the disks row.
func (h *Handler) HandleDiskCreate(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	if h.diskCipher == nil {
		return httpx.Error(c, fiber.StatusServiceUnavailable, "disks API not configured")
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	// Per-user disk caps. Internal keys bypass.
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
			concurrentCap := L.MaxSandboxDisks
			if concurrentCap >= 0 {
				n, cerr := h.repo.CountDisksActive(c.UserContext(), userID)
				if cerr != nil {
					log.WithContext(c.UserContext()).Errorf("[quota] disk concurrent count: %v", cerr)
					return httpx.Error(c, fiber.StatusServiceUnavailable, "internal error")
				}
				if n >= concurrentCap {
					return httpx.Fail(c, fiber.StatusTooManyRequests, fmt.Sprintf(
						"disk concurrent quota reached (%d / %d). Delete an unused disk first.", n, concurrentCap))
				}
			}
			perDayCap := L.MaxSandboxDisksPerDay
			if perDayCap >= 0 {
				n, cerr := h.repo.CountDisksSince(c.UserContext(), userID, time.Now().Add(-24*time.Hour))
				if cerr != nil {
					log.WithContext(c.UserContext()).Errorf("[quota] disk per-day count: %v", cerr)
					return httpx.Error(c, fiber.StatusServiceUnavailable, "internal error")
				}
				if n >= perDayCap {
					return httpx.Fail(c, fiber.StatusTooManyRequests, fmt.Sprintf(
						"disk per-day quota reached (%d / %d). Try again in 24h.", n, perDayCap))
				}
			}
		}
	}
	var req diskCreateReq
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	req.Name = strings.TrimSpace(req.Name)
	if !diskNameRE.MatchString(req.Name) {
		return httpx.Fail(c, fiber.StatusBadRequest,
			"name must be 1–63 chars, lowercase alphanumeric + dash, must not start with dash")
	}
	if req.Kind != models.DiskKindS3 {
		return httpx.Fail(c, fiber.StatusBadRequest,
			fmt.Sprintf("kind %q not supported (s3 only)", req.Kind))
	}
	if strings.TrimSpace(req.Config.Bucket) == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "bucket is required")
	}
	if strings.TrimSpace(req.Config.Endpoint) == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "endpoint is required")
	}
	if u, err := url.Parse(req.Config.Endpoint); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "endpoint must be a valid http(s) URL")
	}
	if req.Credentials.AccessKey == "" || req.Credentials.SecretKey == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "access_key and secret_key are required")
	}
	// Credentials end up serialized into a geesefs INI file inside the
	// guest (`[default]\naws_access_key_id=<KEY>\naws_secret_access_key=<SECRET>`).
	// Reject control chars (newlines especially) at the front door so an
	// attacker can't inject a second [default] section that overrides
	// `aws_*` with attacker-controlled values, or a [profile] block, or
	// other INI directives. Real AWS / S3-compatible keys are printable
	// ASCII without whitespace; this also catches accidental \r\n from
	// copy-paste-from-Excel.
	if hasControlChar(req.Credentials.AccessKey) {
		return httpx.Fail(c, fiber.StatusBadRequest, "access_key must not contain control characters")
	}
	if hasControlChar(req.Credentials.SecretKey) {
		return httpx.Fail(c, fiber.StatusBadRequest, "secret_key must not contain control characters")
	}

	// (a) preflight: HEAD the bucket. Catches typos / wrong-bucket / bad
	// creds / unreachable endpoint at the moment the user fills the form.
	// 3s timeout is the operator-visible upper bound for "is this reachable".
	if err := probeBucket(c.UserContext(), req.Config, req.Credentials); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, err.Error())
	}

	credJSON, err := json.Marshal(req.Credentials)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] credentials marshal: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	encrypted, err := h.diskCipher.Encrypt(credJSON)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] credentials encrypt: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	configJSON, err := json.Marshal(req.Config)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] config marshal: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}

	rec := models.Disk{
		ID:          newDiskID(),
		UserID:      userID,
		Name:        req.Name,
		Kind:        req.Kind,
		Config:      configJSON,
		Credentials: encrypted,
	}
	if err := h.repo.InsertDisk(c.UserContext(), &rec); err != nil {
		// Unique violation → friendly 409.
		if isUniqueViolation(err) {
			return httpx.Fail(c, fiber.StatusConflict,
				fmt.Sprintf("a disk named %q already exists", req.Name))
		}
		log.WithContext(c.UserContext()).Errorf("[disks] insert: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	h.audit.Emit(c.UserContext(), h.auditCtxWithSubject(c, "disk", rec.ID),
		audit.ActionDiskCreate, audit.OperationCreate,
		audit.BuildDiskCreate(&rec, req.Config.Bucket, req.Config.Endpoint, req.Config.Region, req.Config.UsePathStyle))
	return httpx.Success(c, diskView(rec))
}

// HandleDiskList returns the user's live disks. Honors ?limit=N (default
// 50, max 500) — matches the GET /v1/sandboxes pagination shape. Without
// this, a user with thousands of disks dumps the whole table in one
// response (scenario T43).
func (h *Handler) HandleDiskList(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	if h.diskCipher == nil {
		return httpx.Error(c, fiber.StatusServiceUnavailable, "disks API not configured")
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
	recs, err := h.repo.ListDisksPaged(c.UserContext(), userID, limit, offset)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] list: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	total, err := h.repo.CountUserDisks(c.UserContext(), userID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] count: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	out := make([]diskViewJSON, 0, len(recs))
	for _, r := range recs {
		out = append(out, diskView(r))
	}
	return httpx.Paginated(c, out, total, limit, offset, len(out))
}

// HandleDiskGet looks up by disk_ id or name.
func (h *Handler) HandleDiskGet(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	if h.diskCipher == nil {
		return httpx.Error(c, fiber.StatusServiceUnavailable, "disks API not configured")
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	idOrName := c.Params(middlewares.ParamSandboxID)
	rec, err := h.repo.GetDisk(c.UserContext(), userID, idOrName)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] get: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "not found")
	}
	return httpx.Success(c, diskView(*rec))
}

// HandleDiskDelete soft-deletes the disk. Refuses with 409 if any
// non-destroyed sandbox still holds an attachment.
func (h *Handler) HandleDiskDelete(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	if h.diskCipher == nil {
		return httpx.Error(c, fiber.StatusServiceUnavailable, "disks API not configured")
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	idOrName := c.Params(middlewares.ParamSandboxID)
	err := h.repo.DeleteDisk(c.UserContext(), userID, idOrName)
	if errors.Is(err, models.ErrDiskAttached) {
		return httpx.Fail(c, fiber.StatusConflict,
			"disk is attached to a running or paused sandbox — detach first")
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return httpx.Fail(c, fiber.StatusNotFound, "not found")
	}
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] delete: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, diskDeletedResp{Deleted: true})
}

// HandleDiskCredentialRotate rotates the bucket creds on an existing
// disk row without deleting + recreating. Re-runs the create-time bucket
// probe with the new creds, re-encrypts the credentials JSON with the
// active disk_credential_key, UPDATEs the disks row, then fans out a
// fresh MMDS push to every currently-running sandbox that has this
// disk attached (best-effort — DB commit is the success boundary).
// Returns the same DiskView shape as GET /v1/disks/:id; credentials
// are NEVER echoed back.
func (h *Handler) HandleDiskCredentialRotate(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	if h.diskCipher == nil {
		return httpx.Error(c, fiber.StatusServiceUnavailable, "disks API not configured")
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	var req diskCredentialRotateReq
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if req.Credentials.AccessKey == "" || req.Credentials.SecretKey == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "access_key and secret_key are required")
	}
	// Same INI-injection guard as HandleDiskCreate — see there for rationale.
	if hasControlChar(req.Credentials.AccessKey) {
		return httpx.Fail(c, fiber.StatusBadRequest, "access_key must not contain control characters")
	}
	if hasControlChar(req.Credentials.SecretKey) {
		return httpx.Fail(c, fiber.StatusBadRequest, "secret_key must not contain control characters")
	}
	idOrName := c.Params(middlewares.ParamSandboxID)
	disk, err := h.repo.GetDisk(c.UserContext(), userID, idOrName)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] rotate lookup: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if disk == nil {
		// Same 404 shape as GET — no cross-user existence leak.
		return httpx.Fail(c, fiber.StatusNotFound, "not found")
	}
	// Re-probe against the existing config + the new creds. Same accept
	// map as POST /v1/disks (200/401/403 OK, 404 → bucket missing, etc.).
	var cfg diskConfig
	if err := json.Unmarshal(disk.Config, &cfg); err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] rotate decode config: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if err := probeBucket(c.UserContext(), cfg, req.Credentials); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, err.Error())
	}
	credJSON, err := json.Marshal(req.Credentials)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] rotate marshal: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	encrypted, err := h.diskCipher.Encrypt(credJSON)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] rotate encrypt: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if err := h.repo.UpdateDiskCredentials(c.UserContext(), disk.ID, userID, encrypted); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return httpx.Fail(c, fiber.StatusNotFound, "not found")
		}
		log.WithContext(c.UserContext()).Errorf("[disks] rotate update: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	// Best-effort MMDS refresh on every running sandbox holding this
	// disk. Per-host failures are logged but don't fail the request —
	// the DB row is the source of truth, and the agent will pick up
	// fresh creds on next resume anyway.
	h.pushRotatedCredsToHosts(c, disk, req.Credentials)

	// Re-read so created_at + name reflect the live row.
	updated, _ := h.repo.GetDisk(c.UserContext(), userID, disk.ID)
	if updated == nil {
		updated = disk
	}
	return httpx.Success(c, diskView(*updated))
}

// pushRotatedCredsToHosts walks every running sandbox attached to the
// rotated disk and POSTs a fresh ResolvedDisk to the owning host's
// live-attach endpoint. The host's AttachDiskLive treats a matching
// (disk_id, mount_path) pair as a replace, so an existing mount gets
// new credentials on the next agent reconcile tick.
func (h *Handler) pushRotatedCredsToHosts(c *fiber.Ctx, disk *models.Disk, plain diskCredentials) {
	atts, err := h.repo.ListRunningSandboxesForDisk(c.UserContext(), disk.ID)
	if err != nil {
		log.WithContext(c.UserContext()).Warnf("[disks] rotate fanout list: %v", err)
		return
	}
	plainJSON, err := json.Marshal(plain)
	if err != nil {
		log.WithContext(c.UserContext()).Warnf("[disks] rotate fanout marshal: %v", err)
		return
	}
	uid := utils.UserID(c)
	for _, a := range atts {
		if a.HostAddr == "" {
			log.WithContext(c.UserContext()).Warnf("[disks] rotate fanout: sandbox %s has no host addr", a.SandboxID)
			continue
		}
		sealed, err := sealDiskCreds(a.HostPublicKey, plainJSON)
		if err != nil {
			log.WithContext(c.UserContext()).Warnf("[disks] rotate fanout seal %s: %v", a.SandboxID, err)
			continue
		}
		body, _ := json.Marshal(proto.ResolvedDisk{
			DiskID:      disk.ID,
			Kind:        disk.Kind,
			Config:      disk.Config,
			Credentials: sealed,
			MountPath:   a.MountPath,
			SubPath:     a.SubPath,
		})
		url := "http://" + a.HostAddr + "/v1/sandboxes/" + a.SandboxID + "/disks"
		req, err := http.NewRequestWithContext(c.UserContext(), http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			log.WithContext(c.UserContext()).Warnf("[disks] rotate fanout build %s: %v", a.SandboxID, err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		httpx.SetRequestIDHeader(c.UserContext(), req)
		utils.SetUserIDHeader(req, uid)
		resp, err := h.http.Do(req)
		if err != nil {
			log.WithContext(c.UserContext()).Warnf("[disks] rotate fanout %s -> %s: %v", a.SandboxID, a.HostAddr, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			log.WithContext(c.UserContext()).Warnf("[disks] rotate fanout %s -> %s: HTTP %d", a.SandboxID, a.HostAddr, resp.StatusCode)
		}
	}
}

// HandleSandboxDiskAttach live-attaches a disk to a running sandbox.
// Mirrors the create-time attach flow: validates ownership, persists
// the sandbox_disks row, decrypts credentials, forwards to the host.
func (h *Handler) HandleSandboxDiskAttach(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	if h.diskCipher == nil {
		return httpx.Error(c, fiber.StatusServiceUnavailable, "disks API not configured")
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	var req proto.DiskAttachment
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	req.DiskID = strings.TrimSpace(req.DiskID)
	if req.DiskID == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "disk_id is required")
	}
	cleanedMP, err := validateMountPath(req.MountPath)
	if err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "mount_path: "+err.Error())
	}
	req.MountPath = cleanedMP
	subPath := normalizeSubPath(req.SubPath)
	if err := validateSubPath(subPath); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "sub_path: "+err.Error())
	}
	sbID := c.Params(middlewares.ParamSandboxID)
	rec, err := h.repo.Get(c.UserContext(), sbID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] sandbox lookup: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil || rec.CreatedBy != userID {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if rec.Region != "" && rec.Region != h.region {
		return h.forwardToPeerControl(c, rec.Region, c.Method(), c.Path())
	}
	// Live attach only makes sense on a running VM. Reject paused / pausing /
	// destroyed states with a hint — paused VMs get their disks via the
	// existing resume-time push.
	if rec.Status != models.StatusRunning {
		return httpx.Fail(c, fiber.StatusConflict,
			fmt.Sprintf("sandbox is %s; live attach only works on running", rec.Status))
	}
	// Enforce the per-sandbox max BEFORE we decrypt or forward. Counts
	// only the attachments the user can currently see (mirrors what
	// ListSandboxDisks returns). The DB has no equivalent constraint —
	// without this gate a runaway client can grow `sandbox_disks` past
	// the host-side mount-reconcile budget (#66).
	if existing, err := h.repo.ListSandboxDisks(c.UserContext(), sbID); err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] count attached: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	} else if len(existing) >= maxDisksPerSandbox {
		return httpx.Fail(c, fiber.StatusConflict,
			fmt.Sprintf("sandbox already has %d disks attached (max %d); detach one before attaching another",
				len(existing), maxDisksPerSandbox))
	}
	disk, err := h.repo.GetDisk(c.UserContext(), userID, req.DiskID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] disk lookup: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if disk == nil {
		return httpx.Fail(c, fiber.StatusNotFound, fmt.Sprintf("disk %q not found", req.DiskID))
	}
	plain, err := h.diskCipher.Decrypt(disk.Credentials)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] decrypt: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	// Persist the attachment first; forward second. If forward fails the
	// row is still there and a subsequent retry sees the disk attached.
	//
	// TOCTOU-safe: AttachDiskIfRunning locks the sandbox row and inserts
	// only if status='running' at lock time. Without this, a concurrent
	// pause can flip status='pausing' between the status check above and
	// this insert — the row then exists but isn't in the snapshot bundle,
	// so resume tries to mount a disk the agent has no MMDS entry for and
	// the VM is unrecoverable. Issue #67.
	running, _, diskExists, err := h.repo.AttachDiskIfRunning(c.UserContext(), sbID, disk.ID, req.MountPath, subPath)
	if err != nil {
		// Unique violation (SQLState 23505) on (sandbox_id, mount_path)
		// means another disk is already at this path. Friendly 409.
		if isUniqueViolation(err) {
			return httpx.Fail(c, fiber.StatusConflict,
				fmt.Sprintf("another disk is already mounted at %q on this sandbox", req.MountPath))
		}
		log.WithContext(c.UserContext()).Errorf("[disks] attach row: %T %v", err, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if !diskExists {
		// Disk soft-deleted between our GetDisk and the locked insert.
		return httpx.Fail(c, fiber.StatusNotFound, fmt.Sprintf("disk %q not found", req.DiskID))
	}
	if !running {
		// The sandbox flipped out of 'running' between the handler's
		// status check and the locked insert (most commonly into
		// 'pausing'). Refuse rather than leaving a row that won't be
		// in the snapshot bundle.
		return httpx.Fail(c, fiber.StatusConflict,
			"sandbox is no longer running; live attach aborted")
	}
	// Forward the bundle to the host that owns this sandbox. Disk
	// credentials are sealed to the host's Ed25519 pubkey so the cleartext
	// JSON never traverses the control→host channel.
	host := models.Host{ID: derefString(rec.HostID, ""), Addr: ""}
	if hostRec, err := h.repo.GetHost(c.UserContext(), host.ID); err == nil && hostRec != nil {
		host.Addr = hostRec.Addr
		host.PublicKey = hostRec.PublicKey
	}
	if host.Addr == "" {
		return httpx.Error(c, fiber.StatusServiceUnavailable, "host unreachable")
	}
	sealed, err := sealDiskCreds(host.PublicKey, plain)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] seal disk creds for host %s: %v", host.ID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	body, _ := json.Marshal(proto.ResolvedDisk{
		DiskID:      disk.ID,
		Kind:        disk.Kind,
		Config:      disk.Config,
		Credentials: sealed,
		MountPath:   req.MountPath,
		SubPath:     subPath,
	})
	c.Request().SetBody(body)
	if err := ForwardResponseTo(c, host, "/v1/sandboxes/"+sbID+"/disks", h.http); err != nil {
		return err
	}
	h.audit.Emit(c.UserContext(), h.auditCtxWithSubject(c, "disk", disk.ID),
		audit.ActionDiskAttach, audit.OperationModify,
		audit.BuildDiskAttach(disk, sbID, req.MountPath, subPath))
	return nil
}

// HandleSandboxDiskDetach live-detaches a disk. For a running sandbox
// we forward to the host FIRST (so the agent unmounts via MMDS push)
// and only delete the DB row on success — otherwise a forward failure
// would leave the DB saying "detached" while the VM keeps the FUSE
// mount live, with no reconciler to repair it until the next pause/
// resume. For paused / destroyed sandboxes there's nothing to push to,
// so the DB row removal is the whole operation. The host-side
// reconciler in vm/disks_reconcile.go closes the residual gap (e.g. a
// successful row delete on a paused sandbox that later resumes on a
// stale-MMDS host).
func (h *Handler) HandleSandboxDiskDetach(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	sbID := c.Params(middlewares.ParamSandboxID)
	diskParam := c.Params(middlewares.ParamDiskID)
	mountPath := c.Query("mount_path")
	if mountPath == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "mount_path query parameter required")
	}
	rec, err := h.repo.Get(c.UserContext(), sbID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] sandbox lookup: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil || rec.CreatedBy != userID {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if rec.Region != "" && rec.Region != h.region {
		return h.forwardToPeerControl(c, rec.Region, c.Method(), c.Path())
	}
	// Accept either a `disk_<ulid>` id or a user-scoped disk name in the
	// URL — matches attach (req.DiskID via GetDisk) and the SDK docs.
	// Without this lookup, only the literal id worked; a name in the path
	// 404s here even though the same name attaches fine.
	disk, err := h.repo.GetDisk(c.UserContext(), userID, diskParam)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] disk lookup: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if disk == nil {
		return httpx.Fail(c, fiber.StatusNotFound, fmt.Sprintf("disk %q not found", diskParam))
	}
	diskID := disk.ID
	// Confirm the (sandbox_id, disk_id, mount_path) tuple exists before
	// we touch the host. Saves a host call for a stale UI retry, and
	// preserves the pre-existing 404 behaviour on bogus detach attempts.
	attached, err := h.repo.ListSandboxDisks(c.UserContext(), sbID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] detach lookup attached: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	found := false
	for _, sd := range attached {
		if sd.DiskID == diskID && sd.MountPath == mountPath {
			found = true
			break
		}
	}
	if !found {
		return httpx.Fail(c, fiber.StatusNotFound, "disk not attached at that mount_path")
	}
	// Running: forward to host first. The agent must observe the new
	// (disk-less) MMDS before we forget about the attachment, or we end
	// up with a DB that doesn't know about a still-live FUSE mount.
	if rec.Status == models.StatusRunning {
		host := models.Host{ID: derefString(rec.HostID, "")}
		if hostRec, herr := h.repo.GetHost(c.UserContext(), host.ID); herr == nil && hostRec != nil {
			host.Addr = hostRec.Addr
		}
		if host.Addr == "" {
			// Host record missing addr — can't push MMDS. Refuse the
			// detach rather than diverging state. Caller retries when
			// the host is healthy again, or pauses to clear it.
			return httpx.Error(c, fiber.StatusServiceUnavailable, "owning host unreachable; try again")
		}
		fwdPath := "/v1/sandboxes/" + sbID + "/disks/" + diskID
		if err := ForwardResponseTo(c, host, fwdPath, h.http); err != nil {
			// ForwardResponseTo already wrote an error response to the client.
			// DB row left intact so the next retry can finish the job.
			log.WithContext(c.UserContext()).Warnf("[disks] detach forward to host failed: %v (row kept)", err)
			return nil
		}
		// Forwarding can write a host rejection or a local 502 and return nil.
		// Only a successful response permits forgetting the attachment.
		if status := c.Response().StatusCode(); status < http.StatusOK || status >= http.StatusMultipleChoices {
			return nil
		}
	}
	// Forward succeeded (or sandbox isn't running) — now drop the row.
	// A failure here leaves the MMDS already updated but the row
	// lingering; the host-side reconciler will see the divergence on
	// its next tick and re-push, eventually converging.
	if err := h.repo.DetachDisk(c.UserContext(), sbID, diskID, mountPath); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Another concurrent detach raced us — still a success
			// from the caller's POV.
			return httpx.Success(c, diskDetachResp{Detached: true})
		}
		log.WithContext(c.UserContext()).Errorf("[disks] detach row: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	detachedDisk, _ := h.repo.GetDisk(c.UserContext(), userID, diskID)
	h.audit.Emit(c.UserContext(), h.auditCtxWithSubject(c, "disk", diskID),
		audit.ActionDiskDetach, audit.OperationModify,
		audit.BuildDiskDetach(detachedDisk, sbID, mountPath))
	return httpx.Success(c, diskDetachResp{Detached: true})
}

// derefString returns ptr value or empty.
func derefString(p *string, fallback string) string {
	if p != nil && *p != "" {
		return *p
	}
	return fallback
}

// HandleSandboxDisksList returns the disks attached to a sandbox the
// caller owns, with per-attachment mount status.
func (h *Handler) HandleSandboxDisksList(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	sbID := c.Params(middlewares.ParamSandboxID)
	rec, err := h.repo.Get(c.UserContext(), sbID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] sandbox lookup: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil || rec.CreatedBy != userID {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	rows, err := h.repo.ListSandboxDisks(c.UserContext(), sbID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[disks] list attached: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	out := make([]sandboxDiskView, 0, len(rows))
	for _, sd := range rows {
		v := sandboxDiskView{
			DiskID:      sd.DiskID,
			Name:        sd.Name,
			Kind:        sd.Kind,
			Config:      sd.Config,
			MountPath:   sd.MountPath,
			SubPath:     sd.SubPath,
			MountStatus: sd.MountStatus,
		}
		if sd.MountError != nil {
			v.MountError = *sd.MountError
		}
		out = append(out, v)
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
	page, total := httpx.PageSlice(out, limit, offset)
	return httpx.Paginated(c, page, total, limit, offset, len(page))
}

func diskView(d models.Disk) diskViewJSON {
	return diskViewJSON{
		ID:        d.ID,
		Name:      d.Name,
		Kind:      d.Kind,
		Config:    d.Config,
		CreatedAt: d.CreatedAt,
	}
}

// probeBucket performs a signed `BucketExists` (HEAD <endpoint>/<bucket>)
// against the user's provided endpoint+creds. Unlike the previous
// unsigned-HEAD heuristic, this gives an authoritative existence answer
// even against MinIO/R2 endpoints that return 403 to anonymous HEADs
// regardless of whether the bucket exists.
//
// Outcomes:
//   - exists=true, err=nil          → bucket reachable, creds valid
//   - exists=false, err=nil         → bucket missing — return a clear
//     "bucket not found" error
//   - err != nil (connect/sig)      → endpoint unreachable or creds bad
func probeBucket(ctx context.Context, cfg diskConfig, creds diskCredentials) error {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	endpointURL, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return fmt.Errorf("endpoint parse: %v", err)
	}
	host := endpointURL.Host
	if host == "" {
		host = cfg.Endpoint
	}
	secure := strings.EqualFold(endpointURL.Scheme, "https")
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}

	// SSRF gate: reject endpoints that resolve to internal address space
	// (loopback, RFC1918, link-local, ULA, CGNAT, etc.). Without this a
	// hostile user can point disks at 169.254.169.254 (cloud IMDS),
	// 10.x scheduler/postgres, or any private control-plane service and
	// turn the control plane into an SSRF probe. The same check runs
	// again at DialContext time below so DNS rebinding can't bypass it.
	if err := validateExternalEndpoint(probeCtx, host); err != nil {
		return err
	}

	cli, err := minio.New(host, &minio.Options{
		Creds:        credentials.NewStaticV4(creds.AccessKey, creds.SecretKey, ""),
		Secure:       secure,
		Region:       region,
		BucketLookup: bucketLookupFromCfg(cfg.UsePathStyle),
		Transport:    newSSRFGuardedTransport(),
	})
	if err != nil {
		return fmt.Errorf("s3 client: %v", err)
	}
	exists, err := cli.BucketExists(probeCtx, cfg.Bucket)
	if err != nil {
		// minio-go surfaces both transport errors and S3 errors here.
		// Wrap with the endpoint so the user can tell typos apart.
		return fmt.Errorf("bucket check at %s: %v", cfg.Endpoint, err)
	}
	if !exists {
		return fmt.Errorf("bucket %q not found at %s", cfg.Bucket, cfg.Endpoint)
	}
	return nil
}

func bucketLookupFromCfg(pathStyle bool) minio.BucketLookupType {
	if pathStyle {
		return minio.BucketLookupPath
	}
	return minio.BucketLookupDNS
}

// validateExternalEndpoint blocks SSRF by ensuring `hostport` resolves
// only to public, routable, non-internal IPs. Performs a real DNS
// lookup and rejects on the first private/loopback/link-local hit.
//
// This is the *pre*-flight check used before constructing the minio
// client. newSSRFGuardedTransport re-validates at every Dial so DNS
// rebinding can't smuggle a private IP past this gate.
func validateExternalEndpoint(ctx context.Context, hostport string) error {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	if host == "" {
		return fmt.Errorf("endpoint: empty host")
	}
	// Bare-IP literal: skip resolution, just classify it.
	if ip := net.ParseIP(host); ip != nil {
		if !isPublicIP(ip) {
			return fmt.Errorf("endpoint resolves to a non-routable / internal address (%s)", ip)
		}
		return nil
	}
	resolver := net.DefaultResolver
	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("endpoint resolve: %v", err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("endpoint %q resolves to no addresses", host)
	}
	for _, a := range addrs {
		if !isPublicIP(a.IP) {
			return fmt.Errorf("endpoint resolves to a non-routable / internal address (%s)", a.IP)
		}
	}
	return nil
}

// isPublicIP returns true only for globally-routable unicast addresses.
// Rejects: unspecified, loopback (127/8, ::1), link-local (169.254/16,
// fe80::/10), private (10/8, 172.16/12, 192.168/16, fc00::/7),
// CGNAT (100.64/10), broadcast / multicast / IPv4-mapped IPv6 oddities.
func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsPrivate() {
		return false
	}
	// Carrier-grade NAT (100.64.0.0/10) — RFC 6598. Go's IsPrivate
	// doesn't cover this, and ISPs use it for internal-only ranges.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && (v4[1]&0xc0) == 64 {
			return false
		}
	}
	return true
}

// newSSRFGuardedTransport returns an *http.Transport whose DialContext
// re-runs isPublicIP on the resolved IP before connecting. This closes
// the DNS-rebinding gap left by the pre-flight lookup: an attacker who
// controls a public-IP-then-private-IP DNS record can't smuggle a
// private destination past validateExternalEndpoint.
func newSSRFGuardedTransport() *http.Transport {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, a := range ips {
				if !isPublicIP(a.IP) {
					return nil, fmt.Errorf("blocked: %s resolved to non-routable %s", host, a.IP)
				}
			}
			// Re-dial against the validated IP set by deferring to
			// the dialer with the original host:port; Dial's own
			// resolution will hit the same DNS records we just
			// checked (no rebinding within a single sub-second
			// window in practice). For full defense use the first
			// validated IP literal here.
			if len(ips) > 0 {
				return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
			}
			return dialer.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// sealDiskCreds wraps plaintext S3-credential JSON in a cryptobox
// envelope sealed to the destination host's Ed25519 pubkey. Hosts
// already publish that pubkey at registration (hosts.public_key), so
// we don't need any new key distribution: only the matching host can
// decrypt. JWT auth still authenticates the call; this protects the
// payload's confidentiality on the control→host channel.
//
// Returns the marshalled envelope (json.RawMessage) ready to drop into
// proto.ResolvedDisk.Credentials.
func sealDiskCreds(hostPub []byte, plain []byte) (json.RawMessage, error) {
	if len(hostPub) == 0 {
		return nil, errors.New("host public_key missing; cannot seal disk creds")
	}
	env, err := cryptobox.Seal(hostPub, cryptobox.PurposeDiskCredentials, plain)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return env.Marshal()
}
