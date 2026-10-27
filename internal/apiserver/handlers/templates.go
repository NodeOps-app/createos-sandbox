package handlers

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/oklog/ulid"
	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"

	"github.com/NodeOps-app/sandbox/internal/apiserver/middlewares"
	"github.com/NodeOps-app/sandbox/internal/audit"
	"github.com/NodeOps-app/sandbox/internal/builder"
	"github.com/NodeOps-app/sandbox/internal/clickhouse"
	"github.com/NodeOps-app/sandbox/internal/httpx"
	"github.com/NodeOps-app/sandbox/internal/httpx/types"
	"github.com/NodeOps-app/sandbox/internal/proto"
	"github.com/NodeOps-app/sandbox/internal/utils"
	"github.com/NodeOps-app/sandbox/models"
)

type templateCreateReq struct {
	Name       string `json:"name"`
	Dockerfile string `json:"dockerfile"`
	Base       string `json:"base,omitempty"`
}

type templatePatchReq struct {
	Status        string  `json:"status"`
	SHA256        *string `json:"sha256,omitempty"`
	SizeBytes     int64   `json:"size_bytes,omitempty"`
	Ext4SizeBytes int64   `json:"ext4_size_bytes,omitempty"`
}

type templateViewJSON struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Base          string     `json:"base"`
	Status        string     `json:"status"`
	Ext4SizeBytes int64      `json:"ext4_size_bytes"`
	CreatedAt     time.Time  `json:"created_at"`
	BuiltAt       *time.Time `json:"built_at,omitempty"`
	Dockerfile    string     `json:"dockerfile,omitempty"`
}

type countResp struct {
	Count int `json:"count"`
}

type templateBuildLogEvent struct {
	Line  string `json:"line"`
	Level string `json:"level"`
	TS    string `json:"ts"`
}

// templatesPerUserCap is the v1 hard cap on inflight (pending+building)
// builds per external user. 0 = no cap.
const templatesPerUserCap = 2

// MaxDockerfileBytes is the hard cap on user-submitted Dockerfile size.
const MaxDockerfileBytes = 64 * 1024

// newTemplateID mints a fresh tpl_<ulid>. Same Crockford-base32 ULID
// scheme as sandbox IDs; lexicographically sortable, time-prefixed.
func newTemplateID() string {
	return models.TemplateIDPrefix + ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
}

// handleTemplateSubmit accepts a Dockerfile, validates it inline, and
// inserts a 'pending' templates row. Builder picks it up on the next
// claim cycle.
func (h *Handler) HandleTemplateSubmit(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	// Per-user template caps. Internal keys bypass.
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
			concurrentCap := L.MaxSandboxTemplates
			if concurrentCap >= 0 {
				n, cerr := h.repo.CountTemplatesActive(c.UserContext(), userID)
				if cerr != nil {
					log.WithContext(c.UserContext()).Errorf("[quota] template concurrent count: %v", cerr)
					return httpx.Error(c, fiber.StatusServiceUnavailable, "internal error")
				}
				if n >= concurrentCap {
					return httpx.Fail(c, fiber.StatusTooManyRequests, fmt.Sprintf(
						"template concurrent quota reached (%d / %d). Delete an unused template first.", n, concurrentCap))
				}
			}
			perDayCap := L.MaxSandboxTemplatesPerDay
			if perDayCap >= 0 {
				n, cerr := h.repo.CountTemplatesSince(c.UserContext(), userID, time.Now().Add(-24*time.Hour))
				if cerr != nil {
					log.WithContext(c.UserContext()).Errorf("[quota] template per-day count: %v", cerr)
					return httpx.Error(c, fiber.StatusServiceUnavailable, "internal error")
				}
				if n >= perDayCap {
					return httpx.Fail(c, fiber.StatusTooManyRequests, fmt.Sprintf(
						"template per-day quota reached (%d / %d). Try again in 24h.", n, perDayCap))
				}
			}
		}
	}

	var req templateCreateReq
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "required")
	}
	if !validTemplateName(req.Name) {
		return httpx.Fail(c, fiber.StatusBadRequest,
			"must be 1–63 chars, lowercase alphanumeric + dash")
	}
	if len(req.Dockerfile) == 0 {
		return httpx.Fail(c, fiber.StatusBadRequest, "required")
	}
	if len(req.Dockerfile) > MaxDockerfileBytes {
		return httpx.Fail(c, fiber.StatusBadRequest,
			fmt.Sprintf("exceeds %d bytes", MaxDockerfileBytes))
	}

	base, vErr := builder.ValidateDockerfile([]byte(req.Dockerfile), nil)
	if vErr != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, vErr.Error())
	}

	// Per-user inflight cap.
	if templatesPerUserCap > 0 {
		n, err := h.repo.CountInflightTemplatesForUser(c.UserContext(), userID)
		if err != nil {
			return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
		}
		if n >= templatesPerUserCap {
			return httpx.Fail(c, fiber.StatusTooManyRequests,
				fmt.Sprintf("max %d builds in flight; finish one first", templatesPerUserCap))
		}
	}

	taken, err := h.repo.TemplateNameTaken(c.UserContext(), userID, req.Name)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if taken {
		return httpx.Fail(c, fiber.StatusConflict,
			fmt.Sprintf("a template named %q already exists; delete it first", req.Name))
	}

	rec := models.Template{
		ID:         newTemplateID(),
		UserID:     userID,
		Name:       req.Name,
		Base:       base,
		Status:     models.TemplateStatusPending,
		Dockerfile: req.Dockerfile,
	}
	if err := h.repo.InsertTemplate(c.UserContext(), rec); err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	h.audit.Emit(c.UserContext(), h.auditCtxWithSubject(c, "template", rec.ID),
		audit.ActionTemplateSubmit, audit.OperationCreate,
		audit.BuildTemplateSubmit(&rec))
	return httpx.Success(c, templateView(rec, false))
}

// handleTemplateList returns the user's templates, most-recent first.
func (h *Handler) HandleTemplateList(c *fiber.Ctx) error {
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
	recs, err := h.repo.ListUserTemplatesPaged(c.UserContext(), userID, limit, offset)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	total, err := h.repo.CountUserTemplates(c.UserContext(), userID)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	out := make([]templateViewJSON, 0, len(recs))
	for _, r := range recs {
		out = append(out, templateView(r, false))
	}
	return httpx.Paginated(c, out, total, limit, offset, len(out))
}

// handleTemplateGet looks up by tpl_id OR by friendly name (resolved via
// getLatestReadyByName). Returns 404 if not found, 403 if owned by
// another user.
func (h *Handler) HandleTemplateGet(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	rec, err := h.lookupUserTemplate(c.UserContext(), userID, c.Params(middlewares.ParamSandboxID))
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "not found")
	}
	includeDockerfile := c.Query("include") == "dockerfile"
	return httpx.Success(c, templateView(*rec, includeDockerfile))
}

// handleTemplateDelete soft-deletes the template (deleted_at = now()).
// R2 bytes are kept so paused VMs that referenced this tpl can still
// resume.
func (h *Handler) HandleTemplateDelete(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	rec, err := h.lookupUserTemplate(c.UserContext(), userID, c.Params(middlewares.ParamSandboxID))
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "not found")
	}
	id, err := h.repo.SoftDeleteTemplate(c.UserContext(), rec.ID, userID)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if id == "" {
		return httpx.Fail(c, fiber.StatusNotFound, "not found or already deleted")
	}
	h.audit.Emit(c.UserContext(), h.auditCtxWithSubject(c, "template", rec.ID),
		audit.ActionTemplateDelete, audit.OperationRemove,
		audit.BuildTemplateDelete(rec))
	return httpx.Success(c, okResp{OK: true})
}

// handleTemplateLogs returns the build log lines for tplID, fetched
// from ClickHouse. Two modes:
//   - default: dumps every line so far as text (one line per log row),
//     useful as `createos-cli templates logs <id>` after the build finishes.
//   - ?follow=true: keeps the connection open, streams new lines as
//     NDJSON `{"ts":...,"level":...,"line":...}` until the build hits
//     a terminal status, then writes a final `{"final":true,"status":"ready"}`
//     and closes.
//
// Owner check: `lookupUserTemplate` enforces utils.UserID(c) ownership.
func (h *Handler) HandleTemplateLogs(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, types.AuthError{Auth: "invalid api key"})
	}
	rec, err := h.lookupUserTemplate(c.UserContext(), userID, c.Params(middlewares.ParamSandboxID))
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "not found")
	}
	if h.buildlogs == nil {
		return httpx.Error(c, fiber.StatusServiceUnavailable, "build log store not configured")
	}
	tplID := rec.ID

	// `?attempt=N` filters to one specific build attempt; default = 0
	// (all attempts, oldest first). Useful when a build was retried by
	// the janitor and the user wants to compare attempts.
	attempt := uint8(parseUintQuery(c, "attempt", 0))

	if c.QueryBool("follow") {
		return h.streamTemplateLogs(c, tplID, attempt)
	}
	rows, err := h.buildlogs.GetAll(c.UserContext(), tplID, attempt, 100000)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "fetch logs")
	}
	c.Set("Content-Type", "text/plain; charset=utf-8")
	w := c.Response().BodyWriter()
	for _, l := range rows {
		_, _ = io.WriteString(w, l.Line)
		_, _ = io.WriteString(w, "\n")
	}
	return nil
}

// parseUintQuery is a tiny helper for "?attempt=N" parsing.
func parseUintQuery(c *fiber.Ctx, key string, def uint64) uint64 {
	v := c.Query(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(v, 10, 8)
	if err != nil {
		return def
	}
	return n
}

// streamTemplateLogs implements the ?follow=true case. Polls ClickHouse
// every 500 ms for new lines and emits NDJSON. Closes when the
// templates row hits a terminal status.
func (h *Handler) streamTemplateLogs(c *fiber.Ctx, tplID string, attempt uint8) error {
	c.Set("Content-Type", "application/x-ndjson")
	c.Set("X-Accel-Buffering", "no")

	repo := h.repo
	bl := h.buildlogs
	// Propagate the request context so a server-initiated shutdown or
	// upstream cancellation also tears down the ClickHouse polling loop.
	// Wrap with WithCancel so the closure can self-terminate on terminal
	// build status without poisoning the parent.
	parent := c.UserContext()
	ctx, cancel := context.WithCancel(parent)
	c.Response().SetBodyStreamWriter(fasthttp.StreamWriter(func(w *bufio.Writer) {
		defer cancel()
		var since time.Time
		enc := json.NewEncoder(w)
		// Flush returns false when the underlying conn is gone — fasthttp
		// surfaces client disconnect through Flush errors. Detecting it
		// here is what makes "client closed `createos-cli templates logs`"
		// actually stop the ClickHouse poll instead of looping forever.
		flush := func() bool {
			if err := w.Flush(); err != nil {
				return false
			}
			return true
		}

		// First pass: dump history.
		first, err := bl.GetAll(ctx, tplID, attempt, 100000)
		if err == nil {
			for _, l := range first {
				_ = enc.Encode(map[string]any{
					"ts": l.TS.Format(time.RFC3339Nano), "level": l.Level, "line": l.Line, "attempt": l.Attempt,
				})
				if l.TS.After(since) {
					since = l.TS
				}
			}
			if !flush() {
				return
			}
		}

		// Tail loop.
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			// Pick up new lines.
			rows, err := bl.GetAll(ctx, tplID, attempt, 100000)
			if err == nil {
				for _, l := range rows {
					if !l.TS.After(since) {
						continue
					}
					_ = enc.Encode(map[string]any{
						"ts": l.TS.Format(time.RFC3339Nano), "level": l.Level, "line": l.Line, "attempt": l.Attempt,
					})
					since = l.TS
				}
				if !flush() {
					return
				}
			}
			// Check terminal status.
			rec, _ := repo.GetTemplate(ctx, tplID)
			if rec != nil {
				if rec.Status == models.TemplateStatusReady || rec.Status == models.TemplateStatusFailed {
					_ = enc.Encode(map[string]any{
						"final": true, "status": string(rec.Status),
					})
					_ = flush()
					return
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}))
	return nil
}

// handleInternalTemplateLogIngest accepts NDJSON `{"line":"..."}` from
// the build sandbox and persists each line into ClickHouse. Auth: builder
// JWT (sub=:id matches URL).
func (h *Handler) HandleInternalTemplateLogIngest(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	if sub := middlewares.JWTSub(c); sub == "" || sub != id {
		return httpx.Fail(c, fiber.StatusForbidden,
			"jwt sub does not match template id")
	}
	if h.buildlogs == nil {
		// Best-effort: silently drop when no log store. Returning OK so
		// the runner doesn't fail the build over missing logs infra.
		return httpx.Success(c, okResp{OK: true})
	}
	body := c.Body()
	if len(body) == 0 {
		return httpx.Success(c, okResp{OK: true})
	}
	var lines []clickhouse.Line
	for _, raw := range bytes.Split(body, []byte("\n")) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			continue
		}
		var ev templateBuildLogEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			// Allow plain text body as a fallback (each NDJSON line
			// raw-text becomes a {line:...} row).
			ev.Line = string(raw)
		}
		var ts time.Time
		if ev.TS != "" {
			if t, err := time.Parse(time.RFC3339Nano, ev.TS); err == nil {
				ts = t
			}
		}
		lines = append(lines, clickhouse.Line{TS: ts, Level: ev.Level, Line: ev.Line})
	}
	if len(lines) == 0 {
		return httpx.Success(c, okResp{OK: true})
	}
	if err := h.buildlogs.Append(c.UserContext(), id, lines); err != nil {
		log.WithContext(c.UserContext()).Warnf("[buildlogs] append %s: %v", id, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "log ingest failed")
	}
	return httpx.Success(c, okResp{OK: true})
}

// handleInternalTemplatePatch is the build sandbox's terminal-state report.
// Auth: builder-issued JWT (sub=tpl_<id>, aud=control). The handler
// enforces claims.Sub == :id so a leaked JWT can only modify its own row.
func (h *Handler) HandleInternalTemplatePatch(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	// jwt.SubFromContext is set by InternalJWTMiddleware; reject if the
	// JWT's subject doesn't match the URL's :id.
	if sub := middlewares.JWTSub(c); sub == "" || sub != id {
		return httpx.Fail(c, fiber.StatusForbidden,
			"jwt sub does not match template id")
	}
	var req templatePatchReq
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	newStatus := models.TemplateStatus(req.Status)
	if newStatus != models.TemplateStatusReady && newStatus != models.TemplateStatusFailed {
		return httpx.Fail(c, fiber.StatusBadRequest,
			"must be 'ready' or 'failed'")
	}
	if newStatus == models.TemplateStatusReady {
		if req.SHA256 == nil || *req.SHA256 == "" || req.SizeBytes <= 0 {
			return httpx.Fail(c, fiber.StatusBadRequest,
				"ready requires sha256 and size_bytes")
		}
	}
	updated, err := h.repo.CompleteTemplateBuild(c.UserContext(), id, newStatus,
		req.SHA256, req.SizeBytes, req.Ext4SizeBytes)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if updated == "" {
		return httpx.Fail(c, fiber.StatusConflict,
			"template not in 'building' state")
	}
	return httpx.Success(c, okResp{OK: true})
}

// lookupUserTemplate accepts either a tpl_<ulid> or a friendly name.
// Returns nil if not found OR owned by another user.
func (h *Handler) lookupUserTemplate(ctx context.Context, userID, idOrName string) (*models.Template, error) {
	if strings.HasPrefix(idOrName, models.TemplateIDPrefix) {
		rec, err := h.repo.GetTemplate(ctx, idOrName)
		if err != nil {
			return nil, err
		}
		if rec == nil || rec.UserID != userID || rec.DeletedAt != nil {
			return nil, nil
		}
		return rec, nil
	}
	tplID, err := h.repo.GetLatestReadyByName(ctx, userID, idOrName)
	if err != nil {
		return nil, err
	}
	if tplID == "" {
		// Maybe the user is asking for a name that's still pending/failed.
		// Fall back to the most recent matching row regardless of status.
		recs, err := h.repo.ListUserTemplates(ctx, userID, 200)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			if r.Name == idOrName {
				return &r, nil
			}
		}
		return nil, nil
	}
	return h.repo.GetTemplate(ctx, tplID)
}

// resolveSandboxRootfs translates a user-supplied rootfs string into
// the concrete catalog name we forward to the host. For templates the
// returned string is the immutable tpl_id, which both the scheduler and
// the host treat as a regular rootfs name. Empty rootfs and catalog
// names pass through unchanged.
//
// Returns (rootfs, http-status, FieldError). Status 0 means OK.
func (h *Handler) resolveSandboxRootfs(ctx context.Context, userID, rootfs string) (string, int, string) {
	if rootfs == "" {
		return "", 0, ""
	}
	if strings.HasPrefix(rootfs, models.TemplateIDPrefix) {
		rec, err := h.repo.GetTemplate(ctx, rootfs)
		if err != nil {
			return "", fiber.StatusInternalServerError, "lookup failed"
		}
		if rec == nil || rec.DeletedAt != nil {
			return "", fiber.StatusNotFound, "template not found"
		}
		if rec.UserID != userID {
			return "", fiber.StatusForbidden, "template not found"
		}
		if rec.Status != models.TemplateStatusReady {
			return "", fiber.StatusConflict,
				"template is " + string(rec.Status) + ", not ready"
		}
		return rec.ID, 0, ""
	}
	tplID, err := h.repo.GetLatestReadyByName(ctx, userID, rootfs)
	if err != nil {
		return "", fiber.StatusInternalServerError, "lookup failed"
	}
	if tplID != "" {
		return tplID, 0, ""
	}
	return rootfs, 0, ""
}

// templateView projects a TemplateRecord to the response shape.
func templateView(r models.Template, includeDockerfile bool) templateViewJSON {
	v := templateViewJSON{
		ID:            r.ID,
		Name:          r.Name,
		Base:          r.Base,
		Status:        string(r.Status),
		Ext4SizeBytes: r.Ext4SizeBytes,
		CreatedAt:     r.CreatedAt,
		BuiltAt:       r.BuiltAt,
	}
	if includeDockerfile {
		v.Dockerfile = r.Dockerfile
	}
	return v
}

// validTemplateName: 1-63 chars, lowercase alphanum + dash, must start
// with alphanum.
func validTemplateName(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for i, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
		if !ok {
			return false
		}
		if i == 0 && r == '-' {
			return false
		}
	}
	return true
}

// httpDialerForBuilderJWT is a tiny helper that lets the builder
// service-side fall back to PATCHing on its own when the runner couldn't
// reach control. Not used today; placeholder for follow-up.
var _ = errors.New
var _ = http.MethodPatch

func (h *Handler) DbGetTemplate(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	rec, err := h.repo.GetTemplate(c.UserContext(), id)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "template not found")
	}
	return httpx.Success(c, rec)
}

func (h *Handler) DbListHostCachedTemplates(c *fiber.Ctx) error {
	host := c.Query("host", "")
	if host == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "required")
	}
	recs, err := h.repo.ListHostCachedTemplates(c.UserContext(), host)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if recs == nil {
		recs = []models.HostCachedTemplate{}
	}
	return httpx.Success(c, recs)
}

func (h *Handler) DbUpsertHostCachedTemplate(c *fiber.Ctx) error {
	var r proto.ControlUpsertHostCachedTemplateReq
	if err := c.BodyParser(&r); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if r.HostID == "" || r.TplID == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "host_id and tpl_id required")
	}
	if err := h.repo.UpsertHostCachedTemplate(c.UserContext(), r.HostID, r.TplID, r.CachedUntil); err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, okResp{OK: true})
}

func (h *Handler) DbDeleteHostCachedTemplate(c *fiber.Ctx) error {
	host := c.Params(middlewares.ParamHost)
	tpl := c.Params(middlewares.ParamTemplate)
	if err := h.repo.DeleteHostCachedTemplate(c.UserContext(), host, tpl); err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, okResp{OK: true})
}

func (h *Handler) DbHostCachedTemplateActiveCount(c *fiber.Ctx) error {
	host := c.Params(middlewares.ParamHost)
	tpl := c.Params(middlewares.ParamTemplate)
	n, err := h.repo.HostCachedTemplateHasActiveSandbox(c.UserContext(), host, tpl)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, countResp{Count: n})
}
