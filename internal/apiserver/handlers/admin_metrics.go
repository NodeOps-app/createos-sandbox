package handlers

import (
	"context"
	"errors"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/middlewares"
	"github.com/NodeOps-app/createos-sandbox/internal/audit"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx/types"
	"github.com/NodeOps-app/createos-sandbox/models"
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
)

// Explicitly rank recorded user operations, not operational failure or admin
// events. Exec, shell, files, snapshots and checkpoints are not covered by this
// audit surface; do not present their absence as zero usage.
var adminUsageActions = []string{
	string(audit.ActionSandboxCreate), string(audit.ActionSandboxFork),
	string(audit.ActionSandboxPause), string(audit.ActionSandboxResume),
	string(audit.ActionSandboxPatch), string(audit.ActionSandboxResize),
	string(audit.ActionSandboxEgressSet), string(audit.ActionSandboxSSHPubkeyUpdate),
	string(audit.ActionSandboxBandwidthUpdate), string(audit.ActionDiskCreate),
	string(audit.ActionDiskAttach), string(audit.ActionDiskDetach),
	string(audit.ActionNetworkCreate), string(audit.ActionNetworkAttach),
	string(audit.ActionNetworkDetach), string(audit.ActionTemplateSubmit),
}

// Live activity includes deletions; feature rankings retain their existing scope.
var adminActivityActions = append(append([]string(nil), adminUsageActions...),
	string(audit.ActionSandboxDestroy), string(audit.ActionDiskDelete),
	string(audit.ActionNetworkDelete), string(audit.ActionTemplateDelete),
)

type adminMetricsResp struct {
	Sizing       []models.AdminSizingUsage `json:"sizing"`
	Range        string                    `json:"range"`
	Bucket       string                    `json:"bucket"`
	From         time.Time                 `json:"from"`
	To           time.Time                 `json:"to"`
	GeneratedAt  time.Time                 `json:"generated_at"`
	SourceRegion string                    `json:"source_region"`
	models.AdminUsage
}

type adminFeaturesResp struct {
	Range    string                     `json:"range"`
	Bucket   string                     `json:"bucket"`
	From     time.Time                  `json:"from"`
	To       time.Time                  `json:"to"`
	Features []models.AdminFeatureUsage `json:"features"`
}

func (h *Handler) HandleAdminMetrics(c *fiber.Ctx) error {
	c.Set("Cache-Control", "no-store")
	from, to, scope, bucket, err := parseAdminMetricsWindow(c)
	if err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, types.FieldError{"window": err.Error()})
	}
	userID, region, err := parseAdminMetricsFilters(c)
	if err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, types.FieldError{"filters": err.Error()})
	}
	ctx, cancel := context.WithTimeout(c.UserContext(), 5*time.Second)
	defer cancel()
	// Independent aggregates share one deadline. Run them together so Lifetime
	// sizing does not inherit only the time left after the usage query.
	type sizingResult struct {
		rows []models.AdminSizingUsage
		err  error
	}
	sizingDone := make(chan sizingResult, 1)
	go func() {
		rows, err := h.repo.GetAdminSizingUsage(ctx, from, to, bucket, userID, region)
		sizingDone <- sizingResult{rows: rows, err: err}
	}()
	usage, err := h.repo.GetAdminUsage(ctx, from, to, adminUsageActions, bucket, userID, region)
	if err != nil {
		log.WithContext(ctx).WithError(err).Error("[admin-metrics] usage query failed")
		return httpx.Error(c, fiber.StatusInternalServerError, "metrics unavailable")
	}
	sizing := <-sizingDone
	if sizing.err != nil {
		log.WithContext(ctx).WithError(sizing.err).Error("[admin-metrics] sizing query failed")
		return httpx.Error(c, fiber.StatusInternalServerError, "metrics unavailable")
	}
	if userID != "" {
		usage.UserEmail = h.adminUserEmail(ctx, userID)
	}
	return httpx.Success(c, adminMetricsResp{Range: scope, Bucket: bucket, From: from, To: to, GeneratedAt: time.Now().UTC(), SourceRegion: h.region, AdminUsage: usage, Sizing: sizing.rows})
}

func (h *Handler) HandleAdminFeatureMetrics(c *fiber.Ctx) error {
	c.Set("Cache-Control", "no-store")
	from, to, scope, bucket, err := parseAdminMetricsWindow(c)
	if err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, types.FieldError{"window": err.Error()})
	}
	userID, region, err := parseAdminMetricsFilters(c)
	if err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, types.FieldError{"filters": err.Error()})
	}
	ctx, cancel := context.WithTimeout(c.UserContext(), 5*time.Second)
	defer cancel()
	features, err := h.repo.GetAdminFeatureUsage(ctx, from, to, adminUsageActions, bucket, userID, region)
	if err != nil {
		log.WithContext(ctx).WithError(err).Error("[admin-metrics] feature query failed")
		return httpx.Error(c, fiber.StatusInternalServerError, "metrics unavailable")
	}
	return httpx.Success(c, adminFeaturesResp{Range: scope, Bucket: bucket, From: from, To: to, Features: features})
}

// Lifetime is explicitly requested; normal windows retain their 30-day cap.
// Monthly buckets keep lifetime chart payloads small. Lifetime means retained
// rows, not a promise that previously deleted history can be reconstructed.
func parseAdminMetricsWindow(c *fiber.Ctx) (time.Time, time.Time, string, string, error) {
	scope := c.Query(middlewares.QueryRange, "period")
	if scope == "lifetime" {
		if c.Query(middlewares.QueryFrom) != "" || c.Query(middlewares.QueryTo) != "" {
			return time.Time{}, time.Time{}, "", "", errors.New("lifetime cannot be combined with from or to")
		}
		return time.Unix(0, 0).UTC(), time.Now().UTC(), scope, "month", nil
	}
	if scope != "period" {
		return time.Time{}, time.Time{}, "", "", errors.New("range must be period or lifetime")
	}
	from, to, err := parseMetricsWindow(c, 7*24*time.Hour)
	return from, to, scope, "day", err
}

// Filters are bound SQL parameters, never identifiers or fragments of SQL.
func parseAdminMetricsFilters(c *fiber.Ctx) (string, string, error) {
	userID := strings.TrimSpace(c.Query(middlewares.QueryUserID))
	region := strings.TrimSpace(c.Query(middlewares.QueryRegion))
	if len(userID) > 128 || len(region) > 64 {
		return "", "", errors.New("metrics filter is too long")
	}
	return userID, region, nil
}

type adminGroupsResp struct {
	ExcludeInternal bool                     `json:"exclude_internal"`
	Groups          []models.AdminUsageGroup `json:"groups"`
	Limit           int                      `json:"limit"`
	Offset          int                      `json:"offset"`
	HasMore         bool                     `json:"has_more"`
}

func (h *Handler) HandleAdminUserMetrics(c *fiber.Ctx) error {
	return h.handleAdminUsageGroups(c, false)
}

func (h *Handler) HandleAdminRegionMetrics(c *fiber.Ctx) error {
	return h.handleAdminUsageGroups(c, true)
}

func (h *Handler) handleAdminUsageGroups(c *fiber.Ctx, byRegion bool) error {
	c.Set("Cache-Control", "no-store")
	from, to, _, _, err := parseAdminMetricsWindow(c)
	if err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, types.FieldError{"window": err.Error()})
	}
	limit, err := strconv.Atoi(c.Query(middlewares.QueryLimit, "50"))
	if err != nil || limit < 1 || limit > 100 {
		return httpx.Fail(c, fiber.StatusBadRequest, types.FieldError{middlewares.QueryLimit: "must be between 1 and 100"})
	}
	offset, err := strconv.Atoi(c.Query(middlewares.QueryOffset, "0"))
	if err != nil || offset < 0 || offset > 100000 {
		return httpx.Fail(c, fiber.StatusBadRequest, types.FieldError{middlewares.QueryOffset: "must be between 0 and 100000"})
	}
	excludeInternal := false
	if !byRegion {
		switch c.Query(middlewares.QueryExcludeInternal, "false") {
		case "true":
			excludeInternal = true
		case "false":
		default:
			return httpx.Fail(c, fiber.StatusBadRequest, types.FieldError{middlewares.QueryExcludeInternal: "must be true or false"})
		}
	}
	ctx, cancel := context.WithTimeout(c.UserContext(), 5*time.Second)
	defer cancel()
	groups, err := h.repo.GetAdminUsageGroups(ctx, from, to, adminUsageActions, byRegion, excludeInternal, limit+1, offset)
	if err != nil {
		log.WithContext(ctx).WithError(err).Error("[admin-metrics] grouped usage query failed")
		return httpx.Error(c, fiber.StatusInternalServerError, "metrics unavailable")
	}
	more := len(groups) > limit
	if more {
		groups = groups[:limit]
	}
	if !byRegion {
		h.fillAdminUserEmails(ctx, groups)
	}
	return httpx.Success(c, adminGroupsResp{Groups: groups, Limit: limit, Offset: offset, HasMore: more, ExcludeInternal: excludeInternal})
}

type adminActivityResp struct {
	Events      []models.AdminActivity `json:"events"`
	Current     models.AdminLiveCounts `json:"current"`
	GeneratedAt time.Time              `json:"generated_at"`
}

func (h *Handler) HandleAdminActivity(c *fiber.Ctx) error {
	c.Set("Cache-Control", "no-store")
	from, to, err := parseMetricsWindow(c, 24*time.Hour)
	if err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, types.FieldError{"window": err.Error()})
	}
	userID, region, err := parseAdminMetricsFilters(c)
	if err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, types.FieldError{"filters": err.Error()})
	}
	ctx, cancel := context.WithTimeout(c.UserContext(), 4*time.Second)
	defer cancel()
	events, err := h.repo.GetAdminActivity(ctx, from, to, userID, region, adminActivityActions)
	if err != nil {
		log.WithContext(ctx).WithError(err).Error("[admin-metrics] activity query failed")
		return httpx.Error(c, fiber.StatusInternalServerError, "activity unavailable")
	}
	current, err := h.repo.GetAdminLiveCounts(ctx, userID, region)
	if err != nil {
		log.WithContext(ctx).WithError(err).Error("[admin-metrics] live counts query failed")
		return httpx.Error(c, fiber.StatusInternalServerError, "activity unavailable")
	}
	// Resolve each distinct owner once per poll, using the same bounded lookup
	// workers and simple email cache as the Users view.
	users := make([]models.AdminUsageGroup, 0)
	indices := make(map[string]int)
	for _, event := range events {
		if _, found := indices[event.UserID]; !found {
			indices[event.UserID] = len(users)
			users = append(users, models.AdminUsageGroup{ID: event.UserID})
		}
	}
	h.fillAdminUserEmails(ctx, users)
	for i := range events {
		events[i].UserEmail = users[indices[events[i].UserID]].Email
	}
	return httpx.Success(c, adminActivityResp{Events: events, Current: current, GeneratedAt: time.Now().UTC()})
}

const adminEmailCacheLimit = 1024

func (h *Handler) fillAdminUserEmails(ctx context.Context, groups []models.AdminUsageGroup) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	jobs := make(chan int, len(groups))
	for i := range groups {
		jobs <- i
	}
	close(jobs)
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				if ctx.Err() != nil {
					return
				}
				groups[index].Email = h.adminUserEmail(ctx, groups[index].ID)
			}
		}()
	}
	workers.Wait()
}

// Emails are optional display data, cached until the controller restarts.
// Failed lookups are not cached, so a later request can retry. Concurrent cache
// misses may fetch the same user; never hold the map lock during network IO.
func (h *Handler) adminUserEmail(ctx context.Context, userID string) string {
	if h.createos == nil || userID == "" || ctx.Err() != nil {
		return ""
	}
	h.adminEmailMu.RLock()
	email := h.adminEmails[userID]
	h.adminEmailMu.RUnlock()
	if email != "" {
		return email
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	response, err := h.createos.GetCurrentPlan(ctx, userID)
	if err != nil || response.User == nil || response.User.ID != userID {
		return ""
	}
	email = strings.TrimSpace(response.User.Email)
	address, err := mail.ParseAddress(email)
	if err != nil || address.Name != "" || address.Address != email {
		return ""
	}
	h.adminEmailMu.Lock()
	if h.adminEmails == nil {
		h.adminEmails = make(map[string]string)
	}
	// Keep memory bounded; uncached users still receive their fetched email.
	if len(h.adminEmails) < adminEmailCacheLimit {
		h.adminEmails[userID] = email
	}
	h.adminEmailMu.Unlock()
	return email
}
