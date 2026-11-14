package handlers

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/middlewares"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx/types"
	"github.com/NodeOps-app/createos-sandbox/internal/utils"
)

type userMetricsResp struct {
	Current map[string]int    `json:"current"`
	Window  userMetricsWindow `json:"window"`
}

type userMetricsWindow struct {
	From      time.Time            `json:"from"`
	To        time.Time            `json:"to"`
	Spawned   int                  `json:"spawned"`
	Destroyed int                  `json:"destroyed"`
	LifetimeS userMetricsLifetime  `json:"lifetime_seconds"`
	Compute   userMetricsCompute   `json:"compute"`
	Bandwidth userMetricsBandwidth `json:"bandwidth_bytes"`
	ByShape   []userMetricsByShape `json:"by_shape"`
}

type userMetricsLifetime struct {
	Min     float64 `json:"min"`
	P50     float64 `json:"p50"`
	P95     float64 `json:"p95"`
	Average float64 `json:"average"`
}

type userMetricsCompute struct {
	VcpuSeconds    float64 `json:"vcpu_seconds"`
	MemMibSeconds  float64 `json:"mem_mib_seconds"`
	DiskMibSeconds float64 `json:"disk_mib_seconds"`
}

type userMetricsBandwidth struct {
	Egress  int64 `json:"egress"`
	Ingress int64 `json:"ingress"`
}

type userMetricsByShape struct {
	Shape       string  `json:"shape"`
	Count       int     `json:"count"`
	VcpuSeconds float64 `json:"vcpu_seconds"`
}

type userMetricsTimeseriesResp struct {
	From    time.Time           `json:"from"`
	To      time.Time           `json:"to"`
	Bucket  string              `json:"bucket"`
	Buckets []userMetricsBucket `json:"buckets"`
}

type userMetricsBucket struct {
	Ts        time.Time `json:"ts"`
	Spawned   int       `json:"spawned"`
	Destroyed int       `json:"destroyed"`
	Running   int       `json:"running"`
}

// HandleUserMetrics serves aggregate metrics for the caller's user_id
// over [?from, ?to). Defaults to last 24h; window capped at 30 days.
func (h *Handler) HandleUserMetrics(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized,
			types.AuthError{Auth: "invalid api key"})
	}
	from, to, err := parseMetricsWindow(c, 24*time.Hour)
	if err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest,
			types.FieldError{"window": err.Error()})
	}
	ctx := c.UserContext()

	byStatus, err := h.repo.GetUserMetricsByStatus(ctx, userID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[metrics] by-status %s: %v", userID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "metrics unavailable")
	}
	statusMap := make(map[string]int, len(byStatus))
	for _, r := range byStatus {
		statusMap[r.Status] = r.Count
	}

	w, err := h.repo.GetUserMetricsWindow(ctx, userID, from, to)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[metrics] window %s: %v", userID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "metrics unavailable")
	}

	shapes, err := h.repo.GetUserMetricsByShape(ctx, userID, from, to)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[metrics] by-shape %s: %v", userID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "metrics unavailable")
	}
	byShape := make([]userMetricsByShape, 0, len(shapes))
	for _, s := range shapes {
		byShape = append(byShape, userMetricsByShape{
			Shape: s.Shape, Count: s.Count, VcpuSeconds: s.VcpuSeconds,
		})
	}

	return httpx.Success(c, userMetricsResp{
		Current: statusMap,
		Window: userMetricsWindow{
			From:      from,
			To:        to,
			Spawned:   w.Spawned,
			Destroyed: w.Destroyed,
			LifetimeS: userMetricsLifetime{
				Min:     w.LifetimeMin,
				P50:     w.LifetimeP50,
				P95:     w.LifetimeP95,
				Average: w.LifetimeAvg,
			},
			Compute: userMetricsCompute{
				VcpuSeconds:    w.VcpuSeconds,
				MemMibSeconds:  w.MemMibSeconds,
				DiskMibSeconds: w.DiskMibSeconds,
			},
			Bandwidth: userMetricsBandwidth{
				Egress: w.EgressBytes, Ingress: w.IngressBytes,
			},
			ByShape: byShape,
		},
	})
}

// HandleUserMetricsTimeseries serves bucketed counts for charts.
// `bucket` must be "hour" or "day"; window defaults to last 7 days.
func (h *Handler) HandleUserMetricsTimeseries(c *fiber.Ctx) error {
	if isSandboxPrincipal(c) {
		return sandboxPrincipalForbidden(c)
	}
	userID := utils.UserID(c)
	if userID == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized,
			types.AuthError{Auth: "invalid api key"})
	}
	bucketParam := c.Query("bucket", "hour")
	var pgInterval string
	switch bucketParam {
	case "hour":
		pgInterval = "1 hour"
	case "day":
		pgInterval = "1 day"
	default:
		return httpx.Fail(c, fiber.StatusBadRequest,
			types.FieldError{"bucket": "must be 'hour' or 'day'"})
	}
	from, to, err := parseMetricsWindow(c, 7*24*time.Hour)
	if err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest,
			types.FieldError{"window": err.Error()})
	}

	rows, err := h.repo.GetUserMetricsTimeseries(c.UserContext(), userID, from, to, pgInterval)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[metrics] timeseries %s: %v", userID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "metrics unavailable")
	}
	buckets := make([]userMetricsBucket, 0, len(rows))
	for _, b := range rows {
		buckets = append(buckets, userMetricsBucket{
			Ts: b.Ts, Spawned: b.Spawned, Destroyed: b.Destroyed, Running: b.Running,
		})
	}
	return httpx.Success(c, userMetricsTimeseriesResp{
		From: from, To: to, Bucket: bucketParam, Buckets: buckets,
	})
}

// parseMetricsWindow reads ?from / ?to (RFC3339). Defaults to
// [now-defaultLookback, now]; caps the span at 30 days; rejects
// inverted windows.
func parseMetricsWindow(c *fiber.Ctx, defaultLookback time.Duration) (time.Time, time.Time, error) {
	now := time.Now().UTC()
	to := now
	from := now.Add(-defaultLookback)
	if v := c.Query(middlewares.QueryTo); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return time.Time{}, time.Time{}, errors.New("invalid 'to' (want RFC3339)")
		}
		to = t.UTC()
	}
	if v := c.Query(middlewares.QueryFrom); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return time.Time{}, time.Time{}, errors.New("invalid 'from' (want RFC3339)")
		}
		from = t.UTC()
	}
	if !from.Before(to) {
		return time.Time{}, time.Time{}, errors.New("'from' must be before 'to'")
	}
	if to.Sub(from) > 30*24*time.Hour {
		return time.Time{}, time.Time{}, errors.New("window exceeds 30 days")
	}
	return from, to, nil
}
