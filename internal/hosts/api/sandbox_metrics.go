package api

import (
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/NodeOps-app/createos-sandbox/internal/hosts/metrics"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
)

// handleSandboxMetrics returns the on-demand resource snapshot for one
// sandbox by reading its cgroup files directly. Auth (mTLS role=control)
// is enforced by the route registration; ownership is enforced upstream
// by the control plane before forwarding.
//
// Returns 404 when the sandbox's cgroup is absent — either the VM isn't
// on this host (control's forwarder picked the wrong host, or it was
// destroyed between the lookup and this call) or the host is running on
// cgroup v1 (no /sys/fs/cgroup/createos at all).
func (s *Server) handleSandboxMetrics(c *fiber.Ctx) error {
	id := c.Params("id")
	snap, err := metrics.ReadSandboxSnapshot(id)
	if err != nil {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox metrics unavailable")
	}
	return httpx.Success(c, snap)
}

// handleSandboxMetricsTimeseries returns the 1-hour ring buffer of
// samples for one sandbox. Same auth model as handleSandboxMetrics
// (mTLS role=control on the route; ownership enforced upstream).
//
// Response shape: {points: [...MetricPoint]} — chronological, oldest
// first. Empty array = VM is younger than one scraper tick or the
// scraper hasn't started. The client renders straight from this
// (no downsampling required at 10s buckets over 1h).
func (s *Server) handleSandboxMetricsTimeseries(c *fiber.Ctx) error {
	id := c.Params("id")
	pts := metrics.SandboxTimeseries(id)
	// ?since=<unix> — filter pool-warmup points; control passes the
	// sandbox's created_at (bumped to now() on pool claim).
	if since := c.QueryInt("since", 0); since > 0 {
		cut := time.Unix(int64(since), 0)
		kept := pts[:0]
		for _, p := range pts {
			if !p.Ts.Before(cut) {
				kept = append(kept, p)
			}
		}
		pts = kept
	}
	return httpx.Success(c, sandboxTimeseriesView{
		SandboxID:     id,
		StepSeconds:   int(metrics.RingBucketInterval.Seconds()),
		WindowSeconds: int(metrics.RingWindow.Seconds()),
		Points:        pts,
	})
}

type sandboxTimeseriesView struct {
	SandboxID     string                `json:"sandbox_id"`
	StepSeconds   int                   `json:"step_seconds"`
	WindowSeconds int                   `json:"window_seconds"`
	Points        []metrics.MetricPoint `json:"points"`
}
