package handlers

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/apiserver/middlewares"
	"github.com/NodeOps-app/sandbox/internal/httpx"
)

// HandleSandboxMetrics returns on-demand resource usage (memory + CPU)
// for one sandbox. Authentication runs in the middleware chain; this
// handler enforces ownership and then forwards to the owning host's
// /v1/sandboxes/:id/metrics endpoint.
//
// The owner check happens HERE (not just downstream) so a cross-tenant
// probe by sandbox id is rejected before we burn a host RPC.
func (h *Handler) HandleSandboxMetrics(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	rec, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[metrics] sandbox lookup: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil || !runtimeOwnerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	return h.forwardBySandbox(c, "/v1/sandboxes/"+id+"/metrics")
}

// HandleSandboxMetricsTimeseries returns the last hour of samples
// (10s buckets, ~360 points) from the owning host's in-memory ring.
// Same owner-gate as HandleSandboxMetrics.
func (h *Handler) HandleSandboxMetricsTimeseries(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	rec, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[metrics-ts] sandbox lookup: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil || !runtimeOwnerOK(c, rec) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	// `since` = user-owned-since instant. Pool claim bumps sandboxes.created_at
	// to now() so this cleanly filters out pool-warmup ring points.
	return h.forwardBySandbox(c, fmt.Sprintf("/v1/sandboxes/%s/metrics/timeseries?since=%d", id, rec.CreatedAt.Unix()))
}
