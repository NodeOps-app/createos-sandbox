package handlers

import (
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/middlewares"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
)

type operatorHostStatusResp struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type operatorHostDrainResp struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Found  int    `json:"found"`
}

// HandleOperatorCordonHost prevents new placements on a host. The route is
// protected by the narrow admin-token middleware.
func (h *Handler) HandleOperatorCordonHost(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	if id == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "required")
	}
	got, err := h.repo.SetHostSchedulingDisabled(c.UserContext(), id, true)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[operator] cordon host %s: %v", id, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if got == "" {
		return httpx.Fail(c, fiber.StatusNotFound, "host not registered")
	}
	return httpx.Success(c, operatorHostStatusResp{ID: id, Status: "cordoned"})
}

// HandleOperatorUncordonHost makes a host eligible for placement again.
func (h *Handler) HandleOperatorUncordonHost(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	if id == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "required")
	}
	got, err := h.repo.SetHostSchedulingDisabled(c.UserContext(), id, false)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[operator] uncordon host %s: %v", id, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if got == "" {
		return httpx.Fail(c, fiber.StatusNotFound, "host not registered")
	}
	return httpx.Success(c, operatorHostStatusResp{ID: id, Status: "uncordoned"})
}

// HandleOperatorDrainHost disables scheduling and marks the host draining.
// The sweep worker subsequently evacuates its running sandboxes.
func (h *Handler) HandleOperatorDrainHost(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	if id == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "required")
	}
	got, err := h.repo.SetHostDrain(c.UserContext(), id)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[operator] drain host %s: %v", id, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if got == "" {
		return httpx.Fail(c, fiber.StatusNotFound, "host not registered")
	}
	ids, err := h.repo.ListRunningSandboxesOnHost(c.UserContext(), id)
	if err != nil {
		log.WithContext(c.UserContext()).Warnf("[operator] list running sandboxes on draining host %s: %v", id, err)
	}
	return httpx.Success(c, operatorHostDrainResp{ID: id, Status: "draining", Found: len(ids)})
}
