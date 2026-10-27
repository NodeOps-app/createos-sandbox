package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/apiserver/middlewares"
	"github.com/NodeOps-app/sandbox/internal/httpx"
	"github.com/NodeOps-app/sandbox/internal/proto"
	"github.com/NodeOps-app/sandbox/models"
)

// HandleProcesses forwards every buffered managed-process operation to the
// sandbox's owning host. The host preserves the guest agent's status and JSON
// response, so process-specific errors pass through without translation.
func (h *Handler) HandleProcesses(c *fiber.Ctx) error {
	record, path, err := h.authorizeProcessRequest(c)
	if err != nil {
		return err
	}
	if strings.HasSuffix(path, "/wait") {
		client := cloneHTTPClientWithoutTimeout(h.http)
		return h.forwardBySandboxUsingRecWithClient(c, path, record, client)
	}
	return h.forwardBySandboxUsingRec(c, path, record)
}

// HandleProcessConnect uses the streaming relay. Buffering this endpoint would
// prevent interactive PTYs and long-running pipe processes from delivering
// output until they exit.
func (h *Handler) HandleProcessConnect(c *fiber.Ctx) error {
	record, path, err := h.authorizeProcessRequest(c)
	if err != nil {
		return err
	}
	return h.forwardStreamBySandboxUsingRec(c, path, record)
}

func (h *Handler) authorizeProcessRequest(c *fiber.Ctx) (*models.Sandbox, string, error) {
	id := c.Params(middlewares.ParamSandboxID)
	record, err := h.repo.GetForExec(c.UserContext(), id)
	if err != nil {
		log.WithContext(c.UserContext()).WithError(err).WithField("sandbox_id", id).Error("[process] sandbox lookup")
		return nil, "", httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if record == nil || !runtimeOwnerOK(c, record) {
		return nil, "", httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if processUnavailableStatus(record.Status) {
		return nil, "", httpx.Fail(c, fiber.StatusConflict,
			"sandbox is "+string(record.Status)+"; process API requires a running sandbox")
	}
	if record.AutoPauseAfterSeconds != nil {
		bandwidth := record.BandwidthUsedBytes + record.BandwidthIngressBytes
		go h.repo.TouchActivity(context.WithoutCancel(c.UserContext()), strings.Clone(id), bandwidth) //nolint:errcheck
	}

	// The public and host APIs deliberately have the same path. Rebuild it
	// from validated route parameters instead of forwarding arbitrary URL text.
	path := "/v1/sandboxes/" + id + "/processes"
	if processID := c.Params(middlewares.ParamProcessID); processID != "" {
		if err := proto.ValidateManagedProcessID(processID); err != nil {
			return nil, "", httpx.Fail(c, fiber.StatusBadRequest, "invalid process id")
		}
		path += "/" + processID
		switch {
		case strings.HasSuffix(c.Path(), "/connect"):
			path += "/connect"
		case strings.HasSuffix(c.Path(), "/input"):
			path += "/input"
		case strings.HasSuffix(c.Path(), "/stdin/close"):
			path += "/stdin/close"
		case strings.HasSuffix(c.Path(), "/resize"):
			path += "/resize"
		case strings.HasSuffix(c.Path(), "/signal"):
			path += "/signal"
		case strings.HasSuffix(c.Path(), "/wait"):
			path += "/wait"
		}
	}
	return record, path, nil
}

func processUnavailableStatus(status models.Status) bool {
	return status != models.StatusRunning
}

func cloneHTTPClientWithoutTimeout(client *http.Client) *http.Client {
	clone := *client
	clone.Timeout = 0
	return &clone
}
