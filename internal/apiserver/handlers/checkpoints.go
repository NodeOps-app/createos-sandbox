package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/middlewares"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/internal/utils"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// HandleCheckpoints accepts account owners and delegated credentials scoped to
// this sandbox. The principal stays sandbox-scoped across regional forwarding.
func (h *Handler) HandleCheckpoints(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	if sandboxID := utils.SandboxPrincipalIDFromContext(c.UserContext()); sandboxID != "" {
		if sandboxID != id {
			return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		}
	} else if utils.UserIDFromContext(c.UserContext()) == "" {
		return httpx.Fail(c, fiber.StatusUnauthorized, "invalid api key")
	}
	record, err := h.repo.GetForExec(c.UserContext(), id)
	if err != nil {
		log.WithContext(c.UserContext()).WithError(err).WithField("sandbox_id", id).Error("[checkpoint] sandbox lookup")
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return h.handleCheckpointForSandbox(c, record)
}

func (h *Handler) handleCheckpointForSandbox(c *fiber.Ctx, record *models.Sandbox) error {
	if record == nil || !runtimeOwnerOK(c, record) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	// Resolve state in the owning region, as for VM snapshots. Ownership is
	// checked before forwarding; credentials never authorize another user's row.
	if record.Region != "" && record.Region != h.region {
		return h.forwardToPeerControl(c, record.Region, c.Method(), c.Path())
	}
	if record.Status != models.StatusRunning {
		return httpx.Fail(c, fiber.StatusConflict, "sandbox must be running to manage directory checkpoints")
	}
	if len(c.Request().URI().QueryString()) != 0 {
		return httpx.Fail(c, fiber.StatusBadRequest, "checkpoint operations do not accept query parameters")
	}
	checkpointID := c.Params(middlewares.ParamCheckpointID)
	if checkpointID != "" && proto.ValidateCheckpointID(checkpointID) != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid checkpoint id")
	}
	if c.Method() == fiber.MethodPost && checkpointID == "" {
		if _, err := parseCheckpointCreate(c.Body()); err != nil {
			return httpx.Fail(c, fiber.StatusBadRequest, err.Error())
		}
	} else if len(bytes.TrimSpace(c.Body())) != 0 {
		return httpx.Fail(c, fiber.StatusBadRequest, "this checkpoint operation does not accept a request body")
	}

	if record.AutoPauseAfterSeconds != nil {
		go h.repo.TouchActivity(context.WithoutCancel(c.UserContext()), strings.Clone(record.ID), record.BandwidthUsedBytes+record.BandwidthIngressBytes) //nolint:errcheck
	}
	path := "/v1/sandboxes/" + record.ID + "/checkpoints"
	if checkpointID != "" {
		path += "/" + checkpointID
		if c.Method() == fiber.MethodPost {
			path += "/restore"
		}
	}
	return h.forwardBySandboxUsingRec(c, path, record)
}

func parseCheckpointCreate(body []byte) (*proto.CheckpointCreateReq, error) {
	var req *proto.CheckpointCreateReq
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if len(body) > 16<<10 || dec.Decode(&req) != nil || req == nil {
		return nil, errors.New("expected a JSON object containing only path and name")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, errors.New("expected a single JSON object")
	}
	if !path.IsAbs(req.Path) || len(req.Path) > 4096 || strings.IndexByte(req.Path, 0) >= 0 {
		return nil, errors.New("path must be an absolute directory path")
	}
	// Filesystem/symlink/mount checks belong in the agent, inside the sandbox.
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if err := proto.ValidateCheckpointName(&name); err != nil {
			return nil, err
		}
		if name == "" {
			req.Name = nil
		} else {
			req.Name = &name
		}
	}
	return req, nil
}
