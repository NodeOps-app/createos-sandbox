package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
)

// handleCheckpointProxy shares the existing authenticated exec connection.
// Public exec bodies are not passed through: only this owner-authorized route
// constructs the CHECKPOINT wire prefix. No account API key reaches the guest.
func (s *Server) handleCheckpointProxy(c *fiber.Ctx) error {
	target, err := s.processTarget(c)
	if err != nil {
		return writeProcessTargetError(c, err)
	}
	req, err := checkpointRequest(c)
	if err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, err.Error())
	}
	ctx, cancel := context.WithTimeout(c.UserContext(), time.Minute)
	defer cancel()
	reply, err := checkpointAgentCall(ctx, target, req)
	if err != nil {
		log.WithContext(ctx).WithError(err).WithField("sandbox_id", c.Params("id")).Error("[checkpoint.agent] request failed")
		return httpx.Error(c, http.StatusBadGateway, "checkpoint agent unavailable")
	}
	return writeCheckpointAgentResponse(c, reply)
}

// checkpointRequest validates the host trust boundary without writing a Fiber
// response. A parsing error explicitly stops the caller before any guest RPC.
func checkpointRequest(c *fiber.Ctx) (proto.CheckpointAgentRequest, error) {
	if len(c.Request().URI().QueryString()) != 0 || len(c.Body()) > 16<<10 {
		return proto.CheckpointAgentRequest{}, errors.New("invalid checkpoint request")
	}
	req := proto.CheckpointAgentRequest{ID: c.Params(proto.CheckpointIDParam)}
	if req.ID != "" && proto.ValidateCheckpointID(req.ID) != nil {
		return proto.CheckpointAgentRequest{}, errors.New("invalid checkpoint id")
	}
	switch {
	case c.Method() == http.MethodGet && req.ID == "":
		req.Action = proto.CheckpointActionList
	case c.Method() == http.MethodDelete && req.ID != "":
		req.Action = proto.CheckpointActionDelete
	case c.Method() == http.MethodPost && req.ID != "" && strings.HasSuffix(c.Path(), "/restore"):
		req.Action = proto.CheckpointActionRestore
	case c.Method() == http.MethodPost && req.ID == "":
		req.Action = proto.CheckpointActionCreate
		dec := json.NewDecoder(bytes.NewReader(c.Body()))
		dec.DisallowUnknownFields()
		if dec.Decode(&req.Create) != nil || req.Create == nil {
			return proto.CheckpointAgentRequest{}, errors.New("invalid checkpoint request")
		}
		var extra any
		if dec.Decode(&extra) != io.EOF {
			return proto.CheckpointAgentRequest{}, errors.New("invalid checkpoint request")
		}
	default:
		return proto.CheckpointAgentRequest{}, errors.New("invalid checkpoint operation")
	}
	if req.Action != proto.CheckpointActionCreate && len(bytes.TrimSpace(c.Body())) != 0 {
		return proto.CheckpointAgentRequest{}, errors.New("request body is not supported")
	}
	return req, nil
}

func writeCheckpointAgentResponse(c *fiber.Ctx, reply proto.CheckpointAgentResponse) error {
	switch reply.Status {
	case http.StatusOK:
		if !json.Valid(reply.Data) {
			return httpx.Error(c, http.StatusBadGateway, "checkpoint agent response failed")
		}
		return httpx.Success(c, reply.Data)
	case http.StatusBadRequest, http.StatusNotFound, http.StatusConflict:
		return httpx.Fail(c, reply.Status, reply.Error)
	case http.StatusInsufficientStorage:
		return httpx.Error(c, http.StatusInsufficientStorage, "not enough sandbox disk space")
	case http.StatusInternalServerError:
		return httpx.Error(c, http.StatusInternalServerError, "checkpoint operation could not complete")
	default:
		return httpx.Error(c, http.StatusBadGateway, "checkpoint agent response failed")
	}
}

func checkpointAgentCall(ctx context.Context, target processAgentTarget, req proto.CheckpointAgentRequest) (proto.CheckpointAgentResponse, error) {
	var reply proto.CheckpointAgentResponse
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.ip, "1024"))
	if err != nil {
		return reply, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err = proto.WriteAuthLine(conn, target.token); err != nil {
		return reply, err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return reply, err
	}
	if _, err = io.WriteString(conn, proto.CheckpointRequestPrefix+string(body)+"\n"); err != nil {
		return reply, err
	}
	body, err = readGuestResponse(conn)
	if err != nil {
		return reply, err
	}
	err = json.Unmarshal(body, &reply)
	return reply, err
}
