package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"

	"github.com/NodeOps-app/sandbox/internal/httpx"
	"github.com/NodeOps-app/sandbox/internal/proto"
	"github.com/NodeOps-app/sandbox/internal/utils"
)

const agentProcessPort = 1028

type processCreateReq struct {
	Cmd  string             `json:"cmd"`
	Args []string           `json:"args,omitempty"`
	Cwd  string             `json:"cwd,omitempty"`
	Env  map[string]string  `json:"env,omitempty"`
	PTY  *processPTYOptions `json:"pty,omitempty"`
}

type processPTYOptions struct {
	Cols uint16 `json:"cols,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
}

type processAgentTarget struct {
	ip    string
	token string
}

// processAgentClient authenticates every new guest connection with the same
// AUTH preface used by exec, files, tunnel, and the legacy PTY service. The
// HTTP request begins immediately after that line.
func processAgentClient(token string) *http.Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 15 * time.Second}
			connection, err := dialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			if err := proto.WriteAuthLine(connection, token); err != nil {
				_ = connection.Close()
				return nil, fmt.Errorf("write auth line: %w", err)
			}
			return connection, nil
		},
		DisableKeepAlives: true,
	}
	// Managed processes may outlive an ordinary request. Wait and connect own
	// their lifetime through request cancellation and therefore must not inherit
	// a client-wide deadline.
	return &http.Client{Transport: transport}
}

func (s *Server) processTarget(c *fiber.Ctx) (processAgentTarget, error) {
	id := c.Params("id")
	view, err := s.Svc.Get(c.UserContext(), id, utils.UserID(c))
	if err != nil {
		return processAgentTarget{}, err
	}
	if view.IP == nil || *view.IP == "" {
		return processAgentTarget{}, errors.New("sandbox has no ip")
	}
	token, err := s.Svc.SecretToken(c.UserContext(), id)
	if err != nil {
		return processAgentTarget{}, err
	}
	return processAgentTarget{ip: *view.IP, token: token}, nil
}

func processGuestPath(c *fiber.Ctx) string {
	path := "/v1/processes"
	if processID := c.Params("process"); processID != "" {
		// Control validates this too; repeat at the trust boundary so a future
		// internal caller cannot inject separators into the guest URL.
		if proto.ValidateManagedProcessID(processID) != nil {
			return ""
		}
		path += "/" + url.PathEscape(processID)
		requestPath := c.Path()
		marker := "/processes/" + processID
		if offset := strings.Index(requestPath, marker); offset >= 0 {
			tail := strings.TrimPrefix(requestPath[offset+len(marker):], "/")
			if tail != "" {
				path += "/" + tail
			}
		}
	}
	return path
}

func processGuestURL(target processAgentTarget, path, query string) string {
	u := url.URL{
		Scheme:   "http",
		Host:     net.JoinHostPort(target.ip, strconv.Itoa(agentProcessPort)),
		Path:     path,
		RawQuery: query,
	}
	return u.String()
}

func (s *Server) handleProcessProxy(c *fiber.Ctx) error {
	target, err := s.processTarget(c)
	if err != nil {
		return writeProcessTargetError(c, err)
	}

	guestPath := processGuestPath(c)
	if guestPath == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid process id")
	}
	body := c.Body()
	if c.Method() == http.MethodPost && guestPath == "/v1/processes" {
		var createReq processCreateReq
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&createReq); err != nil {
			return writeProcessRequestError(c, "invalid_request")
		}
		var trailing json.RawMessage
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return writeProcessRequestError(c, "invalid_request")
		}
		mergedEnv, err := s.Svc.MergeProcessEnv(
			c.UserContext(), c.Params("id"), utils.UserID(c), createReq.Env,
		)
		if err != nil {
			if errors.Is(err, ErrInvalidRequest) {
				return httpx.Fail(c, fiber.StatusBadRequest, err.Error())
			}
			return writeProcessTargetError(c, err)
		}
		createReq.Env = mergedEnv
		body, err = json.Marshal(createReq)
		if err != nil {
			return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
		}
	}
	request, err := http.NewRequestWithContext(
		c.UserContext(),
		c.Method(),
		processGuestURL(target, guestPath, string(c.Request().URI().QueryString())),
		bytes.NewReader(body),
	)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if len(body) > 0 {
		request.Header.Set(fiber.HeaderContentType, c.Get(fiber.HeaderContentType))
		request.ContentLength = int64(len(body))
	}

	response, err := processAgentClient(target.token).Do(request)
	if err != nil {
		log.WithContext(c.UserContext()).WithError(err).WithField("sandbox_id", c.Params("id")).Error("[process.agent] upstream error")
		return httpx.Error(c, fiber.StatusBadGateway, "process agent unavailable")
	}
	defer response.Body.Close()
	body, err = readGuestResponse(response.Body)
	if err != nil {
		return httpx.Error(c, fiber.StatusBadGateway, "process agent response failed")
	}
	copyProcessResponseHeaders(c, response)
	return writeProcessAgentResponse(c, response.StatusCode, body)
}

func writeProcessRequestError(c *fiber.Ctx, code string) error {
	return httpx.Fail(c, fiber.StatusBadRequest, code)
}

func writeProcessAgentResponse(c *fiber.Ctx, status int, body []byte) error {
	if status >= http.StatusOK && status < http.StatusMultipleChoices {
		if len(body) == 0 {
			return httpx.Success(c, struct{}{})
		}
		if !json.Valid(body) {
			log.WithContext(c.UserContext()).WithFields(log.Fields{"status": status, "bytes": len(body)}).
				Error("[process.agent] invalid success JSON")
			return httpx.Error(c, fiber.StatusBadGateway, "process agent response failed")
		}
		return httpx.Success(c, json.RawMessage(body))
	}

	if !json.Valid(body) {
		log.WithContext(c.UserContext()).WithFields(log.Fields{"status": status, "bytes": len(body)}).
			Error("[process.agent] invalid error JSON")
		if status >= http.StatusInternalServerError {
			return httpx.Error(c, status, "process operation failed")
		}
		return httpx.Fail(c, status, "process request failed")
	}
	if status >= http.StatusInternalServerError {
		log.WithContext(c.UserContext()).WithFields(log.Fields{"status": status, "bytes": len(body)}).
			Error("[process.agent] operation failed")
		return httpx.Error(c, status, "process operation failed")
	}
	// Preserve structured client-error metadata such as the replay journal's
	// oldest_available_seq while placing it under JSend's data field.
	return httpx.Fail(c, status, json.RawMessage(body))
}

func (s *Server) handleProcessConnect(c *fiber.Ctx) error {
	target, err := s.processTarget(c)
	if err != nil {
		return writeProcessTargetError(c, err)
	}

	// Fiber recycles its request context after the handler returns. The stream
	// owns the upstream connection and closes it when copying finishes or the
	// downstream writer fails.
	guestPath := processGuestPath(c)
	if guestPath == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid process id")
	}
	request, err := http.NewRequestWithContext(
		context.WithoutCancel(c.UserContext()),
		http.MethodGet,
		processGuestURL(target, guestPath, string(c.Request().URI().QueryString())),
		nil,
	)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	response, err := processAgentClient(target.token).Do(request)
	if err != nil {
		log.WithContext(c.UserContext()).WithError(err).WithField("sandbox_id", c.Params("id")).Error("[process.connect] upstream error")
		return httpx.Error(c, fiber.StatusBadGateway, "process agent unavailable")
	}
	if response.StatusCode != http.StatusOK {
		defer response.Body.Close()
		body, readErr := readGuestResponse(response.Body)
		if readErr != nil {
			return httpx.Error(c, fiber.StatusBadGateway, "process agent response failed")
		}
		return writeProcessAgentResponse(c, response.StatusCode, body)
	}

	copyProcessResponseHeaders(c, response)
	c.Status(response.StatusCode)
	c.Response().SetBodyStreamWriter(fasthttp.StreamWriter(func(writer *bufio.Writer) {
		defer response.Body.Close()
		buffer := make([]byte, 32<<10)
		for {
			count, readErr := response.Body.Read(buffer)
			if count > 0 {
				if _, writeErr := writer.Write(buffer[:count]); writeErr != nil {
					return
				}
				if flushErr := writer.Flush(); flushErr != nil {
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}))
	return nil
}

func writeProcessTargetError(c *fiber.Ctx, err error) error {
	if errors.Is(err, ErrNotFound) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if err.Error() == "sandbox has no ip" {
		return httpx.Error(c, fiber.StatusServiceUnavailable, "sandbox has no ip")
	}
	log.WithContext(c.UserContext()).WithError(err).Error("[process.agent] resolve sandbox")
	return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
}

func copyProcessResponseHeaders(c *fiber.Ctx, response *http.Response) {
	for _, header := range []string{
		fiber.HeaderContentType,
		fiber.HeaderCacheControl,
		"X-Accel-Buffering",
	} {
		if value := response.Header.Get(header); value != "" {
			c.Set(header, value)
		}
	}
}
