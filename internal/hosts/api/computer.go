package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/httpx"
	"github.com/NodeOps-app/sandbox/internal/proto"
)

const computerPathMarker = "/computer/"

const (
	maxComputerResponseBytes = 32 << 20
	maxHostScreenshots       = 4
)

func (s *Server) acquireScreenshot(sandboxID string) bool {
	s.computerOnce.Do(func() {
		s.computerScreenshots = make(map[string]struct{})
		s.computerSlots = make(chan struct{}, maxHostScreenshots)
	})
	s.computerMu.Lock()
	defer s.computerMu.Unlock()
	if _, exists := s.computerScreenshots[sandboxID]; exists {
		return false
	}
	select {
	case s.computerSlots <- struct{}{}:
		s.computerScreenshots[sandboxID] = struct{}{}
		return true
	default:
		return false
	}
}

func (s *Server) releaseScreenshot(sandboxID string) {
	s.computerMu.Lock()
	if _, exists := s.computerScreenshots[sandboxID]; exists {
		delete(s.computerScreenshots, sandboxID)
		<-s.computerSlots
	}
	s.computerMu.Unlock()
}

func computerGuestPath(path string) string {
	offset := strings.Index(path, computerPathMarker)
	if offset < 0 {
		return ""
	}
	action := strings.TrimPrefix(path[offset:], "/computer")
	switch action {
	case "/screenshot", "/screen", "/cursor",
		"/mouse/move", "/mouse/click", "/mouse/scroll", "/mouse/drag",
		"/mouse/down", "/mouse/up", "/keyboard/type", "/keyboard/press",
		"/keyboard/down", "/keyboard/up", "/clipboard",
		"/open", "/launch", "/windows", "/windows/current", "/screens":
		return "/v1/computer" + action
	default:
		if validComputerScreenAction(action) {
			return "/v1/computer" + action
		}
		if validComputerWindowAction(action) {
			return "/v1/computer" + action
		}
		windowID := strings.TrimPrefix(action, "/windows/")
		if windowID == "" || len(windowID) > 20 {
			return ""
		}
		for _, r := range windowID {
			if r < '0' || r > '9' {
				return ""
			}
		}
		return "/v1/computer/windows/" + windowID
	}
}

func validComputerWindowAction(action string) bool {
	parts := strings.Split(strings.TrimPrefix(action, "/"), "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "windows" || len(parts[1]) > 20 {
		return false
	}
	for _, r := range parts[1] {
		if r < '0' || r > '9' {
			return false
		}
	}
	if parts[1] == "" || len(parts) == 2 {
		return parts[1] != ""
	}
	switch parts[2] {
	case "focus", "geometry", "move", "resize", "maximize", "minimize", "restore":
		return true
	default:
		return false
	}
}

func validComputerScreenAction(action string) bool {
	parts := strings.Split(strings.TrimPrefix(action, "/"), "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "screens" || !strings.HasPrefix(parts[1], "screen-") {
		return false
	}
	index := strings.TrimPrefix(parts[1], "screen-")
	if index == "" || len(index) > 2 {
		return false
	}
	for _, r := range index {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(parts) == 2 || parts[2] == "connect" || parts[2] == "resize"
}

// handleComputerProxy forwards native desktop operations to the authenticated
// guest service sharing agent port 1028. The service's binary screenshot is
// preserved verbatim; JSON operations receive the platform's JSend envelope.
func (s *Server) handleComputerProxy(c *fiber.Ctx) error {
	target, err := s.processTarget(c)
	if err != nil {
		return writeProcessTargetError(c, err)
	}
	guestPath := computerGuestPath(c.Path())
	if guestPath == "" {
		return httpx.Fail(c, fiber.StatusNotFound, "computer operation not found")
	}
	if guestPath == "/v1/computer/screenshot" {
		sandboxID := c.Params("id")
		if !s.acquireScreenshot(sandboxID) {
			c.Set(fiber.HeaderRetryAfter, "1")
			return httpx.Fail(c, fiber.StatusTooManyRequests, "screenshot capacity busy")
		}
		defer s.releaseScreenshot(sandboxID)
	}
	body := c.Body()
	request, err := http.NewRequestWithContext(
		c.UserContext(), c.Method(),
		processGuestURL(target, guestPath, string(c.Request().URI().QueryString())), bytes.NewReader(body),
	)
	if err != nil {
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if len(body) > 0 {
		request.Header.Set(fiber.HeaderContentType, c.Get(fiber.HeaderContentType))
		request.ContentLength = int64(len(body))
	}
	if template := c.Get(proto.HeaderSandboxIngressURLTemplate); template != "" {
		request.Header.Set(proto.HeaderSandboxIngressURLTemplate, template)
	}
	response, err := processAgentClient(target.token).Do(request)
	if err != nil {
		log.WithContext(c.UserContext()).WithError(err).WithField("sandbox_id", c.Params("id")).Error("[computer.agent] upstream error")
		return httpx.Error(c, fiber.StatusBadGateway, "computer agent unavailable")
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxComputerResponseBytes+1))
	if err != nil {
		return httpx.Error(c, fiber.StatusBadGateway, "computer agent response failed")
	}
	if len(responseBody) > maxComputerResponseBytes {
		log.WithContext(c.UserContext()).WithFields(log.Fields{"status": response.StatusCode, "bytes": len(responseBody)}).
			Error("[computer.agent] response exceeds limit")
		return httpx.Error(c, fiber.StatusBadGateway, "computer agent response too large")
	}
	if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices &&
		strings.HasPrefix(response.Header.Get("Content-Type"), "image/png") {
		c.Set(fiber.HeaderContentType, "image/png")
		c.Set(fiber.HeaderCacheControl, "no-store")
		return c.Status(response.StatusCode).Send(responseBody)
	}
	if !json.Valid(responseBody) {
		log.WithContext(c.UserContext()).WithFields(log.Fields{"status": response.StatusCode, "bytes": len(responseBody)}).
			Error("[computer.agent] invalid JSON response")
		return httpx.Error(c, fiber.StatusBadGateway, "computer agent response failed")
	}
	if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
		return httpx.Success(c, json.RawMessage(responseBody))
	}
	if response.StatusCode >= http.StatusInternalServerError {
		return httpx.Error(c, response.StatusCode, "computer operation failed")
	}
	return httpx.Fail(c, response.StatusCode, json.RawMessage(responseBody))
}
