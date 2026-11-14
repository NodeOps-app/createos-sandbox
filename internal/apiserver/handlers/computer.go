package handlers

import (
	"context"
	"strings"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/middlewares"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
)

var computerOperations = map[string]struct{}{
	"screenshot":      {},
	"screen":          {},
	"cursor":          {},
	"mouse/move":      {},
	"mouse/click":     {},
	"mouse/scroll":    {},
	"mouse/drag":      {},
	"mouse/down":      {},
	"mouse/up":        {},
	"keyboard/type":   {},
	"keyboard/press":  {},
	"keyboard/down":   {},
	"keyboard/up":     {},
	"clipboard":       {},
	"open":            {},
	"launch":          {},
	"windows":         {},
	"windows/current": {},
	"screens":         {},
}

const maxControlScreenshots = 4

func (h *Handler) acquireComputerScreenshot(sandboxID string) bool {
	h.computerOnce.Do(func() {
		h.computerScreenshots = make(map[string]struct{})
		h.computerSlots = make(chan struct{}, maxControlScreenshots)
	})
	h.computerMu.Lock()
	defer h.computerMu.Unlock()
	if _, exists := h.computerScreenshots[sandboxID]; exists {
		return false
	}
	select {
	case h.computerSlots <- struct{}{}:
		h.computerScreenshots[sandboxID] = struct{}{}
		return true
	default:
		return false
	}
}

func (h *Handler) releaseComputerScreenshot(sandboxID string) {
	h.computerMu.Lock()
	if _, exists := h.computerScreenshots[sandboxID]; exists {
		delete(h.computerScreenshots, sandboxID)
		<-h.computerSlots
	}
	h.computerMu.Unlock()
}

// HandleComputer applies the same API-key ownership boundary as exec and
// managed processes, then forwards only a fixed set of desktop operations to
// the sandbox's owning host.
func (h *Handler) HandleComputer(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	record, err := h.repo.GetForExec(c.UserContext(), id)
	if err != nil {
		log.WithContext(c.UserContext()).WithError(err).WithField("sandbox_id", id).Error("[computer] sandbox lookup")
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if record == nil || !runtimeOwnerOK(c, record) {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	if processUnavailableStatus(record.Status) {
		return httpx.Fail(c, fiber.StatusConflict,
			"sandbox is "+string(record.Status)+"; computer API requires a running sandbox")
	}
	marker := "/computer/"
	offset := strings.Index(c.Path(), marker)
	if offset < 0 {
		return httpx.Fail(c, fiber.StatusNotFound, "computer operation not found")
	}
	operation := strings.TrimPrefix(c.Path()[offset:], marker)
	if _, ok := computerOperations[operation]; !ok {
		screenPathOK := validScreenOperation(operation)
		windowPathOK := validWindowOperation(operation)
		if !screenPathOK && !windowPathOK {
			return httpx.Fail(c, fiber.StatusNotFound, "computer operation not found")
		}
	}
	if operation == "screenshot" {
		if !h.acquireComputerScreenshot(id) {
			c.Set(fiber.HeaderRetryAfter, "1")
			return httpx.Fail(c, fiber.StatusTooManyRequests, "screenshot capacity busy")
		}
		defer h.releaseComputerScreenshot(id)
	}
	if strings.HasSuffix(operation, "/connect") {
		if !record.IngressEnabled || h.ingressDomainSuffix == "" {
			return httpx.Fail(c, fiber.StatusConflict, "sandbox ingress must be enabled to connect a screen")
		}
		c.Request().Header.Set(proto.HeaderSandboxIngressURLTemplate, h.ingressURLTemplate(id))
	}
	if record.AutoPauseAfterSeconds != nil {
		bandwidth := record.BandwidthUsedBytes + record.BandwidthIngressBytes
		go h.repo.TouchActivity(context.WithoutCancel(c.UserContext()), strings.Clone(id), bandwidth) //nolint:errcheck
	}
	path := "/v1/sandboxes/" + id + "/computer/" + operation
	return h.forwardBySandboxUsingRec(c, path, record)
}

func validWindowOperation(operation string) bool {
	parts := strings.Split(operation, "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "windows" || !decimalString(parts[1]) {
		return false
	}
	if len(parts) == 2 {
		return true
	}
	switch parts[2] {
	case "focus", "geometry", "move", "resize", "maximize", "minimize", "restore":
		return true
	default:
		return false
	}
}

func validScreenOperation(operation string) bool {
	parts := strings.Split(operation, "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "screens" || !strings.HasPrefix(parts[1], "screen-") {
		return false
	}
	if _, ok := strings.CutPrefix(parts[1], "screen-"); !ok {
		return false
	}
	index := strings.TrimPrefix(parts[1], "screen-")
	if !decimalString(index) {
		return false
	}
	return len(parts) == 2 || parts[2] == "connect" || parts[2] == "resize"
}

func decimalString(value string) bool {
	if value == "" || len(value) > 20 {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
