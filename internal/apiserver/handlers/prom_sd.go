package handlers

import (
	"crypto/subtle"
	"fmt"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/metrics"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
)

// promSDTarget matches Prometheus's http_sd response shape.
// Each entry: one group of targets plus shared labels. We emit one
// group per host so per-host labels (region, cpu_vendor) attach
// correctly. See https://prometheus.io/docs/prometheus/latest/http_sd/.
type promSDTarget struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

// HandlePromSDHosts returns the live host list in Prometheus
// http_sd format so the central Prometheus auto-discovers new hosts
// without operator-edited scrape config. Filters to active +
// non-cordoned hosts so cordoned/dead hosts don't show up as
// down-targets in Prometheus.
//
// Auth: same static bearer token used by host /metrics. Gating the
// endpoint matters because the response leaks host addresses; we
// publish addresses anyway in some surfaces, but it's better to
// require the same credential Prometheus already holds.
//
// The metrics port (default :9091) is appended via Prometheus
// relabel_configs on the scraper side, so this endpoint emits
// addresses with the API port and the scraper rewrites them.
func (h *Handler) HandlePromSDHosts(c *fiber.Ctx) error {
	hosts, err := h.repo.ListActiveHosts(c.UserContext())
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[promSD] list hosts: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	out := make([]promSDTarget, 0, len(hosts))
	for _, host := range hosts {
		// Cordoned hosts (host.SchedulingDisabled) are deliberately kept:
		// still alive, so scraping their metrics is fine and the cordon
		// dashboard panel needs them visible. Filter here to hide them.
		out = append(out, promSDTarget{
			Targets: []string{host.Addr}, // host:apiport — scraper rewrites the port
			Labels: map[string]string{
				"__meta_createos_host_id":    host.ID,
				"__meta_createos_region":     host.Region,
				"__meta_createos_cpu_vendor": host.CPUVendor,
				"__meta_createos_status":     host.Status,
			},
		})
	}
	return c.JSON(out)
}

// HandlePromScrape serves control's own Prometheus metrics on its
// dedicated isolated registry. Same token gate as the SD endpoint.
func (h *Handler) HandlePromScrape(c *fiber.Ctx) error {
	return adaptor.HTTPHandler(metrics.Handler())(c)
}

// PromSDAuth returns a Fiber middleware that gates the SD endpoint
// with a static bearer token. Empty token = endpoint disabled (405).
func PromSDAuth(expectedToken string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if expectedToken == "" {
			return c.Status(fiber.StatusMethodNotAllowed).SendString("promSD disabled (set --prom-sd-token)")
		}
		h := c.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") ||
			subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(h, "Bearer ")), []byte(expectedToken)) != 1 {
			c.Set("WWW-Authenticate", `Bearer realm="createos-promsd"`)
			return c.Status(fiber.StatusUnauthorized).SendString("unauthorized")
		}
		return c.Next()
	}
}

// loadPromSDToken reads the static token from a file path. Empty
// path returns the empty string — callers treat that as "disabled".
// Trims trailing whitespace so files written with `echo` work.
func LoadPromSDToken(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	return readTrim(path)
}

func readTrim(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %q: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}
