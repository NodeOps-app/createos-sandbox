package middlewares

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NodeOps-app/sandbox/internal/hosts/metrics"
	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
)

func TestInternalMetricsUseRouteTemplates(t *testing.T) {
	app := fiber.New()
	group := app.Group("/internal", InstrumentInternalRPC("route-security-test"))
	group.Get("/sandboxes/:id", func(c *fiber.Ctx) error { return c.SendStatus(401) })
	for i := 0; i < 1000; i++ {
		for _, path := range []string{fmt.Sprintf("/internal/unknown-%d", i), fmt.Sprintf("/internal/sandboxes/id-%d", i)} {
			resp, err := app.Test(httptest.NewRequest("GET", path, nil))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		}
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics.InternalRPC, metrics.InternalRPCSeconds)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		count := 0
		for _, metric := range family.Metric {
			ours := false
			for _, label := range metric.Label {
				if label.GetName() == "service" && label.GetValue() == "route-security-test" {
					ours = true
				}
			}
			if !ours {
				continue
			}
			count++
			for _, label := range metric.Label {
				if strings.Contains(label.GetValue(), "unknown-") || strings.Contains(label.GetValue(), "id-") {
					t.Fatalf("raw URL leaked into metric: %v", label)
				}
			}
		}
		if count == 0 || count > 3 {
			t.Fatalf("%s: got %d series", family.GetName(), count)
		}
	}
}
