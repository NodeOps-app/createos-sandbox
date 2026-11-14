package api

import (
	"bytes"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"

	"github.com/NodeOps-app/createos-sandbox/internal/hosts/metrics"
	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

func TestHostConnectionErrorsPreserveCauseWithoutRequestSecrets(t *testing.T) {
	var output bytes.Buffer
	oldOutput := log.StandardLogger().Out
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(oldOutput) })
	app := fiber.New()
	defer app.Shutdown()
	var err error = &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
	called := false
	app.Server().ErrorHandler = func(c *fasthttp.RequestCtx, got error) {
		called = true
		if got != err {
			t.Fatalf("original error replaced: %v", got)
		}
		c.SetStatusCode(500)
	}
	logHostConnectionErrors(app)
	var c fasthttp.RequestCtx
	c.Request.Header.Set("Authorization", "Bearer secret-test-token")
	c.Request.SetRequestURI("/?key=secret-test-token")
	c.Request.SetBodyString("secret-test-token")
	app.Server().ErrorHandler(&c, err)
	if !called || c.Response.StatusCode() != 500 {
		t.Fatal("existing error handler was not preserved")
	}
	got := output.String()
	if !strings.Contains(got, "connection reset by peer") || !strings.Contains(got, "network_operation=read") {
		t.Fatalf("missing transport cause: %s", got)
	}
	if strings.Contains(got, "secret-test-token") {
		t.Fatal("request secret leaked into connection log")
	}
	output.Reset()
	err = fmt.Errorf("invalid header: secret-test-token")
	app.Server().ErrorHandler(&c, err)
	if strings.Contains(output.String(), "secret-test-token") {
		t.Fatal("parser error leaked raw request bytes")
	}
}

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
