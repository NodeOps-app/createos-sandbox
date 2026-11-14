package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	fiberlogger "github.com/gofiber/fiber/v2/middleware/logger"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/requestctx"
	"github.com/NodeOps-app/createos-sandbox/internal/utils"
)

func jsonLine(t *testing.T, fn func(l *log.Logger)) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	l := log.New()
	l.SetOutput(&buf)
	l.SetFormatter(&log.JSONFormatter{})
	l.AddHook(ContextHook{})
	fn(l)
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("not JSON: %q: %v", buf.String(), err)
	}
	return out
}

func requestCtx() context.Context {
	ctx := requestctx.WithRequestID(context.Background(), "req-1")
	ctx = utils.WithUserID(ctx, "user-1")
	return requestctx.WithSandboxID(ctx, "sb-abc")
}

func TestHookAddsCorrelationFields(t *testing.T) {
	got := jsonLine(t, func(l *log.Logger) { l.WithContext(requestCtx()).Info("hello") })
	for k, want := range map[string]string{"request_id": "req-1", "user_id": "user-1", "sandbox_id": "sb-abc", "msg": "hello"} {
		if got[k] != want {
			t.Errorf("%s = %v, want %q", k, got[k], want)
		}
	}
}

func TestHookSurvivesDetachedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(requestCtx())
	cancel()
	got := jsonLine(t, func(l *log.Logger) { l.WithContext(context.WithoutCancel(ctx)).Info("bg") })
	if got["request_id"] != "req-1" || got["user_id"] != "user-1" {
		t.Errorf("detached context lost fields: %v", got)
	}
}

func TestHookKeepsCallerFields(t *testing.T) {
	got := jsonLine(t, func(l *log.Logger) {
		l.WithContext(requestCtx()).WithField("sandbox_id", "sb-explicit").Info("x")
	})
	if got["sandbox_id"] != "sb-explicit" {
		t.Errorf("sandbox_id = %v, want caller value", got["sandbox_id"])
	}
}

func TestHookWithoutContext(t *testing.T) {
	got := jsonLine(t, func(l *log.Logger) { l.Info("plain") })
	for _, k := range []string{"request_id", "user_id", "sandbox_id"} {
		if _, ok := got[k]; ok {
			t.Errorf("unexpected %s on context-free line", k)
		}
	}
}

func TestHookAddsComponentWithoutContext(t *testing.T) {
	var buf bytes.Buffer
	l := log.New()
	l.SetOutput(&buf)
	l.SetFormatter(&log.JSONFormatter{})
	l.AddHook(ContextHook{Component: "host"})
	l.Info("started")

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %q: %v", buf.String(), err)
	}
	if got["component"] != "host" {
		t.Errorf("component = %v, want host", got["component"])
	}
}

func TestHookKeepsCallerComponent(t *testing.T) {
	var buf bytes.Buffer
	l := log.New()
	l.SetOutput(&buf)
	l.SetFormatter(&log.JSONFormatter{})
	l.AddHook(ContextHook{Component: "host"})
	l.WithField("component", "crl").Info("refreshed")

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %q: %v", buf.String(), err)
	}
	if got["component"] != "crl" {
		t.Errorf("component = %v, want caller component crl", got["component"])
	}
}

func TestAccessLogFormat(t *testing.T) {
	jsonMode = false
	if AccessLogFormat() != textAccessLog {
		t.Fatal("text mode must keep the historical access log format")
	}
	jsonMode = true
	defer func() { jsonMode = false }()
	if AccessLogFormat() != jsonAccessLog {
		t.Fatal("json mode must use the JSON access log format")
	}
}

func TestJSONAccessLogEscapesRequestControlledFields(t *testing.T) {
	jsonMode = true
	component = "control"
	defer func() {
		jsonMode = false
		component = ""
	}()

	const (
		requestID = `req-"quoted"\backslash`
		userID    = `user-"quoted"\backslash`
		sandboxID = `sb-"quoted"\backslash`
	)

	var output bytes.Buffer
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("requestid", requestID)
		c.Locals(utils.UserIDLocalsKey, userID)
		c.Locals("sandbox_id", sandboxID)
		return c.Next()
	})
	app.Use(fiberlogger.New(fiberlogger.Config{
		Format:     AccessLogFormat(),
		CustomTags: AccessLogCustomTags(),
		Output:     &output,
	}))
	app.Get("/test", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusNoContent) })

	resp, err := app.Test(httptest.NewRequest("GET", "/test", nil))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	var got map[string]any
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatalf("access log is not valid JSON: %q: %v", output.String(), err)
	}
	for key, want := range map[string]string{
		"component":  "control",
		"request_id": requestID,
		"user_id":    userID,
		"sandbox_id": sandboxID,
		"method":     "GET",
		"path":       "/test",
	} {
		if got[key] != want {
			t.Errorf("%s = %v, want %q", key, got[key], want)
		}
	}
}
