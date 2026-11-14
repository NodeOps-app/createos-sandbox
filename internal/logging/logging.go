// Package logging configures the process-wide loggers and stamps request
// correlation fields onto every line logged with a context.
package logging

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	fiberlogger "github.com/gofiber/fiber/v2/middleware/logger"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/requestctx"
	"github.com/NodeOps-app/createos-sandbox/internal/utils"
)

// Setup applies the supplied format at process startup. "json" installs JSON
// formatters for logrus and slog; other values leave existing formatters intact.
// The logrus correlation hook is installed in both modes; the slog context
// handler is installed only in JSON mode.
func Setup(format, processComponent string) {
	jsonMode = strings.EqualFold(strings.TrimSpace(format), "json")
	component = strings.TrimSpace(processComponent)
	if jsonMode {
		log.SetFormatter(&log.JSONFormatter{})
		slog.SetDefault(slog.New(contextHandler{
			Handler:   slog.NewJSONHandler(os.Stderr, nil),
			component: component,
		}))
	}
	log.AddHook(ContextHook{Component: component})
}

var (
	jsonMode  bool
	component string
)

const textAccessLog = "${time} ${locals:requestid} ${method} ${path} ${status} ${latency}\n"

const jsonAccessLog = `{"time":"${time}","level":"info","msg":"http request",${json_request_fields},` +
	`"status":${status},"latency":"${latency}"}` + "\n"

// AccessLogFormat is the Fiber access-log template for the configured mode.
// The text template is the historical one and must not change shape.
func AccessLogFormat() string {
	if jsonMode {
		return jsonAccessLog
	}
	return textAccessLog
}

// AccessLogCustomTags JSON-encodes every request-controlled string inserted
// into the JSON access-log template. Fiber's built-in tags write raw bytes;
// using them inside quoted JSON would let a quote or backslash in an incoming
// X-Request-Id or path corrupt the log line.
func AccessLogCustomTags() map[string]fiberlogger.LogFunc {
	if !jsonMode {
		return nil
	}
	return map[string]fiberlogger.LogFunc{
		"json_request_fields": writeJSONRequestFields,
	}
}

func writeJSONRequestFields(output fiberlogger.Buffer, c *fiber.Ctx, _ *fiberlogger.Data, _ string) (int, error) {
	requestID, _ := c.Locals("requestid").(string)
	userID, _ := c.Locals(utils.UserIDLocalsKey).(string)
	sandboxID, _ := c.Locals("sandbox_id").(string)

	// Build all request-controlled fields in one buffer. strconv.AppendQuote
	// provides JSON-compatible string escaping without json.Marshal's
	// reflection and one-allocation-per-field cost on this hot path.
	buf := make([]byte, 0, len(component)+len(requestID)+len(userID)+len(sandboxID)+len(c.Method())+len(c.Path())+112)
	buf = append(buf, `"component":`...)
	buf = strconv.AppendQuote(buf, component)
	buf = append(buf, `,"request_id":`...)
	buf = strconv.AppendQuote(buf, requestID)
	buf = append(buf, `,"user_id":`...)
	buf = strconv.AppendQuote(buf, userID)
	buf = append(buf, `,"sandbox_id":`...)
	buf = strconv.AppendQuote(buf, sandboxID)
	buf = append(buf, `,"method":`...)
	buf = strconv.AppendQuote(buf, c.Method())
	buf = append(buf, `,"path":`...)
	buf = strconv.AppendQuote(buf, c.Path())
	return output.Write(buf)
}

// ContextHook stamps the process component and copies request_id, user_id and
// sandbox_id from the entry's context. Fields already set by the caller win.
type ContextHook struct {
	Component string
}

func (ContextHook) Levels() []log.Level { return log.AllLevels }

func (h ContextHook) Fire(e *log.Entry) error {
	if h.Component != "" {
		if _, set := e.Data["component"]; !set {
			e.Data["component"] = h.Component
		}
	}
	if e.Context == nil {
		return nil
	}
	for k, v := range Fields(e.Context) {
		if _, set := e.Data[k]; !set {
			e.Data[k] = v
		}
	}
	return nil
}

// Fields returns the non-empty correlation fields carried by ctx.
func Fields(ctx context.Context) map[string]string {
	out := map[string]string{}
	if v := requestctx.RequestID(ctx); v != "" {
		out["request_id"] = v
	}
	if v := utils.UserIDFromContext(ctx); v != "" {
		out["user_id"] = v
	}
	if v := requestctx.SandboxID(ctx); v != "" {
		out["sandbox_id"] = v
	}
	return out
}

// contextHandler adds the same correlation fields to slog records.
type contextHandler struct {
	slog.Handler
	component    string
	hasComponent bool
}

func (h contextHandler) Handle(ctx context.Context, r slog.Record) error {
	hasComponent := h.hasComponent
	if !hasComponent {
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "component" {
				hasComponent = true
				return false
			}
			return true
		})
	}
	if !hasComponent && h.component != "" {
		r.AddAttrs(slog.String("component", h.component))
	}
	for k, v := range Fields(ctx) {
		r.AddAttrs(slog.String(k, v))
	}
	return h.Handler.Handle(ctx, r)
}

func (h contextHandler) WithAttrs(a []slog.Attr) slog.Handler {
	hasComponent := h.hasComponent
	for _, attr := range a {
		if attr.Key == "component" {
			hasComponent = true
			break
		}
	}
	h.Handler = h.Handler.WithAttrs(a)
	h.hasComponent = hasComponent
	return h
}

func (h contextHandler) WithGroup(name string) slog.Handler {
	h.Handler = h.Handler.WithGroup(name)
	return h
}
