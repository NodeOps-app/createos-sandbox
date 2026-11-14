package httpx

import (
	"context"
	"net/http"
	"strings"

	"github.com/NodeOps-app/createos-sandbox/internal/requestctx"
	"github.com/gofiber/fiber/v2"
)

// HeaderRequestID is the canonical header used to carry a request id
// between hops. Fiber's requestid middleware reads + sets it under the
// same name; outbound HTTP clients here propagate it onward so a single
// user request is traceable across control → scheduler → host.
const HeaderRequestID = "X-Request-Id"

// WithRequestID returns a child context that carries the given request
// id. Background goroutines spawned mid-request should derive from this
// so their logs and outbound RPCs stay correlated.
func WithRequestID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return requestctx.WithRequestID(ctx, id)
}

// RequestID extracts the request id from ctx, or "" if absent.
func RequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	return requestctx.RequestID(ctx)
}

// FiberRequestIDIntoContext is a Fiber middleware that copies the
// per-request id installed by gofiber's requestid.New() into the
// UserContext so downstream code reading from Go contexts (repo calls,
// outbound clients) can pick it up without touching Fiber locals.
//
// Mount AFTER requestid.New() and BEFORE any handler that derives a
// goroutine context from c.UserContext().
func FiberRequestIDIntoContext(c *fiber.Ctx) error {
	id, _ := c.Locals("requestid").(string)
	if id == "" {
		// Fall back to the header — covers tests that bypass requestid.New().
		id = c.Get(HeaderRequestID)
	}
	if id != "" {
		// Fiber strings may alias fasthttp's reusable request buffer. The
		// request id is retained in a Go context and later indexed by an
		// outbound HTTP/2 HPACK encoder, so it must own its bytes.
		c.SetUserContext(WithRequestID(c.UserContext(), strings.Clone(id)))
	}
	return c.Next()
}

// SetRequestIDHeader copies the request id from ctx onto req so the
// callee sees it as an inbound X-Request-Id. No-op when ctx has no id.
// Outbound HTTP clients should call this on every request they build.
func SetRequestIDHeader(ctx context.Context, req *http.Request) {
	if id := RequestID(ctx); id != "" {
		req.Header.Set(HeaderRequestID, id)
	}
}
