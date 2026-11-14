// Package requestctx carries request and sandbox IDs and connection cancellation
// in context.Context.
// HTTP helpers and API/host handlers attach the IDs; logging and database
// tracing read them to correlate operations. Keeping the shared context keys
// here avoids coupling those consumers to Fiber or API-server packages.
package requestctx

import "context"

type requestIDKey struct{}

func WithRequestID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, requestIDKey{}, id)
}

func RequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

type sandboxIDKey struct{}

// WithSandboxID returns a child context carrying the sandbox the request
// acts on, so log lines further down can be correlated to it.
func WithSandboxID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, sandboxIDKey{}, id)
}

// SandboxID extracts the sandbox id from ctx, or "" if absent.
func SandboxID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(sandboxIDKey{}).(string)
	return id
}
