// Package httpx holds shared HTTP primitives — the JSend response
// envelope helpers (Success/Fail/Error), request correlation, and diagnostics
// shared by Fiber services. Streaming and ingress responses need not use JSend.
package httpx

import (
	"encoding/json"
	"fmt"

	"github.com/gofiber/fiber/v2"

	"github.com/NodeOps-app/createos-sandbox/internal/proto"
)

// Envelope is the JSend response shape used by these helpers.
// See https://github.com/omniti-labs/jsend for the spec.
type Envelope struct {
	Status  string      `json:"status"`            // "success" | "fail" | "error"
	Data    interface{} `json:"data,omitempty"`    // for "success" and "fail"
	Message string      `json:"message,omitempty"` // only for "error"
	Code    int         `json:"code,omitempty"`    // only for "error"
}

// Success replies 200 + {"status":"success","data":<data>}.
func Success(c *fiber.Ctx, data interface{}) error {
	return SuccessStatus(c, fiber.StatusOK, data)
}

// SuccessStatus replies with the supplied 2xx status and a standard JSend
// success envelope. Use it for asynchronous or creation responses whose HTTP
// semantics are not 200 OK.
func SuccessStatus(c *fiber.Ctx, status int, data interface{}) error {
	return c.Status(status).JSON(Envelope{
		Status: "success",
		Data:   data,
	})
}

// Fail replies `status` + {"status":"fail","data":<data>}.
// Typical for client errors (validation, not-found).
func Fail(c *fiber.Ctx, status int, data interface{}) error {
	return c.Status(status).JSON(Envelope{
		Status: "fail",
		Data:   data,
	})
}

// PageSlice slices an in-memory list against (limit, offset) and returns
// (page, total) for catalog endpoints whose full result already fits in
// memory (for example /v1/shapes). Out-of-range
// offsets at or beyond total produce an empty page; total is always len(all).
// Callers must validate nonnegative offset/limit and avoid integer overflow.
//
// For DB-backed lists, pass LIMIT/OFFSET to the query and use Paginated
// directly — don't load everything into memory.
func PageSlice[T any](all []T, limit, offset int) ([]T, int) {
	total := len(all)
	if offset >= total {
		return all[:0], total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return all[offset:end], total
}

// Paginated replies 200 + a fully-shaped paginated envelope:
//
//	{"status":"success","data":{"data":[...],"pagination":{...}}}
//
// items should already be the page slice (server applied limit + offset).
// total is supplied by the caller and should count matching items before
// pagination. The helper does not query or validate that count.
func Paginated(c *fiber.Ctx, items interface{}, total, limit, offset, count int) error {
	return Success(c, proto.Page[interface{}]{
		Data: items,
		Pagination: proto.Pagination{
			Total:  total,
			Limit:  limit,
			Offset: offset,
			Count:  count,
		},
	})
}

// Error replies `status` + {"status":"error","message":<msg>,"code":<status>}.
// Server errors.
//
// IMPORTANT: never pass raw err.Error() output here — that leaks
// internal detail (DB error text, upstream stack traces) to the
// caller. Pass a generic, hard-coded message and log the underlying
// err separately on the server side.
func Error(c *fiber.Ctx, status int, message string) error {
	return c.Status(status).JSON(Envelope{
		Status:  "error",
		Message: message,
		Code:    status,
	})
}

// Decode unwraps a JSend envelope from rbody into *out. Use it on the
// client side wherever you'd otherwise hand-write a `var env struct{
// Data <T>; ... }` decode. Returns an error if the envelope's `status`
// isn't "success" or if the body isn't valid JSON.
func Decode[T any](rbody []byte, out *T) error {
	var env struct {
		Status  string          `json:"status"`
		Data    json.RawMessage `json:"data"`
		Message string          `json:"message,omitempty"`
	}
	if err := json.Unmarshal(rbody, &env); err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	if env.Status != "success" {
		if env.Message != "" {
			return fmt.Errorf("jsend %s: %s", env.Status, env.Message)
		}
		return fmt.Errorf("jsend %s: %s", env.Status, string(rbody))
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return nil
	}
	return json.Unmarshal(env.Data, out)
}
