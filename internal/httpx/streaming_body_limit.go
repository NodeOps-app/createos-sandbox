package httpx

import (
	"io"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// EnforceStreamingBodyLimits keeps StreamRequestBody from widening the body
// limit for ordinary endpoints. File PUTs may stream up to fileMax; internal
// RPCs and user-facing bodies retain their independent caps. Unknown-length
// bodies on ordinary endpoints are buffered only up to their cap, then
// restored for the handler. File uploads remain streamed end-to-end, where
// the guest applies the final byte cap.
func EnforceStreamingBodyLimits(defaultMax, internalMax, fileMax int64) fiber.Handler {
	return func(c *fiber.Ctx) error {
		length := int64(c.Request().Header.ContentLength())
		isFileUpload := c.Method() == fiber.MethodPut && strings.HasSuffix(c.Path(), "/files")
		if isFileUpload {
			if length > fileMax {
				return Fail(c, fiber.StatusRequestEntityTooLarge, "file exceeds 10 GiB limit")
			}
			return c.Next()
		}
		max := defaultMax
		if strings.HasPrefix(c.Path(), "/v1/internal/") {
			max = internalMax
		}
		if length > max {
			return Fail(c, fiber.StatusRequestEntityTooLarge, "request body too large")
		}
		if length < 0 {
			switch c.Method() {
			case fiber.MethodPost, fiber.MethodPut, fiber.MethodPatch:
				stream := c.Context().RequestBodyStream()
				if stream == nil {
					return c.Next()
				}
				body, err := io.ReadAll(io.LimitReader(stream, max+1))
				if err != nil {
					return Fail(c, fiber.StatusBadRequest, "invalid request body")
				}
				if int64(len(body)) > max {
					return Fail(c, fiber.StatusRequestEntityTooLarge, "request body too large")
				}
				c.Request().SetBodyRaw(body)
			}
		}
		return c.Next()
	}
}
