package middlewares

import (
	"github.com/gofiber/fiber/v2"
	"strconv"
	"time"

	"github.com/NodeOps-app/sandbox/internal/hosts/metrics"
)

// InstrumentInternalRPC labels metrics with registered route templates, never
// attacker-controlled URLs or resource IDs. Resolve the route after Next so
// matched endpoints replace the group middleware's prefix.
func InstrumentInternalRPC(service string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		started := time.Now()
		err := c.Next()
		path := c.Route().Path
		metrics.InternalRPC.WithLabelValues(service, path).Inc()
		metrics.InternalRPCSeconds.WithLabelValues(service, path, statusClass(c.Response().StatusCode())).Observe(time.Since(started).Seconds())
		return err
	}
}

func statusClass(status int) string {
	if status < 100 {
		return "other"
	}
	return strconv.Itoa(status/100) + "xx"
}
