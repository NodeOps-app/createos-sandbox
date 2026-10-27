package handlers

import (
	"github.com/gofiber/fiber/v2"

	"github.com/NodeOps-app/sandbox/internal/apiserver/docs"
)

func (h *Handler) HandleSwagger(c *fiber.Ctx) error {
	c.Set(fiber.HeaderContentType, "application/json; charset=utf-8")
	c.Set(fiber.HeaderCacheControl, "public, max-age=300")
	c.Set("X-Content-Type-Options", "nosniff")
	return c.Send(docs.SwaggerJSON)
}
