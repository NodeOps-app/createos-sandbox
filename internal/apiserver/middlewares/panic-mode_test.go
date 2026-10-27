package middlewares

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestPanicModeDisabledPassesPublicRequests(t *testing.T) {
	app := fiber.New()
	app.Use(PanicMode(false))
	app.Get("/v1/sandboxes", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusNoContent) })

	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/v1/sandboxes", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, fiber.StatusNoContent)
	}
}

func TestPanicModeEnabledRejectsPublicRequests(t *testing.T) {
	app := fiber.New()
	app.Use(PanicMode(true))
	app.Get("/v1/sandboxes", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusNoContent) })

	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/v1/sandboxes", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, fiber.StatusServiceUnavailable)
	}
}

func TestPanicModeEnabledKeepsRecoveryRoutesAvailable(t *testing.T) {
	for _, path := range []string{
		"/healthz",
		"/readyz",
		"/v1/internal/crl",
		"/v1/admin/hosts/host-1/drain",
	} {
		t.Run(path, func(t *testing.T) {
			app := fiber.New()
			app.Use(PanicMode(true))
			app.Get(path, func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusNoContent) })

			resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, path, nil))
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != fiber.StatusNoContent {
				t.Fatalf("status = %d, want %d", resp.StatusCode, fiber.StatusNoContent)
			}
		})
	}
}
