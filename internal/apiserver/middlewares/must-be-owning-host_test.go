package middlewares

import (
	"context"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestExtractBodyStringFieldRejectsAmbiguousKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		body  string
		field string
		want  string
		err   bool
	}{
		{name: "exact host", body: `{"host":"host-a"}`, field: "host", want: "host-a"},
		{name: "exact id", body: `{"id":"sandbox-a"}`, field: "id", want: "sandbox-a"},
		{name: "unrelated case variants allowed", body: `{"host":"host-a","Name":"value"}`, field: "host", want: "host-a"},
		{name: "missing", body: `{"at":"2026-01-01T00:00:00Z"}`, field: "host"},
		{name: "host case variant", body: `{"host":"host-a","Host":"host-b"}`, field: "host", err: true},
		{name: "id case variant", body: `{"id":"sandbox-a","Id":"sandbox-b"}`, field: "id", err: true},
		{name: "id uppercase variant", body: `{"id":"sandbox-a","ID":"sandbox-b"}`, field: "id", err: true},
		{name: "variant without exact key", body: `{"Host":"host-b"}`, field: "host", err: true},
		{name: "duplicate exact key", body: `{"host":"host-a","host":"host-b"}`, field: "host", err: true},
		{name: "non-object", body: `[]`, field: "host", err: true},
		{name: "malformed", body: `{"host":`, field: "host", err: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := extractBodyStringField([]byte(tt.body), tt.field)
			if tt.err {
				if err == nil {
					t.Fatalf("expected error, got value %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGateOwningHostFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		lookup     SandboxOwnerLookup
		callerHost string
		wantStatus int
	}{
		{
			name: "matching active owner",
			lookup: func(context.Context, string) (string, bool, error) {
				return "host-a", true, nil
			},
			callerHost: "host-a",
			wantStatus: http.StatusNoContent,
		},
		{
			name: "different active owner",
			lookup: func(context.Context, string) (string, bool, error) {
				return "host-b", true, nil
			},
			callerHost: "host-a",
			wantStatus: http.StatusForbidden,
		},
		{
			name: "existing but unassigned",
			lookup: func(context.Context, string) (string, bool, error) {
				return "", true, nil
			},
			callerHost: "host-a",
			wantStatus: http.StatusForbidden,
		},
		{
			name: "missing sandbox",
			lookup: func(context.Context, string) (string, bool, error) {
				return "", false, nil
			},
			callerHost: "host-a",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			app := fiber.New()
			mw := &Middleware{SandboxOwnerLookup: tt.lookup}
			app.Get("/", func(c *fiber.Ctx) error {
				if !mw.gateOwningHost(c, "sb-test", tt.callerHost) {
					return nil
				}
				return c.SendStatus(http.StatusNoContent)
			})
			resp, err := app.Test(newFiberRequest(t, http.MethodGet, "/"))
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status=%d, want %d", resp.StatusCode, tt.wantStatus)
			}
		})
	}
}

func newFiberRequest(t *testing.T, method, path string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, "http://example.test"+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}
