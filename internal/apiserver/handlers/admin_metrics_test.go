package handlers

import (
	"context"
	"encoding/json"
	"github.com/NodeOps-app/createos-sandbox/internal/createos"
	"github.com/NodeOps-app/createos-sandbox/internal/hmacsign"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/middlewares"
	"github.com/gofiber/fiber/v2"
)

// A nil repository makes accidental access beyond the gate fail immediately.
func TestAdminMetricsAuthorization(t *testing.T) {
	for _, path := range []string{"/metrics", "/metrics/features", "/metrics/users", "/metrics/regions", "/metrics/activity"} {
		for _, tc := range []struct {
			name, configured, header, credential string
			status                               int
		}{
			{"missing", "metrics-secret", "", "", 401},
			{"admin-value", "metrics-secret", middlewares.HeaderAdminToken, "operator-secret", 401},
			{"wrong", "metrics-secret", middlewares.HeaderAdminToken, "wrong", 401},
			{"user-key", "metrics-secret", middlewares.HeaderXAPIKey, "metrics-secret", 401},
			{"disabled", "", middlewares.HeaderAdminToken, "metrics-secret", 503},
			{"authorized-invalid-window", "metrics-secret", middlewares.HeaderAdminToken, "metrics-secret", 400},
		} {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				app := fiber.New()
				mw := &middlewares.Middleware{MetricsToken: tc.configured, AdminToken: "operator-secret"}
				h := &Handler{}
				admin := app.Group("/v1/admin", mw.MustReadMetrics())
				admin.Get("/metrics", h.HandleAdminMetrics)
				admin.Get("/metrics/features", h.HandleAdminFeatureMetrics)
				admin.Get("/metrics/users", h.HandleAdminUserMetrics)
				admin.Get("/metrics/regions", h.HandleAdminRegionMetrics)
				admin.Get("/metrics/activity", h.HandleAdminActivity)
				req := httptest.NewRequest("GET", "/v1/admin"+path+"?from=invalid", nil)
				if tc.header != "" {
					req.Header.Set(tc.header, tc.credential)
				}
				res, err := app.Test(req)
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				if res.StatusCode != tc.status {
					t.Fatalf("status %d, want %d", res.StatusCode, tc.status)
				}
			})
		}
	}
}

func TestAdminUserEmailSignedLookupAndCache(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		timestamp, err := strconv.ParseInt(r.Header.Get("X-CreateOS-Timestamp"), 10, 64)
		if err != nil || r.Method != "POST" || r.URL.Path != "/v1/sandboxes/current-plan" || r.Header.Get("X-CreateOS-Signature") != hmacsign.Sign([]byte("test-secret"), body, time.Unix(timestamp, 0)) {
			t.Error("invalid signed request")
			w.WriteHeader(401)
			return
		}
		var req struct {
			UserID string `json:"user_id"`
		}
		if err := json.Unmarshal(body, &req); err != nil || req.UserID != "user-1" {
			t.Error("wrong user lookup")
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"success","data":{"user":{"id":"user-1","email":"person@example.test"}}}`)
	}))
	defer upstream.Close()
	h := &Handler{createos: createos.New(upstream.URL, "test-secret")}
	if got := h.adminUserEmail(context.Background(), "user-1"); got != "person@example.test" {
		t.Fatalf("email = %q", got)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := h.adminUserEmail(context.Background(), "user-1"); got != "person@example.test" {
				t.Errorf("email = %q", got)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("made %d calls, want cached lookup", calls.Load())
	}
	h.adminEmailMu.Lock()
	delete(h.adminEmails, "user-1")
	h.adminEmailMu.Unlock()
	if h.adminUserEmail(context.Background(), "user-1") == "" || calls.Load() != 2 {
		t.Fatal("cache miss was not fetched")
	}
}
func TestAdminUserEmailFallback(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"upstream-error", `{}`, 503},
		{"missing-profile", `{"status":"success","data":{}}`, 200},
		{"different-user", `{"status":"success","data":{"user":{"id":"other","email":"person@example.test"}}}`, 200},
		{"not-email", `{"status":"success","data":{"user":{"id":"user-1","email":"display name"}}}`, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer server.Close()
			h := &Handler{createos: createos.New(server.URL, "test-secret")}
			for i := 0; i < 2; i++ {
				if h.adminUserEmail(context.Background(), "user-1") != "" {
					t.Fatal("expected ID fallback")
				}
			}
			if calls.Load() != 2 {
				t.Fatal("failed lookups must remain retryable")
			}
		})
	}
}

// Exercise route ordering as well as credential separation: metrics must bypass
// the operator gate, while their credential must never reach operator handlers.
func TestMetricsTokenCannotManageHosts(t *testing.T) {
	app := fiber.New()
	mw := &middlewares.Middleware{AdminToken: "operator-secret", MetricsToken: "metrics-secret"}
	app.Get("/v1/admin/metrics", mw.MustReadMetrics(), func(c *fiber.Ctx) error { return c.SendStatus(200) })
	admin := app.Group("/v1/admin", mw.MustBeAdmin())
	reached := false
	for _, path := range []string{"/hosts/test/cordon", "/hosts/test/uncordon", "/hosts/test/drain"} {
		admin.Post(path, func(c *fiber.Ctx) error { reached = true; return c.SendStatus(200) })
	}
	admin.Get("/debug/pprof/", func(c *fiber.Ctx) error { reached = true; return c.SendStatus(200) })
	for _, path := range []string{"/hosts/test/cordon", "/hosts/test/uncordon", "/hosts/test/drain", "/debug/pprof/"} {
		for _, header := range []string{middlewares.HeaderAdminToken, middlewares.HeaderXAPIKey} {
			method := "POST"
			if path == "/debug/pprof/" {
				method = "GET"
			}
			req := httptest.NewRequest(method, "/v1/admin"+path, nil)
			req.Header.Set(header, "metrics-secret")
			res, err := app.Test(req)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			if res.StatusCode != 401 || reached {
				t.Fatalf("metrics token reached %s via %s: %d", path, header, res.StatusCode)
			}
		}
	}
	req := httptest.NewRequest("GET", "/v1/admin/metrics", nil)
	req.Header.Set(middlewares.HeaderAdminToken, "metrics-secret")
	res, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("metrics denied: %d", res.StatusCode)
	}
	mw.MetricsToken = mw.AdminToken
	req.Header.Set(middlewares.HeaderAdminToken, "operator-secret")
	res, err = app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 503 {
		t.Fatalf("identical credentials must fail closed: %d", res.StatusCode)
	}
}
