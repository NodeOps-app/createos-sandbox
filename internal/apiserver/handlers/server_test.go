package handlers

import (
	"fmt"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

func TestCreateRejectsCallerSnapshotCacheAllowance(t *testing.T) {
	app := fiber.New()
	h := &Handler{}
	app.Post("/sandboxes", h.HandleCreate)
	req := httptest.NewRequest(http.MethodPost, "/sandboxes", strings.NewReader(`{"snapshot_cache":{"budget_mib":20480,"free_floor_mib":0}}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want rejection before placement", resp.StatusCode)
	}
}

func TestSnapshotCacheHintBounds(t *testing.T) {
	now := time.Now()
	id := "snap_01M6MY5DN2DZGXS73F8X64N00Z"
	hints := []proto.CachedSnapshot{
		{ID: "invalid", ExpiresAt: now.Add(time.Minute)},
		{ID: id, ExpiresAt: now.Add(-time.Minute)},
		{ID: id, ExpiresAt: now.Add(time.Hour)},
		{ID: id, ExpiresAt: now.Add(time.Minute)},
	}
	got := snapshotCacheHints(hints, now)
	if len(got) != 1 || got[0].ExpiresAt != now.Add(10*time.Minute) {
		t.Fatalf("unbounded hints: %v", got)
	}
	for i := 0; i < 300; i++ {
		hints = append(hints, proto.CachedSnapshot{ID: fmt.Sprintf("snap_%026d", i), ExpiresAt: now.Add(time.Minute)})
	}
	if len(snapshotCacheHints(hints, now)) != proto.MaxCachedSnapshotHints {
		t.Fatal("inventory not bounded")
	}
}
