package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/controlclient"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/vm"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func budgetFixture(free, limit int64) *diskBudget {
	return &diskBudget{root: "/cache", cacheLimit: limit, leases: make(map[*diskLease]struct{}),
		space:     func(string) (uint64, int64, error) { return 1, free, nil },
		allocated: func(string) (int64, error) { return 0, nil }}
}

func TestDiskBudgetConcurrentPauseAndCache(t *testing.T) {
	b := budgetFixture(100, 100)
	var wg sync.WaitGroup
	accepted := make(chan *diskLease, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l, err := b.reserve([]diskNeed{{fmt.Sprintf("/cache/%d", i), 10}}, i%2 == 0, 0)
			if err == nil {
				accepted <- l
			} else if !errors.Is(err, errDiskBudget) {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	close(accepted)
	if len(accepted) != 10 {
		t.Fatalf("accepted %d reservations; want 10", len(accepted))
	}
	for l := range accepted {
		l.release()
		l.release()
	}
	if _, err := b.reserve([]diskNeed{{"/cache/next", 100}}, false, 0); err != nil {
		t.Fatal(err)
	}
}

func TestDiskBudgetCreditsWrittenBytesAndSeparatesDevices(t *testing.T) {
	b := budgetFixture(100, 100)
	written := int64(0)
	b.allocated = func(path string) (int64, error) {
		if path == "/cache" || path == "/cache/pause" {
			return written, nil
		}
		return 0, nil
	}
	b.space = func(path string) (uint64, int64, error) {
		if path == "/runtime/restore" {
			return 2, 30, nil
		}
		return 1, 100 - written, nil
	}
	l, err := b.reserve([]diskNeed{{"/cache/pause", 60}}, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer l.release()
	written = 40
	cache, err := b.reserve([]diskNeed{{"/cache/download", 40}, {"/runtime/restore", 30}}, false, 0)
	if err != nil {
		t.Fatal("written bytes counted twice or devices combined:", err)
	}
	cache.release()
	if _, err = b.reserve([]diskNeed{{"/cache/download", 41}}, true, 0); !errors.Is(err, errDiskBudget) {
		t.Fatalf("overcommit: %v", err)
	}
	if _, err = b.reserve([]diskNeed{{"/cache/download", 40}}, true, 1); !errors.Is(err, errDiskBudget) {
		t.Fatalf("floor ignored: %v", err)
	}
}

func TestDiskBudgetRestartRetainsCheckpointAndCountsSparseAllocation(t *testing.T) {
	dir := t.TempDir()
	checkpoint := filepath.Join(dir, "snap_pending")
	if err := os.WriteFile(checkpoint, make([]byte, 8192), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "sparse"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(1 << 30); err != nil {
		t.Fatal(err)
	}
	f.Close()
	s := &Service{PauseCfg: PauseConfig{PausedDir: dir, LocalDiskBudget: 1}}
	for i := 0; i < 2; i++ {
		if err = s.InitDiskBudget(); err != nil {
			t.Fatal(err)
		}
		used, err := s.diskBudget.cacheUsage()
		if err != nil {
			t.Fatal(err)
		}
		if used < 8192 || used >= 1<<30 {
			t.Fatalf("wrong physical allocation: %d", used)
		}
		s.reapDiskBudget(context.Background())
		if _, err = os.Stat(checkpoint); err != nil {
			t.Fatal("unuploaded checkpoint removed:", err)
		}
		if _, err = s.diskBudget.reserve([]diskNeed{{filepath.Join(dir, "new"), 1}}, true, 0); !errors.Is(err, errDiskBudget) {
			t.Fatalf("restart lost cache accounting: %v", err)
		}
	}
}

func TestDiskBudgetRetentionLimitDoesNotBlockMandatoryWork(t *testing.T) {
	b := budgetFixture(100, 20)
	l, err := b.reserve([]diskNeed{{"/cache/pause", 50}}, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.reserve([]diskNeed{{"/cache/download", 1}}, true, 0); !errors.Is(err, errDiskBudget) {
		t.Fatalf("cache ignored pause reservation: %v", err)
	}
	l.release()
	if _, err = b.reserve([]diskNeed{{"/cache/download", 20}}, true, 0); err != nil {
		t.Fatal(err)
	}
}

func TestPauseDiskPressureKeepsGuestRunning(t *testing.T) {
	var rolledBack atomic.Bool
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/internal/db/pause/local-cache-candidates":
			fmt.Fprint(w, `{"status":"success","data":[]}`)
		case "/v1/internal/db/pause/mark-rolled-back":
			rolledBack.Store(true)
			fmt.Fprint(w, `{"status":"success","data":{"status":"running"}}`)
		default:
			t.Errorf("unexpected lifecycle request %s", r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer control.Close()
	sb := &vm.Sandbox{ID: "sb-budget", MemMib: 1024, DiskMib: 1024}
	s := &Service{Mgr: &vm.Manager{Sandboxes: map[string]*vm.Sandbox{sb.ID: sb}}, Repo: controlclient.NewClient(control.URL), PauseCfg: PauseConfig{PausedDir: t.TempDir()}, diskBudget: budgetFixture(0, 0)}
	s.runPause(context.Background(), sb.ID)
	if !rolledBack.Load() || sb.Freezing.Load() {
		t.Fatal("disk pressure did not preserve running guest")
	}
	if len(s.diskBudget.leases) != 0 {
		t.Fatal("failed pause leaked reservation")
	}
}

func TestDiskBudgetEvictionProtectsActiveDownloads(t *testing.T) {
	dir := t.TempDir()
	c := &snapshotDownloadCache{entries: make(map[string]*snapshotCacheEntry), snapshots: make(map[string][]string)}
	for _, name := range []string{"idle", "reader", "writer"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("data"), 0600); err != nil {
			t.Fatal(err)
		}
		c.entries[name] = &snapshotCacheEntry{path: path, size: 4}
		c.used += 4
	}
	c.entries["reader"].refs = 1
	c.entries["writer"].ready = make(chan struct{})
	s := &Service{snapshotCache: c}
	if !s.evictDiskCache(context.Background()) {
		t.Fatal("idle entry not evicted")
	}
	if _, err := os.Stat(filepath.Join(dir, "idle")); !os.IsNotExist(err) {
		t.Fatalf("idle file remains: %v", err)
	}
	if s.evictDiskCache(context.Background()) {
		t.Fatal("active entry evicted")
	}
	for _, name := range []string{"reader", "writer"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
}
