package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/hosts/controlclient"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/vm"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/internal/storage"
)

type blockedPauseStorage struct {
	*storage.MemStorage
	deadline time.Time
	calls    int
}

func (s *blockedPauseStorage) Put(ctx context.Context, _ string, _ io.Reader, _ int64, _ string) error {
	s.deadline, _ = ctx.Deadline()
	s.calls++
	<-ctx.Done()
	return ctx.Err()
}

func TestPauseUploadDeadlineRollsBackWithLiveContext(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "fc.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var resumed, recorded atomic.Bool
	fc := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch && r.URL.Path == "/vm" {
			resumed.Store(true)
			w.WriteHeader(204)
			return
		}
		w.WriteHeader(400)
	})}
	go fc.Serve(listener)
	defer fc.Close()
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/internal/db/pause/mark-rolled-back" || !resumed.Load() {
			w.WriteHeader(400)
			return
		}
		recorded.Store(true)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"status":"running"}}`)
	}))
	defer control.Close()
	backend := &blockedPauseStorage{MemStorage: storage.NewMemStorage()}
	s := &Service{Storage: backend, Repo: controlclient.NewClient(control.URL), PauseCfg: PauseConfig{PausedDir: dir, RetryBudget: 5}}
	sb := &vm.Sandbox{ID: "test-pause", ApiSocket: socket}
	sb.Freezing.Store(true)
	file := filepath.Join(dir, "memfile")
	if err := os.WriteFile(file, []byte("snapshot"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	desc := storage.ArtifactDescriptor{Size: 8}
	if s.uploadBundleWithRetry(ctx, sb, "snapshots/test/", file, file, file, []byte("manifest"), desc, desc, desc) {
		t.Fatal("blocked upload succeeded")
	}
	if backend.deadline.IsZero() || backend.calls != 1 {
		t.Fatalf("deadline=%v calls=%d", backend.deadline, backend.calls)
	}
	if !resumed.Load() || !recorded.Load() || sb.Freezing.Load() {
		t.Fatal("expired upload did not resume and record rollback")
	}
}

func TestPauseUploadBudgetScalesWithBundle(t *testing.T) {
	if got := pauseUploadTimeout(37 * 1024 * 1024); got != 157*time.Second {
		t.Fatalf("small bundle budget: %s", got)
	}
	if got := pauseUploadTimeout(8 * 1024 * 1024 * 1024); got != 30*time.Minute {
		t.Fatalf("large bundle budget: %s", got)
	}
}

// These tests exercise the shared-download lifecycle rather than a real bucket.
type snapshotCountingStorage struct {
	*storage.MemStorage
	calls atomic.Int64
	gate  <-chan struct{}
}

func (s *snapshotCountingStorage) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	s.calls.Add(1)
	if s.gate != nil {
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-s.gate:
		}
	}
	return s.MemStorage.Get(ctx, key)
}

func snapshotCacheFixture(t *testing.T) (*Service, *snapshotCountingStorage, *storage.Manifest, *proto.SnapshotCachePolicy) {
	t.Helper()
	dir := t.TempDir()
	backend := &snapshotCountingStorage{MemStorage: storage.NewMemStorage()}
	payload := bytes.Repeat([]byte("snapshot"), 65536)
	sha := fmt.Sprintf("%x", sha256.Sum256(payload))
	if err := backend.Put(context.Background(), "bundle/overlay", bytes.NewReader(payload), int64(len(payload)), sha); err != nil {
		t.Fatal(err)
	}
	s := &Service{Storage: backend, PauseCfg: PauseConfig{PausedDir: dir, LocalDiskBudget: 2 * 1024 * 1024}}
	if err := s.InitSnapshotDownloadCache(dir, dir); err != nil {
		t.Fatal(err)
	}
	if err := s.InitDiskBudget(); err != nil {
		t.Fatal(err)
	}
	s.snapshotCache.free = func() (int64, error) { return 100 * 1024 * 1024, nil }
	return s, backend, &storage.Manifest{Artifacts: map[string]storage.ArtifactDescriptor{"overlay": {Size: int64(len(payload)), SHA256: sha}}}, &proto.SnapshotCachePolicy{BudgetMiB: 1, FreeFloorMiB: 1}
}

func TestSnapshotDownloadCacheConcurrentPrivateCopies(t *testing.T) {
	s, backend, manifest, policy := snapshotCacheFixture(t)
	gate := make(chan struct{})
	backend.gate = gate
	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	paths := make([]string, n)
	for i := range n {
		paths[i] = filepath.Join(t.TempDir(), "restore")
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- s.fetchSnapshotArtifact(context.Background(), "overlay", paths[i], "bundle/overlay", manifest, policy)
		}(i)
	}
	close(gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := backend.calls.Load(); got != 1 {
		t.Fatalf("downloads = %d, want 1", got)
	}
	if err := os.WriteFile(paths[0], []byte("user mutation"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, p := range paths[1:] {
		hash, _, err := storage.HashFile(p)
		if err != nil || hash != manifest.Artifacts["overlay"].SHA256 {
			t.Fatalf("private copy changed: %s %v", hash, err)
		}
	}
	c := s.snapshotCache
	for _, e := range c.entries {
		// Corruption must never reach a VM: a hit must refetch and verify.
		if err := os.WriteFile(e.path, []byte("corrupt"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	dst := filepath.Join(t.TempDir(), "restore")
	if err := s.fetchSnapshotArtifact(context.Background(), "overlay", dst, "bundle/overlay", manifest, policy); err != nil {
		t.Fatal(err)
	}
	hash, _, _ := storage.HashFile(dst)
	if hash != manifest.Artifacts["overlay"].SHA256 || backend.calls.Load() != 2 {
		t.Fatal("corrupt cache was not refetched")
	}
}

func TestSnapshotDownloadCacheBudgetExpiryAndRestart(t *testing.T) {
	s, backend, manifest, policy := snapshotCacheFixture(t)
	fetch := func() {
		t.Helper()
		if err := s.fetchSnapshotArtifact(context.Background(), "overlay", filepath.Join(t.TempDir(), "restore"), "bundle/overlay", manifest, policy); err != nil {
			t.Fatal(err)
		}
	}
	c := s.snapshotCache
	fetch()
	c.mu.Lock()
	var entry *snapshotCacheEntry
	for _, e := range c.entries {
		entry = e
	}
	entry.refs++
	entry.expires = time.Time{}
	c.mu.Unlock()
	c.reap()
	if len(c.entries) != 1 {
		t.Fatal("evicted an active reader")
	}
	c.mu.Lock()
	entry.refs--
	c.mu.Unlock()
	c.reap()
	if len(c.entries) != 0 || c.used != 0 {
		t.Fatal("expired entry still retained")
	}
	fetch()
	c.free = func() (int64, error) { return 0, nil }
	c.reap()
	if len(c.entries) != 0 {
		t.Fatal("disk pressure did not evict")
	}
	before := backend.calls.Load()
	fetch()
	fetch()
	if backend.calls.Load() != before+2 || c.used != 0 {
		t.Fatal("low disk must bypass caching")
	}
	c.free = func() (int64, error) { return 100 * 1024 * 1024, nil }
	s.PauseCfg.LocalDiskBudget = 1
	fetch()
	if c.used != 0 {
		t.Fatal("oversized artifact cached")
	}
	s.PauseCfg.LocalDiskBudget = 1024 * 1024
	fetch()
	oldDir := c.dir
	if err := s.InitSnapshotDownloadCache(filepath.Dir(oldDir), filepath.Dir(oldDir)); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(oldDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("restart retained unaccounted files: %v", err)
	}
}

func TestSnapshotDownloadCacheCancelledLeaderReleasesReservation(t *testing.T) {
	s, backend, manifest, policy := snapshotCacheFixture(t)
	gate := make(chan struct{})
	backend.gate = gate
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- s.fetchSnapshotArtifact(ctx, "overlay", filepath.Join(t.TempDir(), "restore"), "bundle/overlay", manifest, policy)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for backend.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled download succeeded")
	}
	c := s.snapshotCache
	if c.used != 0 || len(c.entries) != 0 {
		t.Fatal("cancelled reservation retained")
	}
	close(gate)
	if err := s.fetchSnapshotArtifact(context.Background(), "overlay", filepath.Join(t.TempDir(), "restore"), "bundle/overlay", manifest, policy); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotDownloadCacheRejectsInvalidRemoteChecksum(t *testing.T) {
	s, _, manifest, policy := snapshotCacheFixture(t)
	want := manifest.Artifacts["overlay"]
	want.SHA256 = fmt.Sprintf("%064d", 0)
	manifest.Artifacts["overlay"] = want
	dst := filepath.Join(t.TempDir(), "restore")
	if err := s.fetchSnapshotArtifact(context.Background(), "overlay", dst, "bundle/overlay", manifest, policy); err == nil {
		t.Fatal("accepted invalid checksum")
	}
	if s.snapshotCache.used != 0 || len(s.snapshotCache.entries) != 0 {
		t.Fatal("invalid download retained")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatal("invalid artifact published")
	}
}

func TestSnapshotDownloadCacheReservesConcurrentMisses(t *testing.T) {
	s, backend, manifest, policy := snapshotCacheFixture(t)
	gate := make(chan struct{})
	backend.gate = gate
	defer close(gate)
	// Three different objects, each half the entire cache budget. The third
	// restore may bypass the cache, but cannot reserve another cache download.
	for _, key := range []string{"other/one", "other/two"} {
		if err := backend.Copy(context.Background(), "bundle/overlay", key); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 3)
	for _, key := range []string{"bundle/overlay", "other/one", "other/two"} {
		dst := filepath.Join(t.TempDir(), "restore")
		go func() { errs <- s.fetchSnapshotArtifact(ctx, "overlay", dst, key, manifest, policy) }()
	}
	deadline := time.Now().Add(5 * time.Second)
	for backend.calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	c := s.snapshotCache
	c.mu.Lock()
	used, entries := c.used, len(c.entries)
	c.mu.Unlock()
	cancel()
	for range 3 {
		<-errs
	}
	if used != 1024*1024 || entries != 2 {
		t.Fatalf("reserved %d bytes across %d entries, want 1 MiB / 2", used, entries)
	}
}

func TestSnapshotCacheAdvertisesOnlyCompleteUnexpiredBundles(t *testing.T) {
	s, backend, manifest, policy := snapshotCacheFixture(t)
	id := "snap_01M6MY5DN2DZGXS73F8X64N00Z"
	for _, name := range []string{"overlay", "memory"} {
		if err := backend.Copy(context.Background(), "bundle/overlay", storage.BundlePrefix(id)+name); err != nil {
			t.Fatal(err)
		}
	}
	manifest.Artifacts["memory"] = manifest.Artifacts["overlay"]
	fetch := func(name string) {
		t.Helper()
		if err := s.fetchSnapshotArtifact(context.Background(), name, filepath.Join(t.TempDir(), name), storage.BundlePrefix(id)+name, manifest, policy); err != nil {
			t.Fatal(err)
		}
	}
	fetch("overlay")
	s.rememberSnapshot(id, manifest)
	if len(s.SnapshotCacheHints()) != 0 {
		t.Fatal("advertised partial bundle")
	}
	fetch("memory")
	s.rememberSnapshot(id, manifest)
	hints := s.SnapshotCacheHints()
	if len(hints) != 1 || hints[0].ID != id {
		t.Fatal("complete bundle not advertised")
	}
	c := s.snapshotCache
	c.mu.Lock()
	for _, e := range c.entries {
		e.expires = time.Now().Add(-time.Second)
		break
	}
	c.mu.Unlock()
	if len(s.SnapshotCacheHints()) != 0 {
		t.Fatal("advertised expired bundle")
	}
	if len(c.snapshots) != 0 {
		t.Fatal("stale inventory retained")
	}
}
