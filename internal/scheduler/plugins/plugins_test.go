package plugins

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/createos-sandbox/models"
)

func active(id string, cap, used, vms, max int, rootfses ...string) models.Host {
	return models.Host{
		ID: id, Status: "active", Region: "eu", LastSeen: time.Now(),
		MemCapacityMib: cap, InUseMib: used, VMCount: vms, MaxVMs: max,
		Rootfses: rootfses,
	}
}

func defaultPipeline(t *testing.T) *framework.Pipeline {
	t.Helper()
	reg := framework.NewRegistry()
	RegisterBuiltins(reg, 0)
	p, err := reg.BuildPipeline(DefaultPipelineSpec())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// pipelineNoReserver returns the default pipeline with the reserver
// stripped — useful for asserting filter/scorer behaviour without
// counter side effects.
func pipelineNoReserver(t *testing.T) *framework.Pipeline {
	t.Helper()
	p := defaultPipeline(t)
	p.Reserver = nil
	return p
}

func TestRootfsFilter_passes(t *testing.T) {
	hosts := []models.Host{
		active("a", 4096, 0, 0, 0, "python"),
		active("b", 4096, 0, 0, 0, "node"),
		active("c", 4096, 0, 0, 0, "python", "node"),
	}
	p := pipelineNoReserver(t)
	for i := 0; i < 5; i++ {
		d, err := p.Schedule(context.Background(), "sb_test", &framework.Request{MemMiB: 256, Rootfs: "python", Region: "eu"}, hosts)
		if err != nil {
			t.Fatalf("python: %v", err)
		}
		if d.HostID == "b" {
			t.Fatalf("python landed on b (only node)")
		}
	}
}

func TestRootfsFilter_unknown(t *testing.T) {
	hosts := []models.Host{active("a", 4096, 0, 0, 0, "python")}
	p := pipelineNoReserver(t)
	_, err := p.Schedule(context.Background(), "sb_test", &framework.Request{MemMiB: 256, Rootfs: "rust", Region: "eu"}, hosts)
	if !errors.Is(err, framework.ErrNoCapacity) {
		t.Fatalf("err = %v, want ErrNoCapacity", err)
	}
}

func TestRootfsFilter_emptyRequestMatchesAny(t *testing.T) {
	hosts := []models.Host{active("a", 4096, 0, 0, 0, "python")}
	p := pipelineNoReserver(t)
	if _, err := p.Schedule(context.Background(), "sb_test", &framework.Request{MemMiB: 256, Region: "eu"}, hosts); err != nil {
		t.Fatalf("empty rootfs should match any host: %v", err)
	}
}

func TestRootfsFilter_legacyHostMatchesAny(t *testing.T) {
	hosts := []models.Host{
		{ID: "legacy", Status: "active", LastSeen: time.Now(), Region: "eu", MemCapacityMib: 4096, Rootfses: nil},
	}
	p := pipelineNoReserver(t)
	if _, err := p.Schedule(context.Background(), "sb_test", &framework.Request{MemMiB: 256, Rootfs: "python", Region: "eu"}, hosts); err != nil {
		t.Fatalf("legacy host should satisfy any rootfs: %v", err)
	}
}

func TestPipeline_capacityAndMaxVMs(t *testing.T) {
	hosts := []models.Host{
		active("small", 128, 0, 0, 0, "python"),
		active("full", 4096, 0, 5, 5, "python"),
		active("ok", 4096, 0, 0, 10, "python"),
	}
	p := pipelineNoReserver(t)
	d, err := p.Schedule(context.Background(), "sb_test", &framework.Request{MemMiB: 256, Rootfs: "python", Region: "eu"}, hosts)
	if err != nil {
		t.Fatal(err)
	}
	if d.HostID != "ok" {
		t.Fatalf("expected ok, got %s", d.HostID)
	}
}

func TestLabelSelectorFilter(t *testing.T) {
	gpuHost := models.Host{ID: "gpu-1", Status: "active", MemCapacityMib: 4096,
		Labels: map[string]string{"gpu": "l4", "region": "nyc1"}}
	plain := models.Host{ID: "plain", Status: "active", MemCapacityMib: 4096}

	cases := []struct {
		name     string
		req      framework.Request
		host     models.Host
		wantPass bool
	}{
		{"empty selector matches any", framework.Request{}, plain, true},
		{"empty selector matches labeled host", framework.Request{}, gpuHost, true},
		{"single label match", framework.Request{Labels: map[string]string{"gpu": "l4"}}, gpuHost, true},
		{"single label miss", framework.Request{Labels: map[string]string{"gpu": "h100"}}, gpuHost, false},
		{"missing key on host", framework.Request{Labels: map[string]string{"gpu": "l4"}}, plain, false},
		{"multi-label all match", framework.Request{Labels: map[string]string{"gpu": "l4", "region": "nyc1"}}, gpuHost, true},
		{"multi-label one miss", framework.Request{Labels: map[string]string{"gpu": "l4", "region": "sfo1"}}, gpuHost, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, _ := (LabelSelectorFilter{}).Filter(&tc.req, &tc.host)
			if ok != tc.wantPass {
				t.Errorf("got pass=%v, want %v", ok, tc.wantPass)
			}
		})
	}
}

func TestStatusFilter_rejectsInactive(t *testing.T) {
	host := models.Host{ID: "draining", Status: "draining", MemCapacityMib: 4096}
	ok, reason := (StatusFilter{}).Filter(&framework.Request{}, &host)
	if ok {
		t.Errorf("expected reject")
	}
	if !strings.Contains(reason, "draining") {
		t.Errorf("reason = %q, want it to mention draining", reason)
	}
}

func TestHostPinFilter(t *testing.T) {
	hosts := []models.Host{
		active("a", 4096, 0, 0, 0, "python"),
		active("b", 4096, 0, 0, 0, "python"),
	}
	p := pipelineNoReserver(t)
	d, err := p.Schedule(context.Background(), "sb_test", &framework.Request{MemMiB: 256, Rootfs: "python", Region: "eu", HostID: "b"}, hosts)
	if err != nil {
		t.Fatal(err)
	}
	if d.HostID != "b" {
		t.Errorf("HostID = %q, want b", d.HostID)
	}
}

func TestHostPin_unknownReturnsNoCapacity(t *testing.T) {
	hosts := []models.Host{active("a", 4096, 0, 0, 0, "python")}
	p := pipelineNoReserver(t)
	_, err := p.Schedule(context.Background(), "sb_test", &framework.Request{MemMiB: 256, Region: "eu", HostID: "z"}, hosts)
	if !errors.Is(err, framework.ErrNoCapacity) {
		t.Errorf("err = %v, want ErrNoCapacity", err)
	}
}

func TestLeastUsedPctScorer_monotonic(t *testing.T) {
	low := active("low", 1000, 100, 0, 0)
	high := active("high", 1000, 800, 0, 0)
	sl := (LeastUsedPctScorer{}).Score(&framework.Request{}, &low)
	sh := (LeastUsedPctScorer{}).Score(&framework.Request{}, &high)
	if sl <= sh {
		t.Errorf("low(%d) should outscore high(%d)", sl, sh)
	}
}

func TestFewestVMsScorer_monotonic(t *testing.T) {
	q := active("q", 1000, 0, 1, 0)
	b := active("b", 1000, 0, 50, 0)
	if (FewestVMsScorer{}).Score(&framework.Request{}, &q) <= (FewestVMsScorer{}).Score(&framework.Request{}, &b) {
		t.Errorf("quieter host should outscore busier one")
	}
}

func TestPipeline_picksLeastUsedFirst(t *testing.T) {
	hosts := []models.Host{
		active("h-50pct", 1000, 500, 0, 0, "python"),
		active("h-10pct", 1000, 100, 0, 0, "python"),
		active("h-30pct", 1000, 300, 0, 0, "python"),
	}
	p := pipelineNoReserver(t)
	d, err := p.Schedule(context.Background(), "sb_test", &framework.Request{MemMiB: 100, Rootfs: "python", Region: "eu"}, hosts)
	if err != nil {
		t.Fatal(err)
	}
	if d.HostID != "h-10pct" {
		t.Errorf("HostID = %q, want h-10pct", d.HostID)
	}
}

func TestInMemReserver_reserveRelease(t *testing.T) {
	r := NewInMemReserver(0)
	defer r.Stop()
	h := active("a", 1000, 0, 0, 0)
	if err := r.Reserve(context.Background(), "sb_aaa", &framework.Request{MemMiB: 200}, &h); err != nil {
		t.Fatal(err)
	}
	snap := r.Snapshot()
	if snap["a"].UsedMib != 232 || snap["a"].VMCount != 1 {
		t.Errorf("snapshot after reserve = %+v", snap)
	}
	if err := r.Release(context.Background(), "sb_aaa"); err != nil {
		t.Fatal(err)
	}
	if got := r.Snapshot(); got["a"].UsedMib != 0 || got["a"].VMCount != 0 {
		t.Errorf("snapshot after release = %+v, want empty", got)
	}
}

func TestInMemReserver_overCapacityReturnsConflict(t *testing.T) {
	r := NewInMemReserver(0)
	defer r.Stop()
	h := active("a", 500, 400, 0, 0)
	err := r.Reserve(context.Background(), "sb_aaa", &framework.Request{MemMiB: 200}, &h)
	if !errors.Is(err, framework.ErrConflict) {
		t.Errorf("err = %v, want ErrConflict", err)
	}
}

func TestInMemReserver_maxVMsCap(t *testing.T) {
	r := NewInMemReserver(0)
	defer r.Stop()
	h := active("a", 5000, 0, 4, 5)
	if err := r.Reserve(context.Background(), "sb_aaa", &framework.Request{MemMiB: 100}, &h); err != nil {
		t.Fatalf("first reserve unexpectedly failed: %v", err)
	}
	if err := r.Reserve(context.Background(), "sb_bbb", &framework.Request{MemMiB: 100}, &h); !errors.Is(err, framework.ErrConflict) {
		t.Errorf("second reserve err = %v, want ErrConflict (would overshoot MaxVMs)", err)
	}
}

func TestInMemReserver_reconcileLive(t *testing.T) {
	r := NewInMemReserver(0)
	defer r.Stop()
	h := active("a", 1000, 0, 0, 0)
	_ = r.Reserve(context.Background(), "sb_aaa", &framework.Request{MemMiB: 200}, &h)
	// Hydrate sees sb_aaa in the live set → delta should drop it.
	r.Reconcile(nil, map[string]bool{"sb_aaa": true}, nil, time.Now().Add(-time.Hour))
	if got := r.Snapshot(); len(got) != 0 {
		t.Errorf("delta after reconcile-live = %+v, want empty", got)
	}
}

func TestInMemReserver_reconcileTerminated(t *testing.T) {
	r := NewInMemReserver(0)
	defer r.Stop()
	h := active("a", 1000, 0, 0, 0)
	_ = r.Reserve(context.Background(), "sb_aaa", &framework.Request{MemMiB: 200}, &h)
	r.Reconcile(nil, nil, map[string]bool{"sb_aaa": true}, time.Now().Add(-time.Hour))
	if got := r.Snapshot(); len(got) != 0 {
		t.Errorf("delta after reconcile-terminated = %+v, want empty", got)
	}
}

func TestInMemReserver_reconcileGrace(t *testing.T) {
	r := NewInMemReserver(0)
	defer r.Stop()
	h := active("a", 1000, 0, 0, 0)
	_ = r.Reserve(context.Background(), "sb_aaa", &framework.Request{MemMiB: 200}, &h)
	// reservedAt is "now"; cutoff in the past → keeps entry.
	r.Reconcile(nil, nil, nil, time.Now().Add(-time.Hour))
	if got := r.Snapshot(); got["a"].UsedMib != 232 {
		t.Errorf("delta should still have entry, got %+v", got)
	}
	// cutoff in the future → drops entry.
	r.Reconcile(nil, nil, nil, time.Now().Add(time.Hour))
	if got := r.Snapshot(); len(got) != 0 {
		t.Errorf("delta after grace expiry = %+v, want empty", got)
	}
}

func TestInMemReserver_pendingIDs(t *testing.T) {
	r := NewInMemReserver(0)
	defer r.Stop()
	h := active("a", 1000, 0, 0, 0)
	_ = r.Reserve(context.Background(), "sb_aaa", &framework.Request{MemMiB: 100}, &h)
	_ = r.Reserve(context.Background(), "sb_bbb", &framework.Request{MemMiB: 100}, &h)
	ids := r.PendingIDs()
	if len(ids) != 2 {
		t.Errorf("PendingIDs len = %d, want 2 (got %v)", len(ids), ids)
	}
}

func TestRegisterBuiltins_buildsDefaultPipeline(t *testing.T) {
	reg := framework.NewRegistry()
	RegisterBuiltins(reg, 0)
	p, err := reg.BuildPipeline(DefaultPipelineSpec())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Filters) != 12 || len(p.Scorers) != 8 || p.Reserver == nil {
		t.Errorf("default pipeline shape wrong: filters=%d scorers=%d reserver=%v",
			len(p.Filters), len(p.Scorers), p.Reserver)
	}
	// Stop the reserver to free its sweeper goroutine.
	if r, ok := p.Reserver.(*InMemReserver); ok {
		r.Stop()
	}
}

func TestSnapshotCacheCannotBypassPlacementFilters(t *testing.T) {
	for _, mode := range []string{"capacity", "region", "cordon", "vendor", "host_pin"} {
		t.Run(mode, func(t *testing.T) {
			cached := active("cached", 4096, 0, 0, 100, "image")
			other := active("other", 4096, 0, 0, 100, "image")
			cached.CPUVendor, other.CPUVendor = "GenuineIntel", "GenuineIntel"
			cached.CachedSnapshots = []proto.CachedSnapshot{{ID: "snapshot", ExpiresAt: time.Now().Add(time.Minute)}}
			req := &framework.Request{SnapshotID: "snapshot", MemMiB: 512, Rootfs: "image", Region: "eu", SourceCPUVendor: "GenuineIntel"}
			switch mode {
			case "capacity":
				cached.InUseMib = 4096
			case "region":
				cached.Region = "us"
			case "cordon":
				cached.SchedulingDisabled = true
			case "vendor":
				cached.CPUVendor = "AuthenticAMD"
			case "host_pin":
				req.HostID = "other"
			}
			p := pipelineNoReserver(t)
			d, err := p.Schedule(context.Background(), "test", req, []models.Host{cached, other})
			if err != nil {
				t.Fatal(err)
			}
			if d.HostID != "other" {
				t.Fatalf("cache bypassed %s filter", mode)
			}
		})
	}
}

func TestStatusFilterHeartbeatFreshness(t *testing.T) {
	for _, tc := range []struct {
		name string
		seen time.Time
		want bool
	}{
		{"fresh", time.Now().Add(-5 * time.Second), true},
		{"stale active host", time.Now().Add(-models.HostHeartbeatStaleAfter - time.Second), false},
		{"missing", time.Time{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := active("host", 4096, 0, 0, 100)
			h.LastSeen = tc.seen
			pass, reason := (StatusFilter{}).Filter(&framework.Request{}, &h)
			if pass != tc.want {
				t.Fatalf("pass=%v reason=%s", pass, reason)
			}
			if !pass && !strings.Contains(reason, "heartbeat") {
				t.Fatalf("missing heartbeat reason: %s", reason)
			}
		})
	}
}

func TestPipelineRejectsStaleActiveHost(t *testing.T) {
	p := pipelineNoReserver(t)
	stale := active("stale", 4096, 0, 0, 100)
	stale.LastSeen = time.Now().Add(-2 * models.HostHeartbeatStaleAfter)
	fresh := active("fresh", 4096, 0, 0, 100)
	req := &framework.Request{Region: "eu", MemMiB: 256, PreferredHostIDs: []string{"stale"}}
	d, err := p.Schedule(context.Background(), "test", req, []models.Host{stale, fresh})
	if err != nil || d.HostID != "fresh" {
		t.Fatalf("decision=%v error=%v", d, err)
	}
	req.HostID = "stale"
	if _, err = p.Schedule(context.Background(), "test", req, []models.Host{stale, fresh}); !errors.Is(err, framework.ErrNoCapacity) {
		t.Fatalf("pinned stale host: %v", err)
	}
	req.HostID = ""
	if _, err = p.Schedule(context.Background(), "test", req, []models.Host{stale}); !errors.Is(err, framework.ErrNoCapacity) {
		t.Fatalf("all stale: %v", err)
	}
	// A newly received heartbeat makes the same active host eligible again.
	stale.LastSeen = time.Now()
	if _, err = p.Schedule(context.Background(), "test", req, []models.Host{stale}); err != nil {
		t.Fatal(err)
	}
}
