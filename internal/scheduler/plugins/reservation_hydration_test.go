package plugins

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/createos-sandbox/models"
)

func TestAuditHydrationStaleSnapshot(t *testing.T) {
	ctx := context.Background()
	req := &framework.Request{MemMiB: 600}
	for _, tc := range []struct {
		name             string
		capacity, maxVMs int
	}{
		{"VM limit", 10000, 1}, {"memory limit", 1000, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := NewInMemReserver(0)
			old := models.Host{ID: "disposable-host", MemCapacityMib: tc.capacity, MaxVMs: tc.maxVMs}
			if err := r.Reserve(ctx, "a", req, &old); err != nil {
				t.Fatal(err)
			}
			// A concurrent Schedule has copied old; hydration has not published new yet.
			copied := old
			if err := r.Reserve(ctx, "before", req, &copied); !errors.Is(err, framework.ErrConflict) {
				t.Fatalf("control: pending reservation must reject: %v", err)
			}
			// Hydration observes A in its durable sum and drops A's pending delta.
			freshUsage := old
			freshUsage.VMCount = 1
			freshUsage.InUseMib = req.ReservedMemoryMiB()
			r.Reconcile(map[string]models.Host{old.ID: freshUsage}, map[string]bool{"a": true}, nil, time.Now().Add(-time.Hour))
			err := r.Reserve(ctx, "b", req, &copied)
			t.Logf("after reconcile: second reservation error=%v; actual commitments=2 VMs, %d MiB; limit=%d VMs/%d MiB", err, 2*req.ReservedMemoryMiB(), tc.maxVMs, tc.capacity)
			if err == nil {
				t.Error("over-admission: stale snapshot accepted a second VM")
			}
			if err := r.Release(ctx, "b"); err != nil {
				t.Fatal(err)
			}
			fresh := old
			fresh.VMCount = 1
			fresh.InUseMib = req.ReservedMemoryMiB()
			if err := r.Reserve(ctx, "fresh", req, &fresh); !errors.Is(err, framework.ErrConflict) {
				t.Fatalf("control: updated snapshot must reject: %v", err)
			}
			t.Log("positive controls: pending delta and updated host snapshot both reject")
		})
	}
}

func TestAdmissionUsesPublishedHost(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		host models.Host
		req  framework.Request
	}{
		{"CPU", models.Host{CPUCount: 1, CPUOvercommitX10: 10, VCPUInUse: 1}, framework.Request{VCPU: 1}},
		{"disk", models.Host{DiskTotalMib: 1000, DiskOvercommitX10: 10, DiskInUseMib: 800}, framework.Request{DiskMiB: 600}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := NewInMemReserver(0)
			stale := models.Host{ID: "h", MemCapacityMib: 10000}
			latest := tc.host
			latest.ID = "h"
			latest.MemCapacityMib = 10000
			hosts := map[string]models.Host{"h": latest}
			r.Reconcile(hosts, nil, nil, time.Now().Add(-time.Hour))
			// Caller mutations must not change the owned admission view.
			hosts["h"] = stale
			if err := r.Reserve(ctx, "b", &tc.req, &stale); !errors.Is(err, framework.ErrConflict) {
				t.Fatalf("stale admission=%v", err)
			}
			r.Reconcile(map[string]models.Host{}, nil, nil, time.Now().Add(-time.Hour))
			if err := r.Reserve(ctx, "b", &tc.req, &stale); !errors.Is(err, framework.ErrConflict) {
				t.Fatalf("removed host admission=%v", err)
			}
		})
	}
}

func TestAdmissionDuringHydration(t *testing.T) {
	r := NewInMemReserver(0)
	stale := models.Host{ID: "h", MemCapacityMib: 10000, MaxVMs: 1}
	latest := stale
	latest.VMCount = 1
	hosts := map[string]models.Host{"h": latest}
	live := map[string]bool{"a": true}
	r.Reconcile(hosts, live, nil, time.Now().Add(-time.Hour))
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			r.Reconcile(hosts, live, nil, time.Now().Add(-time.Hour))
		}
	}()
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				if err := r.Reserve(context.Background(), "b", &framework.Request{MemMiB: 600}, &stale); !errors.Is(err, framework.ErrConflict) {
					t.Errorf("over-admission during hydration: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestHydratedAdmissionFallbackAndPolicy(t *testing.T) {
	for _, mode := range []string{"full preferred", "removed preferred", "hard pin", "all exhausted", "release reuse"} {
		t.Run(mode, func(t *testing.T) {
			p := defaultPipeline(t)
			r := p.Reserver.(*InMemReserver)
			a := active("a", 4096, 0, 0, 1, "image")
			b := active("b", 4096, 0, 0, 1, "image")
			stale := []models.Host{a, b}
			a.VMCount = 1
			current := map[string]models.Host{"a": a, "b": b}
			req := &framework.Request{MemMiB: 512, Rootfs: "image", Region: "eu", PreferredHostIDs: []string{"a"}}
			switch mode {
			case "removed preferred":
				delete(current, "a")
			case "hard pin":
				req.HostID = "a"
			case "all exhausted":
				b.VMCount = 1
				current["b"] = b
			}
			r.Reconcile(current, nil, nil, time.Now().Add(-time.Hour))
			decision, err := p.Schedule(context.Background(), "first", req, stale)
			if mode == "hard pin" || mode == "all exhausted" {
				if !errors.Is(err, framework.ErrNoCapacity) {
					t.Fatalf("want no capacity, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if decision.HostID != "b" {
				t.Fatalf("fallback selected %s", decision.HostID)
			}
			if mode == "release reuse" {
				if _, err = p.Schedule(context.Background(), "second", req, stale); !errors.Is(err, framework.ErrNoCapacity) {
					t.Fatalf("full host accepted another: %v", err)
				}
				if err = r.Release(context.Background(), "first"); err != nil {
					t.Fatal(err)
				}
				if _, err = p.Schedule(context.Background(), "second", req, stale); err != nil {
					t.Fatalf("released capacity not reusable: %v", err)
				}
			}
		})
	}
}
