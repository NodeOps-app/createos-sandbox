package plugins

import (
	"testing"

	"github.com/NodeOps-app/createos-sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// Test fixture for a host with full dimension config. Defaults match
// the cluster's typical "8× cpu, 1× mem, 2× disk" oversub.
func makeHost(id string, cpuCount, cpuUsed int, memMib, memUsed int, diskMib, diskUsed int64) *models.Host {
	return &models.Host{
		ID:                id,
		Status:            models.HostStatusActive,
		CPUCount:          cpuCount,
		VCPUInUse:         cpuUsed,
		CPUOvercommitX10:  80, // 8.0×
		MemCapacityMib:    memMib,
		InUseMib:          memUsed,
		MemOvercommitX10:  10, // 1.0×
		DiskTotalMib:      diskMib,
		DiskInUseMib:      diskUsed,
		DiskOvercommitX10: 20, // 2.0×
	}
}

// TestBalanced_emptyHosts_score: a fresh host with no commitments gets
// the maximum score for any reasonable request.
func TestBalanced_emptyHosts_score(t *testing.T) {
	h := makeHost("h", 12, 0, 122880, 0, 958067, 0)
	req := &framework.Request{VCPU: 1, MemMiB: 1024, DiskMiB: 10240}
	score := (BalancedAllocScorer{}).Score(req, h)
	if score < 95 || score > 100 {
		t.Errorf("empty host should score near 100, got %d", score)
	}
}

// TestBalanced_picks_least_stressed_binder: given two hosts where one
// has 90% CPU committed and the other has 30% CPU committed (all other
// dims equal), the scorer prefers the less-stressed one.
func TestBalanced_picks_least_stressed_binder(t *testing.T) {
	// 12 cores × 8.0× = 96 vCPU limit
	hCPUHot := makeHost("hot", 12, 86, 122880, 8192, 958067, 102400)   // cpu 90%
	hCPUCold := makeHost("cold", 12, 29, 122880, 8192, 958067, 102400) // cpu 30%
	req := &framework.Request{VCPU: 1, MemMiB: 1024, DiskMiB: 10240}
	hotScore := (BalancedAllocScorer{}).Score(req, hCPUHot)
	coldScore := (BalancedAllocScorer{}).Score(req, hCPUCold)
	if hotScore >= coldScore {
		t.Errorf("cold host should outscore hot: hot=%d cold=%d", hotScore, coldScore)
	}
}

// TestBalanced_avoids_stranding_memory: two hosts, same CPU pressure,
// but host-A has nearly-full memory while host-B is empty on memory.
// A memory-light request should still prefer host-B because B has more
// total headroom (memory is what we want to drain).
//
// More importantly: a memory-HEAVY request must NOT go to host-A because
// post-placement memory util would peak there.
func TestBalanced_avoids_stranding_memory(t *testing.T) {
	hAMemFull := makeHost("a", 12, 10, 122880, 115000, 958067, 100000)
	hBMemFree := makeHost("b", 12, 10, 122880, 10000, 958067, 100000)
	bigMem := &framework.Request{VCPU: 1, MemMiB: 8000, DiskMiB: 10240}
	scoreA := (BalancedAllocScorer{}).Score(bigMem, hAMemFull)
	scoreB := (BalancedAllocScorer{}).Score(bigMem, hBMemFree)
	if scoreB <= scoreA {
		t.Errorf("memory-heavy req should prefer mem-free host: A=%d B=%d", scoreA, scoreB)
	}
}

// TestBalanced_dominant_resource: a host has 95% CPU used and 5% mem used.
// Score must reflect the BINDER (CPU at 95%), not the average (50%).
// Otherwise we'd happily place there until the CPU dimension hard-rejects
// at the admission filter.
func TestBalanced_dominant_resource(t *testing.T) {
	h := makeHost("h", 12, 91, 122880, 6144, 958067, 100000) // cpu 95%, mem 5%
	req := &framework.Request{VCPU: 1, MemMiB: 1024, DiskMiB: 10240}
	score := (BalancedAllocScorer{}).Score(req, h)
	// Post-placement CPU util = (91+1)/96 = 95.8%, score should reflect that.
	// score = 100 - 96 = 4 (approximately).
	if score > 10 {
		t.Errorf("near-full CPU should score low even when mem is mostly free, got %d", score)
	}
}

// TestBalanced_legacy_host_compat: a host that hasn't sent the new
// register fields (CPUCount=0, DiskTotalMib=0) still gets scored — falls
// back to memory-only logic, matching LeastUsedPctScorer behavior.
func TestBalanced_legacy_host_compat(t *testing.T) {
	h := makeHost("legacy", 0, 0, 122880, 61440, 0, 0) // 50% mem, no cpu/disk advertised
	req := &framework.Request{VCPU: 1, MemMiB: 1024, DiskMiB: 10240}
	score := (BalancedAllocScorer{}).Score(req, h)
	// Should be ~50 (close to LeastUsedPctScorer's 50 for the same host).
	if score < 40 || score > 60 {
		t.Errorf("legacy host should score by memory only, got %d (want ~50)", score)
	}
}

// TestBalanced_zero_request: a placeholder/probe request with no
// dimensions still scores hosts by current free space.
func TestBalanced_zero_request(t *testing.T) {
	hFree := makeHost("a", 12, 0, 122880, 0, 958067, 0)
	hBusy := makeHost("b", 12, 50, 122880, 80000, 958067, 800000)
	req := &framework.Request{}
	if (BalancedAllocScorer{}).Score(req, hFree) <= (BalancedAllocScorer{}).Score(req, hBusy) {
		t.Errorf("free host should outscore busy host even for empty request")
	}
}

// TestBalanced_zero_limit_safety: a misconfigured host with limit=0
// shouldn't divide-by-zero — return 0.
func TestBalanced_zero_limit_safety(t *testing.T) {
	h := &models.Host{ID: "bad"} // all zeros
	req := &framework.Request{VCPU: 1, MemMiB: 1024}
	if got := (BalancedAllocScorer{}).Score(req, h); got != 0 {
		t.Errorf("zero-everything host should score 0, got %d", got)
	}
}

// TestBalanced_monotonic_decrease: as a host fills toward its CPU
// binder, score should decrease monotonically.
func TestBalanced_monotonic_decrease(t *testing.T) {
	req := &framework.Request{VCPU: 1, MemMiB: 1024, DiskMiB: 10240}
	last := 101
	for cpuUsed := 0; cpuUsed <= 90; cpuUsed += 10 {
		h := makeHost("h", 12, cpuUsed, 122880, 0, 958067, 0)
		score := (BalancedAllocScorer{}).Score(req, h)
		if score > last {
			t.Errorf("score should decrease monotonically: cpu_used=%d score=%d > last=%d", cpuUsed, score, last)
		}
		last = score
	}
}

// TestBalanced_disk_binds: a tiny VM (1 vCPU, 256 MiB) requesting a
// huge disk (60 GiB) on a host where disk is the bound dim should
// score by the disk binder, not by CPU/mem. Disk limit = 958067 × 2.0×
// = 1,916,134 MiB; load disk to 95% of cap so post-placement util pegs
// the binder.
func TestBalanced_disk_binds(t *testing.T) {
	h := makeHost("h", 12, 5, 122880, 5000, 958067, 1820000) // disk 95% of 2.0× cap
	req := &framework.Request{VCPU: 1, MemMiB: 256, DiskMiB: 61440}
	score := (BalancedAllocScorer{}).Score(req, h)
	if score > 20 {
		t.Errorf("disk-binder host should score low for disk-heavy req, got %d", score)
	}
}
