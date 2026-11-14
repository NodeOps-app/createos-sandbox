package plugins

import (
	"testing"

	"github.com/NodeOps-app/createos-sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// Shared makeHost is in balanced_alloc_test.go.

// TestBestFit_small_request_neutral: a small request (under 20% of any
// host dim) should score neutral (50) so balanced_alloc decides which
// host to land on. Best-fit only matters for big requests.
func TestBestFit_small_request_neutral(t *testing.T) {
	h := makeHost("h", 12, 30, 122880, 60000, 958067, 400000)
	req := &framework.Request{VCPU: 1, MemMiB: 1024, DiskMiB: 10240} // ~0.8% mem, 1% cpu, 1% disk
	score := (BestFitScorer{}).Score(req, h)
	if score != 50 {
		t.Errorf("small request should score neutral (50), got %d", score)
	}
}

// TestBestFit_big_memory_request_prefers_tight_fit: a 80 GiB memory
// request fits ON BOTH hosts. Best-fit should prefer the one that
// leaves a smaller gap.
//
// Host A: 30 GiB used → leaves 120 - 30 - 80 = 10 GiB free  → tighter fit → higher score
// Host B: 5 GiB used  → leaves 120 -  5 - 80 = 35 GiB free  → looser fit → lower score
func TestBestFit_big_memory_request_prefers_tight_fit(t *testing.T) {
	hA := makeHost("a", 12, 10, 122880, 30720, 958067, 100000)           // 25% mem used
	hB := makeHost("b", 12, 10, 122880, 5120, 958067, 100000)            // 4% mem used
	bigReq := &framework.Request{VCPU: 1, MemMiB: 81920, DiskMiB: 10240} // 67% mem
	sA := (BestFitScorer{}).Score(bigReq, hA)
	sB := (BestFitScorer{}).Score(bigReq, hB)
	if sA <= sB {
		t.Errorf("tighter-fit host should score higher: A=%d B=%d", sA, sB)
	}
}

// TestBestFit_wouldnt_fit_returns_zero: if the request wouldn't fit on
// this host (admission would reject anyway), return 0 — defensive.
func TestBestFit_wouldnt_fit_returns_zero(t *testing.T) {
	h := makeHost("h", 12, 10, 122880, 100000, 958067, 100000)           // 80% mem used
	bigReq := &framework.Request{VCPU: 1, MemMiB: 40000, DiskMiB: 10240} // wouldn't fit
	if got := (BestFitScorer{}).Score(bigReq, h); got != 0 {
		t.Errorf("won't-fit should return 0, got %d", got)
	}
}

// TestBestFit_big_disk_request: a disk-heavy request that crosses the
// 20% threshold should be steered by disk best-fit. Disk limit on the
// test host is 958067×2.0 = 1916134 MiB, so we need req ≥ 383 GiB for
// the disk dim to count as "big".
func TestBestFit_big_disk_request(t *testing.T) {
	hLooseDisk := makeHost("loose", 12, 10, 122880, 1024, 958067, 100000)        // 5% disk used
	hTightDisk := makeHost("tight", 12, 10, 122880, 1024, 958067, 1400000)       // 73% disk used
	bigDiskReq := &framework.Request{VCPU: 1, MemMiB: 1024, DiskMiB: 500 * 1024} // 500 GiB disk = 26% of limit
	sLoose := (BestFitScorer{}).Score(bigDiskReq, hLooseDisk)
	sTight := (BestFitScorer{}).Score(bigDiskReq, hTightDisk)
	if sTight <= sLoose {
		t.Errorf("tight-disk host should outscore loose for big disk req: tight=%d loose=%d", sTight, sLoose)
	}
}

// TestBestFit_big_cpu_request: similar test for CPU dim.
func TestBestFit_big_cpu_request(t *testing.T) {
	// limit = 12 × 8.0 = 96
	hLooseCPU := makeHost("loose", 12, 5, 122880, 4000, 958067, 100000)     // 5/96 = 5%
	hTightCPU := makeHost("tight", 12, 50, 122880, 4000, 958067, 100000)    // 50/96 = 52%
	bigCpuReq := &framework.Request{VCPU: 30, MemMiB: 1024, DiskMiB: 10240} // 30 vCPU = 31% of cap
	sLoose := (BestFitScorer{}).Score(bigCpuReq, hLooseCPU)
	sTight := (BestFitScorer{}).Score(bigCpuReq, hTightCPU)
	if sTight <= sLoose {
		t.Errorf("tight-cpu host should outscore loose for big cpu req: tight=%d loose=%d", sTight, sLoose)
	}
}

// TestBestFit_request_big_in_one_dim_uses_that_binder: a request that's
// big in only one dimension should score by that dimension's fit, not
// neutral. (Earlier "big" threshold check must trigger per-dim.)
func TestBestFit_request_big_in_one_dim_uses_that_binder(t *testing.T) {
	// Request: tiny CPU/disk but huge memory (50% of cap)
	bigMemReq := &framework.Request{VCPU: 1, MemMiB: 61440, DiskMiB: 10240}
	hTight := makeHost("tight", 12, 5, 122880, 40000, 958067, 100000) // 33% mem used, fits 50% req tightly
	hLoose := makeHost("loose", 12, 5, 122880, 5000, 958067, 100000)  //  4% mem used, fits with lots of slack
	sTight := (BestFitScorer{}).Score(bigMemReq, hTight)
	sLoose := (BestFitScorer{}).Score(bigMemReq, hLoose)
	if sTight <= sLoose {
		t.Errorf("tight mem fit should outscore loose: tight=%d loose=%d", sTight, sLoose)
	}
}

// TestBestFit_legacy_host_compat: a host without CPU/disk fields
// (CPUCount=0, DiskTotalMib=0) falls back to memory-only best-fit.
func TestBestFit_legacy_host_compat(t *testing.T) {
	h := makeHost("legacy", 0, 0, 122880, 30000, 0, 0)
	bigReq := &framework.Request{VCPU: 1, MemMiB: 81920, DiskMiB: 10240}
	score := (BestFitScorer{}).Score(bigReq, h)
	if score < 50 {
		t.Errorf("legacy host should still score the mem dim fit, got %d", score)
	}
}

// TestBestFit_zero_safety: misconfigured host with capacity=0 returns
// 0 (defensive).
func TestBestFit_zero_safety(t *testing.T) {
	h := &models.Host{ID: "bad"}
	req := &framework.Request{VCPU: 1, MemMiB: 1024}
	if got := (BestFitScorer{}).Score(req, h); got != 0 {
		t.Errorf("zero host should be safe-0, got %d", got)
	}
}

// TestBestFit_score_increases_with_tightness: as the gap shrinks, score
// should grow monotonically.
func TestBestFit_score_increases_with_tightness(t *testing.T) {
	bigReq := &framework.Request{VCPU: 1, MemMiB: 61440, DiskMiB: 10240} // 50% mem
	prev := -1
	for memUsed := 0; memUsed <= 50000; memUsed += 10000 {
		h := makeHost("h", 12, 5, 122880, memUsed, 958067, 100000)
		score := (BestFitScorer{}).Score(bigReq, h)
		if score < prev {
			t.Errorf("score should increase as host fills (req+fit gets tighter): used=%d score=%d prev=%d", memUsed, score, prev)
		}
		prev = score
	}
}
