// Per-sandbox on-demand resource snapshot.
//
// Sibling to cgroup_scraper.go. The scraper feeds Prometheus on a tick;
// SandboxSnapshot reads the same cgroup files synchronously for one VM
// and returns a struct shaped for the user-facing API.
//
// CPU-rate accuracy: the scraper writes (usec, ts) into a small per-id
// sample map after each tick. The snapshot reader prefers the last two
// samples (15-30s window) so the call returns instantly. If only one
// sample exists (sandbox <15s old, or scraper hasn't ticked yet), the
// reader falls back to live sample-sleep-sample over ~100ms.
package metrics

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SandboxSnapshot is the on-demand per-sandbox resource view returned
// by the host API. Field zero-values are meaningful: MemoryLimitBytes=0
// means "unlimited" (cgroup memory.max == "max"); CPUPctOfAlloc=0 with
// CPUCoresAllocated=0 means the VM has no CPU quota (uncapped).
type SandboxSnapshot struct {
	SandboxID            string    `json:"sandbox_id"`
	MemoryBytes          uint64    `json:"memory_bytes"`            // host-side cgroup anon
	MemoryUsedGuestBytes uint64    `json:"memory_used_guest_bytes"` // guest `free -m used`; 0 = agent unreachable
	MemoryLimitBytes     uint64    `json:"memory_limit_bytes"`      // 0 = unlimited
	MemoryPct            float64   `json:"memory_pct"`              // 0 when no limit
	CPUCoresUsed         float64   `json:"cpu_cores_used"`          // avg over window
	CPUCoresAllocated    float64   `json:"cpu_cores_allocated"`     // from cpu.max; 0 = unlimited
	CPUPct               float64   `json:"cpu_pct"`                 // 0 when no quota
	AsOf                 time.Time `json:"as_of"`
}

// cpuSample is a single (usec, ts) reading from cpu.stat.
type cpuSample struct {
	usec uint64
	ts   time.Time
}

// cpuHistory keeps the last 2 samples per sandbox so SandboxSnapshot can
// compute a rate without sleeping. The scraper appends on every tick;
// SandboxSnapshot reads with no lock contention because the read path
// only touches one map key.
var (
	cpuHistMu sync.RWMutex
	cpuHist   = make(map[string][2]cpuSample, 64) // [prev, latest]
)

// putCPUSample is called by the scraper after reading cpu.stat. Returns
// (prev_usec, prev_ts, had_prev) so the existing counter-Add logic in
// the scraper still gets its delta.
func putCPUSample(id string, usec uint64) (uint64, time.Time, bool) {
	now := time.Now()
	cpuHistMu.Lock()
	defer cpuHistMu.Unlock()
	cur, ok := cpuHist[id]
	if !ok {
		cpuHist[id] = [2]cpuSample{{}, {usec: usec, ts: now}}
		return 0, time.Time{}, false
	}
	prev := cur[1]
	cpuHist[id] = [2]cpuSample{prev, {usec: usec, ts: now}}
	return prev.usec, prev.ts, prev.ts != time.Time{}
}

// dropCPUSample evicts a sandbox's history when the scraper notices it
// went away. Keeps the map bounded by live count.
func dropCPUSample(id string) {
	cpuHistMu.Lock()
	delete(cpuHist, id)
	cpuHistMu.Unlock()
}

// ReadSandboxSnapshot reads the cgroup files for one sandbox and returns
// the on-demand view. Returns an error if the VM's cgroup root is
// missing (sandbox not on this host, or just torn down).
func ReadSandboxSnapshot(id string) (*SandboxSnapshot, error) {
	dir := filepath.Join(cgRootPath, id)
	// Prefer memory.stat's "anon" (guest workload memory) over
	// memory.current so the snapshot matches what the tenant sees
	// inside their VM's `free`/`top`. memory.current would include
	// page cache and drift toward 100% on any long-running VM.
	mem, ok := readMemStatField(filepath.Join(dir, "memory.stat"), "anon")
	if !ok {
		if mem, ok = readUint(filepath.Join(dir, "memory.current")); !ok {
			return nil, fmt.Errorf("sandbox %s: cgroup not found", id)
		}
	}
	limFloat, limOk := readMaxOrInf(filepath.Join(dir, "memory.max"))
	var lim uint64
	if limOk {
		lim = uint64(limFloat)
	}
	memPct := 0.0
	if lim > 0 {
		memPct = float64(mem) / float64(lim) * 100
	}

	coresUsed, _ := sandboxCPUCoresUsed(id, dir)
	// Allocation denominator: prefer the cgroup CPU quota (cpu.max) when
	// the shape sets one (fractional-vcpu shapes like s-0.5vcpu-*). Fall
	// back to the guest's vCPU count for full-vcpu shapes whose cpu.max
	// reads "max" (no host-side throttle). The fallback gives users a
	// meaningful cpu_pct even when no quota is enforced.
	allocCores := readCPUMaxCores(filepath.Join(dir, "cpu.max"))
	if allocCores == 0 && listerRef != nil {
		if vcpu, ok := listerRef.SandboxVCPU(id); ok && vcpu > 0 {
			allocCores = float64(vcpu)
		}
	}
	cpuPct := 0.0
	if allocCores > 0 {
		cpuPct = (coresUsed / allocCores) * 100
	}

	// Guest-side used bytes — cached in vm/, cheap. Zero on miss is
	// meaningful ("agent unreachable or VM too young").
	var guestUsed uint64
	if lister, ok := listerRef.(interface {
		SandboxGuestMemUsedBytes(id string) (uint64, bool)
	}); ok {
		if u, ok := lister.SandboxGuestMemUsedBytes(id); ok {
			guestUsed = u
		}
	}
	return &SandboxSnapshot{
		SandboxID:            id,
		MemoryBytes:          mem,
		MemoryUsedGuestBytes: guestUsed,
		MemoryLimitBytes:     lim,
		MemoryPct:            memPct,
		CPUCoresUsed:         coresUsed,
		CPUCoresAllocated:    allocCores,
		CPUPct:               cpuPct,
		AsOf:                 time.Now().UTC(),
	}, nil
}

// sandboxCPUCoresUsed returns the instantaneous CPU consumption in
// fractional cores. Prefers the scraper's pre-recorded history (zero
// latency); falls back to a live ~100ms sample-sleep-sample if history
// has fewer than 2 samples.
func sandboxCPUCoresUsed(id, dir string) (float64, error) {
	cpuHistMu.RLock()
	h, ok := cpuHist[id]
	cpuHistMu.RUnlock()
	if ok && !h[0].ts.IsZero() && !h[1].ts.IsZero() {
		dt := h[1].ts.Sub(h[0].ts).Seconds()
		if dt > 0 && h[1].usec >= h[0].usec {
			deltaCPU := float64(h[1].usec-h[0].usec) / 1_000_000
			return deltaCPU / dt, nil
		}
	}
	// Live fallback — first call before scraper has 2 ticks.
	statPath := filepath.Join(dir, "cpu.stat")
	a, ok := readCPUUsageUsec(statPath)
	if !ok {
		return 0, nil
	}
	t0 := time.Now()
	time.Sleep(100 * time.Millisecond)
	b, ok := readCPUUsageUsec(statPath)
	if !ok || b < a {
		return 0, nil
	}
	dt := time.Since(t0).Seconds()
	return (float64(b-a) / 1_000_000) / dt, nil
}

// readCPUMaxCores parses cgroup v2 cpu.max ("<quota_us> <period_us>" or
// "max <period_us>") and returns the allocation as fractional cores.
// Returns 0 on "max" (no quota) or any parse error — callers compute
// cpu_pct only when allocation > 0.
func readCPUMaxCores(path string) float64 {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	fields := strings.Fields(strings.TrimSpace(string(raw)))
	if len(fields) < 2 || fields[0] == "max" {
		return 0
	}
	var quota, period float64
	if _, err := fmt.Sscanf(fields[0], "%f", &quota); err != nil || quota <= 0 {
		return 0
	}
	if _, err := fmt.Sscanf(fields[1], "%f", &period); err != nil || period <= 0 {
		return 0
	}
	return quota / period
}
