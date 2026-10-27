// Per-sandbox 1-hour metrics ring buffer, disk-backed.
//
// Each scraper tick appends one JSON line to
//   <runtime>/<sb>/metrics.jsonl
// (the same per-VM dir that already holds fc.sock, vsock.uds etc.
// — mode 0700 slot-uid, so no cross-tenant read; wiped automatically
// when Manager.Destroy removes the runtime dir).
//
// Why disk and not RAM: the machine host process's RSS stays flat
// as VMs come and go. A busy host with 500 VMs would otherwise carry
// ~25 MB of ring state in-process; here it's just 25 MB of small
// files under /var/lib/createos/runtime. The kernel page cache still
// keeps hot files fast; nothing counts against createos's cgroup.
//
// Not persistent by design: rings die with the VM.
//
// Rotation strategy: append every tick; every N ticks (~10 min at
// 10s cadence), rewrite the file with only the last RingCapacity
// lines. Bounded file size = RingCapacity × ~200 B ≈ 72 KB per VM.
//
// Read path (API): os.ReadFile → split by \n → JSON-unmarshal each.
// ~72 KB per request, unmarshal ~20 µs — well under the network cost.

package metrics

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	RingBucketInterval = 10 * time.Second
	RingWindow         = 1 * time.Hour
	RingCapacity       = int(RingWindow / RingBucketInterval) // 360

	metricsFileName = "metrics.jsonl"
	// Rotate lazily to bound the file at ~2× capacity worst-case. Every
	// rotateEvery appends, rewrite the file with only the last
	// RingCapacity lines. Cheap (~72 KB rewrite) at 10-minute cadence.
	rotateEvery = 60
)

// MetricPoint is one sample. All fields optional — zero means
// "unknown" (scraper couldn't read that cgroup file / VM lacks that
// dimension).
type MetricPoint struct {
	Ts                   time.Time `json:"ts"`
	CPUCoresUsed         float64   `json:"cpu_cores_used"`
	CPUPerCore           []float64 `json:"cpu_per_core,omitempty"`
	MemoryBytes          uint64    `json:"memory_bytes"`            // host-side cgroup anon
	MemoryUsedGuestBytes uint64    `json:"memory_used_guest_bytes"` // guest /proc/meminfo, `free -m used`
	MemoryLimitBytes     uint64    `json:"memory_limit_bytes"`
	NetBytesInRate       float64   `json:"net_bytes_in_per_sec"`
	NetBytesOutRate      float64   `json:"net_bytes_out_per_sec"`
	StorageBytes         uint64    `json:"storage_bytes"`
	StorageLimit         uint64    `json:"storage_limit_bytes"`
}

// tickCounter tracks how many appends we've made per sandbox so the
// scraper knows when to trigger rotation. Only load-bearing state kept
// in-process; ~8 bytes/VM.
var (
	tickMu       sync.Mutex
	tickCounters = make(map[string]int, 64)
)

// runtimeDirBase is the resolved host runtime root. It is kept here (rather
// than importing internal/hosts/vm) to avoid a
// package cycle: vm/manager.go already imports metrics for the
// Prometheus counters.
var runtimeDirBase = "/var/lib/createos/runtime"

// SetRuntimeDir installs the resolved host runtime directory before metrics
// collection starts.
func SetRuntimeDir(dir string) {
	if dir != "" {
		runtimeDirBase = dir
	}
}

// metricsPath returns the JSONL file path for one sandbox. Lives in
// the per-VM runtime dir so it inherits the 0700 slot-uid ACL and
// gets cleaned up automatically when the dir is wiped on destroy.
func metricsPath(id string) string {
	return filepath.Join(runtimeDirBase, id, metricsFileName)
}

// ringAppend serialises the point to JSON and appends one line to
// the sandbox's metrics file. Rotates every rotateEvery appends.
func ringAppend(id string, p MetricPoint) {
	line, err := json.Marshal(p)
	if err != nil {
		log.Debugf("[metrics] %s marshal: %v", id, err)
		return
	}
	path := metricsPath(id)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		log.Debugf("[metrics] %s open %s: %v", id, path, err)
		return
	}
	line = append(line, '\n')
	if _, err := f.Write(line); err != nil {
		log.Debugf("[metrics] %s write: %v", id, err)
	}
	_ = f.Close()

	tickMu.Lock()
	tickCounters[id]++
	shouldRotate := tickCounters[id] >= rotateEvery
	if shouldRotate {
		tickCounters[id] = 0
	}
	tickMu.Unlock()
	if shouldRotate {
		rotateMetricsFile(id, path)
	}
}

// ringDrop clears the tick counter when a sandbox goes away. The file
// itself lives inside the runtime dir that Manager.Destroy wipes, so
// we don't need to unlink it explicitly.
func ringDrop(id string) {
	tickMu.Lock()
	delete(tickCounters, id)
	tickMu.Unlock()
}

// rotateMetricsFile trims the JSONL file down to at most RingCapacity
// lines. Best-effort: on any error we leave the file as-is; next
// rotation will retry. Concurrency: at most one rotation runs per
// sandbox because the tick counter reset happens under tickMu.
func rotateMetricsFile(id, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	if len(lines) <= RingCapacity {
		return
	}
	keep := lines[len(lines)-RingCapacity:]
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return
	}
	w := bufio.NewWriter(f)
	for _, ln := range keep {
		_, _ = w.Write(ln)
		_ = w.WriteByte('\n')
	}
	_ = w.Flush()
	_ = f.Close()
	if err := os.Rename(tmp, path); err != nil {
		log.Debugf("[metrics] %s rotate rename: %v", id, err)
		_ = os.Remove(tmp)
	}
}

// SandboxTimeseries reads the JSONL file and returns the last
// RingCapacity buckets in chronological order (oldest first). Nil
// slice = file doesn't exist yet or the sandbox isn't on this host.
func SandboxTimeseries(id string) []MetricPoint {
	data, err := os.ReadFile(metricsPath(id))
	if err != nil {
		return nil
	}
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	// Only the trailing RingCapacity lines are within the 1-hour window;
	// earlier lines exist between rotations but must not be surfaced.
	if len(lines) > RingCapacity {
		lines = lines[len(lines)-RingCapacity:]
	}
	out := make([]MetricPoint, 0, len(lines))
	for _, ln := range lines {
		if len(ln) == 0 {
			continue
		}
		var p MetricPoint
		if err := json.Unmarshal(ln, &p); err != nil {
			continue
		}
		out = append(out, p)
	}
	return out
}
