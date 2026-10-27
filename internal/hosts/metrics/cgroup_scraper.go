// Per-sandbox cgroup scraper — walks /sys/fs/cgroup/createos/<id>/ on
// a tick, feeds Prometheus gauges + the ring buffer, drops series for
// gone sandboxes so cardinality tracks live count.
package metrics

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

// LiveSandboxLister is the subset of vm.Manager the scraper needs.
type LiveSandboxLister interface {
	LiveIDs() []string
	SandboxVCPU(id string) (int, bool)
	SandboxNetTotals(id string) (in, out uint64, ok bool)
	SandboxDiskMib(id string) (mib int64, overlayPath string, ok bool)
	SandboxGuestMemUsedBytes(id string) (uint64, bool)
	SandboxGuestStorage(id string) (used, total uint64, ok bool)
	DropGuestMemCache(id string)
}

// listerRef lets ReadSandboxSnapshot fall back to guest vCPU count when
// the cgroup has no CPU quota. Read-only after startup.
var listerRef LiveSandboxLister

const (
	cgRootPath        = "/sys/fs/cgroup/createos"
	cgroupScrapeEvery = RingBucketInterval
)

type netSample struct {
	in, out uint64
	ts      time.Time
}

var (
	netHistMu sync.Mutex
	netHist   = make(map[string]netSample, 64)
)

func ScrapeCgroupsLoop(ctx context.Context, lister LiveSandboxLister) {
	if lister == nil {
		log.WithContext(ctx).Warnf("[metrics] cgroup scraper started with nil lister; exiting")
		return
	}
	listerRef = lister

	knownIDs := make(map[string]struct{}, 64)
	rootMissing := false

	t := time.NewTicker(cgroupScrapeEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// On a clean host the createos cgroup root does not exist until
			// the first VM is created. Keep the scraper alive across that
			// normal startup state instead of disabling metrics permanently.
			if _, err := os.Stat(cgRootPath); err != nil {
				if !rootMissing {
					log.WithContext(ctx).Warnf("[metrics] cgroup root %s unavailable; waiting: %v", cgRootPath, err)
					rootMissing = true
				}
				continue
			}
			if rootMissing {
				log.WithContext(ctx).Infof("[metrics] cgroup root %s available; collection resumed", cgRootPath)
				rootMissing = false
			}

			live := lister.LiveIDs()
			liveSet := make(map[string]struct{}, len(live))
			for _, id := range live {
				liveSet[id] = struct{}{}
			}

			for _, id := range live {
				dir := filepath.Join(cgRootPath, id)
				labels := prometheus.Labels{"sandbox_id": id}
				now := time.Now().UTC()
				point := MetricPoint{Ts: now}

				// Prefer memory.stat "anon" over memory.current — anon is
				// guest workload RAM; memory.current also includes page
				// cache and drifts to the ceiling on any I/O-heavy VM.
				if mem, ok := readMemStatField(filepath.Join(dir, "memory.stat"), "anon"); ok {
					SandboxMemBytes.With(labels).Set(float64(mem))
					point.MemoryBytes = mem
				} else if mem, ok := readUint(filepath.Join(dir, "memory.current")); ok {
					SandboxMemBytes.With(labels).Set(float64(mem))
					point.MemoryBytes = mem
				}
				if used, ok := lister.SandboxGuestMemUsedBytes(id); ok {
					SandboxMemUsedGuestBytes.With(labels).Set(float64(used))
					point.MemoryUsedGuestBytes = used
				}
				if lim, ok := readMaxOrInf(filepath.Join(dir, "memory.max")); ok {
					SandboxMemLimitBytes.With(labels).Set(lim)
					point.MemoryLimitBytes = uint64(lim)
				}
				if usec, ok := readCPUUsageUsec(filepath.Join(dir, "cpu.stat")); ok {
					prev, prevTS, seen := putCPUSample(id, usec)
					if seen && usec >= prev {
						SandboxCPUSecondsTotal.With(labels).Add(float64(usec-prev) / 1_000_000)
						if dt := now.Sub(prevTS).Seconds(); dt > 0 {
							point.CPUCoresUsed = (float64(usec-prev) / 1_000_000) / dt
						}
					}
				}
				if in, out, ok := lister.SandboxNetTotals(id); ok {
					netHistMu.Lock()
					prev, seen := netHist[id]
					netHist[id] = netSample{in: in, out: out, ts: now}
					netHistMu.Unlock()
					if seen && in >= prev.in {
						SandboxNetBytesInTotal.With(labels).Add(float64(in - prev.in))
					}
					if seen && out >= prev.out {
						SandboxNetBytesOutTotal.With(labels).Add(float64(out - prev.out))
					}
					if seen {
						if dt := now.Sub(prev.ts).Seconds(); dt > 0 {
							if in >= prev.in {
								point.NetBytesInRate = float64(in-prev.in) / dt
							}
							if out >= prev.out {
								point.NetBytesOutRate = float64(out-prev.out) / dt
							}
						}
					}
				}
				if mib, _, ok := lister.SandboxDiskMib(id); ok && mib > 0 {
					limit := uint64(mib) * 1024 * 1024
					SandboxStorageLimitBytes.With(labels).Set(float64(limit))
					point.StorageLimit = limit
				}
				// Storage from guest statfs — host-side ext4 superblock
				// reads are stale (firecracker's drive cache doesn't flush
				// the backing file until VM shutdown).
				if used, _, ok := lister.SandboxGuestStorage(id); ok {
					SandboxStorageUsedBytes.With(labels).Set(float64(used))
					point.StorageBytes = used
				}
				ringAppend(id, point)
				knownIDs[id] = struct{}{}
			}

			// Drop series for gone sandboxes — else prom retains stale
			// gauges and rate() on the cpu counter produces phantom activity.
			for id := range knownIDs {
				if _, alive := liveSet[id]; alive {
					continue
				}
				labels := prometheus.Labels{"sandbox_id": id}
				SandboxMemBytes.Delete(labels)
				SandboxMemLimitBytes.Delete(labels)
				SandboxCPUSecondsTotal.Delete(labels)
				SandboxNetBytesInTotal.Delete(labels)
				SandboxNetBytesOutTotal.Delete(labels)
				SandboxStorageUsedBytes.Delete(labels)
				SandboxStorageLimitBytes.Delete(labels)
				SandboxMemUsedGuestBytes.Delete(labels)
				dropCPUSample(id)
				netHistMu.Lock()
				delete(netHist, id)
				netHistMu.Unlock()
				lister.DropGuestMemCache(id)
				ringDrop(id)
				delete(knownIDs, id)
			}
		}
	}
}

func readUint(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// readMaxOrInf reads a cgroup v2 max-or-int file. "max" → ok=false so
// unlimited emits nothing rather than a bogus 0.
func readMaxOrInf(path string) (float64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(b))
	if s == "max" {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return float64(n), true
}

func readMemStatField(path, field string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	pref := field + " "
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, pref) {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, pref)), 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

func readCPUUsageUsec(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "usage_usec ") {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "usage_usec ")), 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}
