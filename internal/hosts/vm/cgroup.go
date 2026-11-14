// Package vm — cgroup v2 helpers for per-VM CPU + memory throttling.
//
// Used to (a) back fractional-vCPU shapes (e.g. 0.25c, 0.5c) by capping
// real CPU time via cpu.max and (b) bound per-VM memory so a runaway
// guest can't trigger host-wide OOM. The memory cap is the more
// load-bearing one — without it the host OOM killer can take out
// createos itself when a tenant's VM grows past its allocated size.
//
// Layout (cgroup v2 unified hierarchy, /sys/fs/cgroup):
//
//	/sys/fs/cgroup/createos/                 root for our VMs
//	    cgroup.subtree_control               enables cpu, memory, pids; cpuset for CPU lanes
//	/sys/fs/cgroup/createos/<sandbox_id>/    per-VM leaf
//	    cgroup.procs                         firecracker PID is written here
//	    cpu.max                              "<quota> <period>" or "max <period>"
//	    memory.max                           shared host-memory reservation
//	    memory.swap.max                      "0" (no swap, clean death)
//	    memory.oom.group                     "1" (group-scoped OOM handling)
//	    pids.max                             "512" (host tasks in the VM cgroup)
//
// The parent is created (and "+cpu +memory +pids" added to subtree_control)
// lazily on the first call. Per-VM leaves are mkdir'd on EnsureVMCgroup
// and rmdir'd on RemoveVMCgroup. Failures are non-fatal — the VM still
// runs without the throttle and we log a warning. cgroup v1 hosts
// silently skip (the v2 files won't exist).
package vm

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/vmcapacity"

	log "github.com/sirupsen/logrus"
)

const (
	cgRoot   = "/sys/fs/cgroup"
	cgParent = "createos"
	// cpuPeriodUs is the cgroup v2 default period (100 ms). We hold it
	// constant and vary the quota; this matches systemd's CPUQuota=
	// semantics and makes the math trivial (quota = quotaPct * 1000).
	cpuPeriodUs = 100000
)

var (
	cgParentOnce sync.Once
	cgParentErr  error
)

// ensureParent creates /sys/fs/cgroup/createos and enables cpu, memory,
// and pids in subtree_control for per-VM limits. CPU lane configuration
// enables cpuset separately.
// Idempotent; runs at most once per process.
func ensureParent() error {
	cgParentOnce.Do(func() {
		dir := filepath.Join(cgRoot, cgParent)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			cgParentErr = fmt.Errorf("mkdir %s: %w", dir, err)
			return
		}
		// Enable controllers on the parent so leaves inherit them.
		// Enabling cpu, memory, and pids is a no-op for controllers already
		// enabled. Request all three in one write.
		ctl := filepath.Join(dir, "cgroup.subtree_control")
		if err := os.WriteFile(ctl, []byte("+cpu +memory +pids"), 0); err != nil {
			cgParentErr = fmt.Errorf("enable controllers on parent: %w", err)
			return
		}
	})
	return cgParentErr
}

// EnsureVMCgroup creates a per-VM cgroup, moves the firecracker PID
// into it with a tenant cpuset when CPU lanes are active, and writes cpu.max
// (when quotaPct > 0) plus memory.max (when memMib > 0). Without lanes or
// resource limits, no cgroup is needed. Failures are logged rather than
// returned to the caller; missing or failed writes may leave limits unapplied.
func EnsureVMCgroup(vmID, shape string, pid int, quotaPct, memMib int) {
	if pid <= 0 || (quotaPct <= 0 && memMib <= 0 && !CPULanesActive()) {
		// No throttle requested — skip the cgroup entirely. The mkdir +
		// process migration was measured at ~21–28ms per VM on prod
		// (mkdir ~7.7ms, kernel thread-walk on cgroup.procs write
		// ~13–21ms), which dominated the post-tNet spawn tail and
		// pushed floor spawn time from 17ms → 27–30ms. Caller decides
		// whether either knob is worth the cost.
		return
	}
	// Pre-check pid is still alive. Caller runs us in a goroutine so
	// Destroy can race ahead: without this guard we'd mkdir an orphan
	// leaf for a VM that no longer exists. signal 0 is a permission +
	// existence probe — ESRCH means the pid is dead.
	if err := syscall.Kill(pid, 0); err != nil {
		return
	}
	if err := ensureParent(); err != nil {
		log.Warnf("[cgroup] %s: ensure parent: %v (no throttle applied)", vmID, err)
		return
	}
	leaf := filepath.Join(cgRoot, cgParent, vmID)
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		log.Warnf("[cgroup] %s: mkdir leaf: %v", vmID, err)
		return
	}
	// Set the tenant cpuset before migration so existing and future threads
	// are constrained together, while retaining this VM's other resource limits.
	if lanes != nil {
		if err := setCgroupCPUs(leaf, &lanes.tenant); err != nil {
			// A CPU-controller failure must not bypass memory and pids limits.
			log.Warnf("[cgroup] %s: tenant cpuset: %v (continuing with other resource limits)", vmID, err)
		}
	}
	// Move firecracker into the leaf. cgroup.procs accepts one pid per
	// write; the kernel migrates the process and all its threads. If
	// the pid died between the Kill(0) probe above and now (Destroy
	// racing the async attach) the write fails with ESRCH; rmdir the
	// leaf we just created so we don't leak an empty cgroup.
	if err := os.WriteFile(filepath.Join(leaf, "cgroup.procs"),
		[]byte(strconv.Itoa(pid)), 0); err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("[cgroup] %s: attach pid %d: %v", vmID, pid, err)
		}
		_ = os.Remove(leaf)
		return
	}
	// cpu.max: quota = quotaPct% of cpuPeriodUs. e.g. 25% × 100000 = 25000.
	if quotaPct > 0 {
		quota := quotaPct * cpuPeriodUs / 100
		line := fmt.Sprintf("%d %d", quota, cpuPeriodUs)
		if err := os.WriteFile(filepath.Join(leaf, "cpu.max"),
			[]byte(line), 0); err != nil {
			if os.IsNotExist(err) {
				return // Destroy raced us between the procs write and now
			}
			log.Warnf("[cgroup] %s: write cpu.max %q: %v", vmID, line, err)
			return
		}
		log.Debugf("[cgroup] %s: cpu.max=%s (%d%% of one core)", vmID, line, quotaPct)
	}

	// memory.max: hard cap = guest mem + overhead slop. Triggers
	// cgroup-scoped OOM kill on overflow (CONSTRAINT_MEMCG), NOT the
	// host's global OOM killer — that's the whole point.
	if memMib > 0 {
		totalMiB := vmcapacity.ReservedMemoryMiB(shape, memMib)
		memBytes := int64(totalMiB) * 1024 * 1024
		if err := os.WriteFile(filepath.Join(leaf, "memory.max"),
			[]byte(strconv.FormatInt(memBytes, 10)), 0); err != nil {
			if os.IsNotExist(err) {
				return
			}
			log.Warnf("[cgroup] %s: write memory.max %d: %v", vmID, memBytes, err)
			return
		}
		// No swap. Better to die fast than thrash — and the host
		// usually doesn't have meaningful swap anyway. Best-effort:
		// some systems disable the swap controller, which makes this
		// file absent.
		if err := os.WriteFile(filepath.Join(leaf, "memory.swap.max"),
			[]byte("0"), 0); err != nil && !os.IsNotExist(err) {
			log.Debugf("[cgroup] %s: write memory.swap.max=0: %v", vmID, err)
		}
		// Treat this cgroup as one workload during OOM handling, rather than
		// selecting individual processes if more than one belongs to it.
		// This is not a guest-process limit; guest tasks run inside the VM.
		if err := os.WriteFile(filepath.Join(leaf, "memory.oom.group"),
			[]byte("1"), 0); err != nil && !os.IsNotExist(err) {
			log.Debugf("[cgroup] %s: write memory.oom.group=1: %v", vmID, err)
		}
		log.Debugf("[cgroup] %s: memory.max=%d MiB (shape=%s guest=%d overhead=%d)",
			vmID, totalMiB, shape, memMib, totalMiB-memMib)
	}

	// pids.max: bounds a fork-bomb inside an escaped firecracker to one
	// slot. firecracker itself needs ~10 threads (1 API + N vCPUs +
	// vhost helpers); 512 leaves ample headroom and is well below the
	// host's kernel.pid_max. Without this, an RCE'd firecracker can
	// fork() until host PID space is exhausted.
	if err := os.WriteFile(filepath.Join(leaf, "pids.max"),
		[]byte("512"), 0); err != nil && !os.IsNotExist(err) {
		log.Debugf("[cgroup] %s: write pids.max=512: %v", vmID, err)
	}
}

// RemoveVMCgroup rmdirs the per-VM leaf. The kernel refuses rmdir
// while any process is still in cgroup.procs. firecracker is killed
// via SIGKILL fire-and-forget upstream, so its threads can take a
// few hundred ms to fully reap. Without retries the first rmdir hits
// EBUSY and the directory is silently leaked — at scale that
// accumulates thousands of empty cgroups per host.
//
// Retry on EBUSY for ~3 s total. Successful rmdir or ENOENT exits
// immediately. Anything still busy after the budget is logged at
// warning (rare; reaper sweep cleans those later).
func RemoveVMCgroup(vmID string) {
	leaf := filepath.Join(cgRoot, cgParent, vmID)
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := os.Remove(leaf)
		if err == nil || os.IsNotExist(err) {
			return
		}
		if !time.Now().Before(deadline) {
			log.Warnf("[cgroup] %s: rmdir leaf busy after retries: %v (will be reaped by sweeper)", vmID, err)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// SweepOrphanCgroups removes any /sys/fs/cgroup/createos/sb-* leaf
// whose id isn't in liveIDs AND whose cgroup.procs is empty. Catches
// leftovers from past EBUSY retries that gave up, plus any cgroup
// stranded by a crash between the firecracker exit and Manager.Destroy.
//
// Called periodically from a host loop. Idempotent + cheap (just
// readdir + small reads per entry).
func SweepOrphanCgroups(liveIDs map[string]struct{}) int {
	root := filepath.Join(cgRoot, cgParent)
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	removed := 0
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || !strings.HasPrefix(name, "sb-") {
			continue
		}
		if _, alive := liveIDs[name]; alive {
			continue
		}
		// Only remove if empty. A non-empty orphan would mean a leaked
		// firecracker process — surface it for operator triage, don't
		// silently kill.
		procs, err := os.ReadFile(filepath.Join(root, name, "cgroup.procs"))
		if err != nil || len(procs) > 0 {
			continue
		}
		if err := os.Remove(filepath.Join(root, name)); err == nil {
			removed++
		}
	}
	if removed > 0 {
		log.Infof("[cgroup] sweep removed %d orphan leaves", removed)
	}
	return removed
}
