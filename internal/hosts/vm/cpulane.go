package vm

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	"golang.org/x/sys/unix"
)

// CPU lane isolation. Reserves a small set of host cores as the "boot
// lane" — createos and any newly-spawning firecracker run there. All
// existing/running firecrackers are confined to the "tenant lane"
// (everything else). The kernel scheduler cannot migrate a tenant VM
// onto a boot-lane core, so spawn work always has cycles available
// regardless of how busy the tenant lane is.
//
// This is the cpuset-isolation pattern Firecracker's own design doc
// recommends (and that gVisor, k8s static CPU manager, and realtime
// Linux all use in different forms). Applied here specifically to
// guarantee spawn latency under load.
//
// Layout for an N-core host:
//
//	cores [0, BootLaneCores)            → boot lane (createos + spawning fc)
//	cores [BootLaneCores, N)            → tenant lane (running fc)
//
// Sized at startup from runtime.NumCPU(). Hosts below MinCoresForLane
// disable the feature (lane carving doesn't pay off when the tenant
// lane would be tiny).

const (
	// BootLaneCores is how many host cores are reserved for boot work.
	// 2 is a reasonable default for 8–32 core hosts: enough for one
	// concurrent /snapshot/load to complete in ~17 ms even when the
	// tenant lane is saturated, small enough that we lose <17% of host
	// capacity to the reservation.
	BootLaneCores = 2

	// MinCoresForLane disables lane carving on hosts smaller than this.
	// Below 6 cores the reservation eats too much capacity to be worth
	// it — better to share equally.
	MinCoresForLane = 6
)

// laneState is the resolved lane layout for this host. Computed once
// at startup by ConfigureCPULanes; nil if lane carving is disabled.
type laneState struct {
	boot   unix.CPUSet // cores createos + booting fc may run on
	tenant unix.CPUSet // cores running fc may run on
}

var lanes *laneState

// ConfigureCPULanes computes the boot/tenant lane masks for this host
// and pins createos itself to the boot lane. Returns nil if lane
// carving is disabled (host too small) — callers should treat this as
// a soft no-op everywhere else.
func ConfigureCPULanes() error {
	n := runtime.NumCPU()
	if n < MinCoresForLane {
		return nil
	}
	if BootLaneCores >= n {
		return fmt.Errorf("BootLaneCores=%d >= NumCPU=%d, refusing to leave tenant lane empty", BootLaneCores, n)
	}
	st := &laneState{}
	for i := 0; i < BootLaneCores; i++ {
		st.boot.Set(i)
	}
	for i := BootLaneCores; i < n; i++ {
		st.tenant.Set(i)
	}
	lanes = st
	// Note: we deliberately do NOT pin createos or the booting
	// firecracker to the boot lane. Pinning createos made its Go
	// goroutines compete with the booting firecracker for the 2 boot
	// cores, defeating the point — measured boot phase went from ~17ms
	// idle to ~120ms even with lanes. Instead, only the tenant VMs are
	// fenced *out* of the boot lane. createos and any in-flight
	// firecracker boot are unpinned; the kernel CFS scheduler picks
	// the least-loaded core, which is almost always a boot-lane core
	// because the tenant lane is busy and the boot lane has nothing
	// allowed there except them.
	return nil
}

// CPULanesActive reports whether lane carving is enabled on this host.
func CPULanesActive() bool { return lanes != nil }

// PinPidToBootLane confines the given pid (and all its threads) to
// the boot lane. Applied to a brand-new firecracker right after
// StartVMM so /snapshot/load AND the first guest instructions (the
// ones the agent-ready probe is waiting on) run on cores that no
// tenant is allowed to touch. Migrated out via PinPidToTenantLane
// once the agent answers — boot done, joins the steady-state fleet.
//
// createos itself stays unpinned on purpose: pinning it too would
// trap its Go goroutines on the same 2 boot cores, fighting the
// booting firecracker for CPU. With ONLY firecracker pinned and
// createos floating, the boot lane has at most ~5 firecracker
// threads on it (main + fc_api + fc_vcpu_0 + kvm-nx-lpage + possibly
// a worker) and the kernel-scheduler-driven createos orchestration
// runs on the tenant lane (where there's slack alongside the
// existing 100 polling VMs).
func PinPidToBootLane(pid int) error {
	if lanes == nil {
		return nil
	}
	return pinPidAllThreads(pid, &lanes.boot)
}

// PinPidToTenantLane confines the given pid (and all its threads) to
// the tenant lane. Called once the agent has answered — the boot is
// done and this firecracker joins the steady-state fleet.
func PinPidToTenantLane(pid int) error {
	if lanes == nil {
		return nil
	}
	return pinPidAllThreads(pid, &lanes.tenant)
}

// pinPidAllThreads iterates /proc/<pid>/task and applies the cpuset to
// every TID. SchedSetaffinity is per-thread under Linux; setting the
// TGID only changes that one thread.
func pinPidAllThreads(pid int, set *unix.CPUSet) error {
	dir := fmt.Sprintf("/proc/%d/task", pid)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var firstErr error
	for _, e := range ents {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if err := unix.SchedSetaffinity(tid, set); err != nil && firstErr == nil {
			// Race: thread may have exited between readdir and now.
			// ESRCH is benign; surface anything else as the first error.
			if !os.IsNotExist(err) && err != unix.ESRCH {
				firstErr = fmt.Errorf("setaffinity tid=%d: %w", tid, err)
			}
		}
	}
	return firstErr
}

// PinExistingFirecrackersToTenantLane scans /proc for already-running
// firecracker processes (rehydrated from a prior serve run) and pins
// each to the tenant lane. Without this, after a createos restart the
// rehydrated tenants stay on default affinity (every core) and would
// pollute the boot lane until they exit. No-op when lane carving is
// disabled. Reports the count of pinned PIDs.
func PinExistingFirecrackersToTenantLane() (int, error) {
	if lanes == nil {
		return 0, nil
	}
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	pinned := 0
	for _, e := range procs {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}
		if string(comm) != "firecracker\n" {
			continue
		}
		if err := pinPidAllThreads(pid, &lanes.tenant); err == nil {
			pinned++
		}
	}
	return pinned, nil
}

// LaneSummary returns a one-line description of the lane configuration
// for logging on startup.
func LaneSummary() string {
	if lanes == nil {
		return fmt.Sprintf("cpu-lanes: disabled (NumCPU=%d < %d)", runtime.NumCPU(), MinCoresForLane)
	}
	return fmt.Sprintf("cpu-lanes: boot=[0..%d) tenant=[%d..%d)",
		BootLaneCores, BootLaneCores, runtime.NumCPU())
}

// pinToBootLaneHandler is an SDK init handler that pins firecracker
// to the boot lane right after StartVMM (process up, PID known) and
// before /snapshot/load + the guest's first instructions. createos
// stays unpinned; only the booting firecracker is confined here, so
// the 2 boot-lane cores don't get split between createos's
// orchestration goroutines and the new VM's vCPU. After agent-ready
// the manager migrates this pid to the tenant lane.
func pinToBootLaneHandler() firecracker.Handler {
	return firecracker.Handler{
		Name: "createos.PinBootLane",
		Fn: func(ctx context.Context, m *firecracker.Machine) error {
			if lanes == nil {
				return nil
			}
			pid, err := m.PID()
			if err != nil {
				return nil // not fork()'d yet; harmless
			}
			_ = PinPidToBootLane(pid)
			return nil
		},
	}
}
