package vm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	"golang.org/x/sys/unix"
)

// CPU lanes reserve the first two available logical CPUs for boot work.
// Firecracker starts in a shared boot cgroup, then moves to its per-VM
// cgroup with a tenant cpuset. The kernel restricts all current and future
// threads; no /proc task scan is needed. The host service stays unpinned.
const (
	// BootLaneCores is the number of logical CPUs excluded from the tenant
	// lane and made available to booting Firecracker processes. The host
	// service remains unpinned; these CPUs are not exclusive to it.
	BootLaneCores = 2

	// MinCoresForLane disables lane carving on hosts smaller than this.
	// Below 6 cores the reservation eats too much capacity to be worth
	// it — better to share equally.
	MinCoresForLane = 6
)

// laneState is the resolved lane layout for this host. Computed once
// at startup by ConfigureCPULanes; nil if lane carving is disabled.
type laneState struct {
	boot   unix.CPUSet // CPUs available to booting firecrackers
	tenant unix.CPUSet // cores running fc may run on
}

var lanes *laneState

// ConfigureCPULanes derives lanes from CPUs available in the cgroup hierarchy.
// It does not change the host service's own affinity.
func ConfigureCPULanes() error {
	data, err := os.ReadFile(filepath.Join(cgRoot, "cpuset.cpus.effective"))
	if err != nil {
		return fmt.Errorf("cpu lanes: available CPUs: %w", err)
	}
	available, err := parseCPUList(string(data))
	if err != nil {
		return err
	}
	if available.Count() < MinCoresForLane {
		return nil
	}
	// Some hosts enable cpu/memory/pids at the hierarchy root but not cpuset.
	// Enable it there first so our parent can delegate it to the VM leaves.
	if err := os.WriteFile(filepath.Join(cgRoot, "cgroup.subtree_control"), []byte("+cpuset"), 0); err != nil {
		return fmt.Errorf("cpu lanes: enable root cpuset: %w", err)
	}
	st := &laneState{}
	for cpu := 0; cpu < 1024; cpu++ {
		if !available.IsSet(cpu) {
			continue
		}
		if st.boot.Count() < BootLaneCores {
			st.boot.Set(cpu)
		} else {
			st.tenant.Set(cpu)
		}
	}
	if err := ensureParent(); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(cgRoot, cgParent, "cgroup.subtree_control"), []byte("+cpuset"), 0); err != nil {
		return fmt.Errorf("cpu lanes: enable cpuset: %w", err)
	}
	for name, set := range map[string]*unix.CPUSet{"boot": &st.boot, "tenant": &st.tenant} {
		dir := filepath.Join(cgRoot, cgParent, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := setCgroupCPUs(dir, set); err != nil {
			return err
		}
	}
	lanes = st
	return nil
}

func parseCPUList(value string) (unix.CPUSet, error) {
	var set unix.CPUSet
	for _, item := range strings.Split(strings.TrimSpace(value), ",") {
		bounds := strings.Split(item, "-")
		first, err := strconv.Atoi(bounds[0])
		if err != nil {
			return set, fmt.Errorf("invalid CPU list %q", value)
		}
		last := first
		if len(bounds) == 2 {
			last, err = strconv.Atoi(bounds[1])
		}
		if err != nil || len(bounds) > 2 || first < 0 || last < first || last >= 1024 {
			return set, fmt.Errorf("invalid CPU list %q", value)
		}
		for cpu := first; cpu <= last; cpu++ {
			set.Set(cpu)
		}
	}
	return set, nil
}

func cpuList(set *unix.CPUSet) string {
	var cpus []string
	for cpu := 0; cpu < 1024; cpu++ {
		if set.IsSet(cpu) {
			cpus = append(cpus, strconv.Itoa(cpu))
		}
	}
	return strings.Join(cpus, ",")
}

// Verify the effective mask: unavailable CPUs can otherwise cause cpuset to
// fall back to the parent's mask rather than enforce the requested restriction.
func setCgroupCPUs(dir string, set *unix.CPUSet) error {
	if set.Count() == 0 {
		return fmt.Errorf("cpu lanes: empty CPU set")
	}
	if err := os.WriteFile(filepath.Join(dir, "cpuset.cpus"), []byte(cpuList(set)), 0); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(dir, "cpuset.cpus.effective"))
	if err != nil {
		return err
	}
	effective, err := parseCPUList(string(data))
	if err != nil {
		return err
	}
	if effective != *set {
		return fmt.Errorf("cpu lanes: requested %s, effective %s", cpuList(set), strings.TrimSpace(string(data)))
	}
	return nil
}

func moveToCPULane(pid int, dir string, set *unix.CPUSet) error {
	if err := setCgroupCPUs(dir, set); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0)
}

// CPULanesActive reports whether lane carving is enabled on this host.
func CPULanesActive() bool { return lanes != nil }

// PinPidToBootLane places a new Firecracker in the boot cgroup before VM
// startup. EnsureVMCgroup later moves it to its tenant-restricted VM cgroup.
func PinPidToBootLane(pid int) error {
	if lanes == nil {
		return nil
	}
	return moveToCPULane(pid, filepath.Join(cgRoot, cgParent, "boot"), &lanes.boot)
}

// PinPidToTenantLane restores tenant CPU restrictions for a surviving
// Firecracker on host restart, preserving any existing per-VM resource limits.
func PinPidToTenantLane(pid int) error {
	if lanes == nil {
		return nil
	}
	// Preserve existing memory, CPU quota and pids limits on host restart.
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		path, ok := strings.CutPrefix(line, "0::/"+cgParent+"/")
		if ok && strings.HasPrefix(path, "sb-") && !strings.Contains(path, "/") {
			return setCgroupCPUs(filepath.Join(cgRoot, cgParent, path), &lanes.tenant)
		}
	}
	return moveToCPULane(pid, filepath.Join(cgRoot, cgParent, "tenant"), &lanes.tenant)
}

// PinExistingFirecrackersToTenantLane scans /proc for already-running
// firecracker processes (rehydrated from a prior serve run) and pins
// each to the tenant lane. Existing per-VM cgroups survive service restart;
// update their cpusets in place to preserve resource limits. Processes without
// a per-VM leaf move to the shared tenant cgroup. No-op when lane carving is
// disabled. Reports the count of updated PIDs.
func PinExistingFirecrackersToTenantLane() (int, error) {
	if lanes == nil {
		return 0, nil
	}
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	pinned := 0
	var firstErr error
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
		if err := PinPidToTenantLane(pid); err != nil {
			if !os.IsNotExist(err) && firstErr == nil {
				firstErr = fmt.Errorf("tenant lane pid %d: %w", pid, err)
			}
			continue
		}
		pinned++
	}
	return pinned, firstErr
}

// LaneSummary returns a one-line description of the lane configuration
// for logging on startup.
func LaneSummary() string {
	if lanes == nil {
		return "cpu-lanes: disabled"
	}
	return fmt.Sprintf("cpu-lanes: boot=%s tenant=%s", cpuList(&lanes.boot), cpuList(&lanes.tenant))
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
			return PinPidToBootLane(pid)
		},
	}
}
