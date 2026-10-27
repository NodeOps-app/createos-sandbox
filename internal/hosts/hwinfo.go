package hosts

import (
	"bufio"
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// HardwareInfo is a snapshot of the host machine's HW capacity. Cheap to
// collect (one syscall + a runtime accessor) so we re-read it on every
// heartbeat — keeps disk usage live without any background polling.
type HardwareInfo struct {
	CPUCount     int
	DiskTotalMib int64
	DiskUsedMib  int64

	// CPU identity from /proc/cpuinfo. Stable per boot; we read it on
	// every heartbeat anyway because the cost is trivial (~one read of
	// the first few KB of cpuinfo) and a host could be live-migrated
	// to a different vendor's hardware in pathological setups.
	CPUVendor string // e.g. GenuineIntel, AuthenticAMD
	CPUFamily string // family:model:stepping, e.g. "6:85:7"
}

// CollectHardware returns a fresh HardwareInfo. diskPath is statfs'd to
// derive the disk numbers (use whatever filesystem the snapshots/overlays
// live on — usually the snapshot dir).
func CollectHardware(diskPath string) HardwareInfo {
	hw := HardwareInfo{CPUCount: runtime.NumCPU()}
	var s unix.Statfs_t
	if err := unix.Statfs(diskPath, &s); err == nil {
		// Block size × total blocks → bytes → MiB.
		const mib = uint64(1024 * 1024)
		total := uint64(s.Bsize) * s.Blocks / mib
		free := uint64(s.Bsize) * s.Bfree / mib
		hw.DiskTotalMib = int64(total)
		hw.DiskUsedMib = int64(total - free)
	}
	hw.CPUVendor, hw.CPUFamily = readCPUIdentity()
	return hw
}

// readCPUIdentity parses /proc/cpuinfo for the first processor's
// vendor_id, cpu family, model, stepping. Returns ("", "") on parse
// failure — callers leave the field empty rather than blocking
// registration.
func readCPUIdentity() (vendor, family string) {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "", ""
	}
	defer f.Close()
	var fam, model, step string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" && vendor != "" && fam != "" {
			break // end of first processor block
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "vendor_id":
			vendor = strings.TrimSpace(v)
		case "cpu family":
			fam = strings.TrimSpace(v)
		case "model":
			if model == "" {
				model = strings.TrimSpace(v)
			}
		case "stepping":
			step = strings.TrimSpace(v)
		}
	}
	if fam != "" {
		family = fam + ":" + model + ":" + step
	}
	return vendor, family
}
