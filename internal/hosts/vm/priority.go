package vm

import (
	"syscall"
)

// CFS priority tuning. The host runs createos and N firecracker
// processes at the same nice level by default. With 100+ idle VMs each
// polling MMDS at 500 Hz (~17% guest CPU per VM), the host binary and
// any actively-booting firecracker share equally with the herd —
// spawn latency degrades from 17ms (idle host) to 100–700ms (host with
// 100 idle VMs). Nice values are a cheap way to fix this without
// touching cgroups or per-VM affinity.
//
// PRIO_PROCESS = 0; setpriority(PRIO_PROCESS, pid, prio) with pid=0
// means "self".

const (
	prioProcess = 0

	// PriorityHostBinary is applied to the createos process at startup.
	// At nice=-10 createos's CFS weight is ~9000 vs 1024 for default,
	// so it pre-empts the per-VM firecracker processes (each polling
	// MMDS at ~17% CPU) when createos needs to drive a snapshot
	// restore, install BPF, or push iptables rules.
	PriorityHostBinary = -10
)

// SetSelfPriority applies PriorityHostBinary to the current process.
// Best-effort: a missing CAP_SYS_NICE just leaves us at nice=0.
func SetSelfPriority() error {
	return syscall.Setpriority(prioProcess, 0, PriorityHostBinary)
}

// GetSelfPriority returns the calling thread's current nice value.
// Used to verify SetSelfPriority actually stuck (the Go runtime's
// per-OS-thread scheduling can make this surprising).
func GetSelfPriority() (int, error) {
	return syscall.Getpriority(prioProcess, 0)
}
