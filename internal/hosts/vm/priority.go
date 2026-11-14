package vm

import (
	"syscall"
)

// Linux nice tuning gives host management work a higher scheduling weight.
// This complements CPU lanes and per-VM cgroup limits; it does not reserve
// CPUs or guarantee a particular VM startup latency. Linux nice values are
// per-thread, so SetSelfPriority changes the calling OS thread.

const (
	prioProcess = 0

	// PriorityHostBinary is the nice value requested during host startup.
	// Lower nice values give a runnable thread more scheduling weight.
	PriorityHostBinary = -10
)

// SetSelfPriority applies PriorityHostBinary to the calling OS thread.
// Without permission to raise priority, it returns an error and leaves the
// existing nice value unchanged; the host logs the error and continues.
func SetSelfPriority() error {
	return syscall.Setpriority(prioProcess, 0, PriorityHostBinary)
}

// GetSelfPriority returns the calling thread's current nice value.
// Used to verify SetSelfPriority actually stuck (the Go runtime's
// per-OS-thread scheduling can make this surprising).
func GetSelfPriority() (int, error) {
	return syscall.Getpriority(prioProcess, 0)
}
