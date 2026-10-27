// Package vmcapacity defines host-memory reservation policy shared by the
// scheduler and the Firecracker cgroup setup. User-visible memory and billing
// remain based on guestMiB; these functions account only for host capacity.
package vmcapacity

// shapeOverheadMiB is the host memory reserved above guest RAM for each shape.
// It covers Firecracker process state, host/KVM page tables, and file/kernel
// memory charged to the VM cgroup. Keep this table as the single source of
// truth: the scheduler and host both call ReservedMemoryMiB.
var shapeOverheadMiB = map[string]int{
	"s-1vcpu-256mb":    32,
	"s-0.25vcpu-512mb": 32,
	"s-0.5vcpu-1gb":    64,
	"s-1vcpu-1gb":      64,
	"s-1vcpu-2gb":      128,
	"s-2vcpu-2gb":      128,
	"s-2vcpu-4gb":      256,
	"s-4vcpu-4gb":      256,
	"s-4vcpu-8gb":      512,
	"s-8vcpu-8gb":      512,
	"s-8vcpu-16gb":     1024,
}

// OverheadMiB returns host-only headroom for one Firecracker VM. The fallback
// protects custom or newly introduced shapes until they receive an explicit
// measured entry: at least 32 MiB, scaling at 6.25% of guest RAM.
func OverheadMiB(shape string, guestMiB int) int {
	if overhead, ok := shapeOverheadMiB[shape]; ok {
		return overhead
	}
	const floor = 32
	overhead := guestMiB / 16
	if overhead < floor {
		return floor
	}
	return overhead
}

// ReservedMemoryMiB is the physical-host capacity consumed by a VM. It is
// intentionally distinct from the guest memory advertised and billed.
func ReservedMemoryMiB(shape string, guestMiB int) int {
	if guestMiB <= 0 {
		return 0
	}
	return guestMiB + OverheadMiB(shape, guestMiB)
}
