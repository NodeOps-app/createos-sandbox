package plugins

import (
	"fmt"

	"github.com/NodeOps-app/createos-sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// Oversubscription factors are stored in tenths of a multiple (10 = 1x). CPU
// and disk overcommit allow more logical commitments than physical
// capacity; they do not guarantee freedom from contention or disk exhaustion.
const (
	DefaultCPUOvercommitX10  = 80
	DefaultMemOvercommitX10  = 10
	DefaultDiskOvercommitX10 = 20
)

// OvercommitFilter checks CPU, memory, and disk commitment limits. CPU and
// disk checks are skipped when the request or host omits that dimension.
// The default pipeline also applies CapacityFilter, which caps memory at
// physical capacity regardless of a higher memory overcommit factor.
type OvercommitFilter struct{}

func (OvercommitFilter) Name() string { return "overcommit" }

func (OvercommitFilter) Filter(req *framework.Request, h *models.Host) (bool, string) {
	// CPU dimension
	if req.VCPU > 0 && h.CPUCount > 0 {
		factor := h.CPUOvercommitX10
		if factor <= 0 {
			factor = DefaultCPUOvercommitX10
		}
		limit := h.CPUCount * factor / 10
		used := h.VCPUInUse
		if used+req.VCPU > limit {
			return false, fmt.Sprintf("cpu %d+%d > %d (%dcores×%.1f×)", used, req.VCPU, limit, h.CPUCount, float64(factor)/10)
		}
	}

	// A factor below 1x tightens memory admission. A higher factor cannot
	// relax the separate CapacityFilter in the default pipeline.
	if req.MemMiB > 0 && h.MemCapacityMib > 0 {
		factor := h.MemOvercommitX10
		if factor <= 0 {
			factor = DefaultMemOvercommitX10
		}
		limit := h.MemCapacityMib * factor / 10
		used := h.InUseMib
		reserved := req.ReservedMemoryMiB()
		if used+reserved > limit {
			return false, fmt.Sprintf("mem %d+%d > %d MiB (cap×%.1f×)", used, reserved, limit, float64(factor)/10)
		}
	}

	// Disk dimension
	if req.DiskMiB > 0 && h.DiskTotalMib > 0 {
		factor := h.DiskOvercommitX10
		if factor <= 0 {
			factor = DefaultDiskOvercommitX10
		}
		limit := DiskCommitLimitMiB(h)
		used := h.DiskInUseMib
		if used+req.DiskMiB > limit {
			return false, fmt.Sprintf("disk %d+%d > %d MiB (total×%.1f×)", used, req.DiskMiB, limit, float64(factor)/10)
		}
	}

	return true, ""
}
