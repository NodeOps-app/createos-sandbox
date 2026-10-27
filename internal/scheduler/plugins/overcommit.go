package plugins

import (
	"fmt"

	"github.com/NodeOps-app/sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/sandbox/models"
)

// Default oversubscription factors when a host hasn't been configured
// with explicit values. Stored as integer 10ths so 80 = 8.0×, 10 = 1.0×.
//
//	CPU  = 8.0× — most sandbox workloads (AI agents, dev environments,
//	              ephemeral repls) are bursty and mostly idle. AWS
//	              Lambda runs ~8-16× CPU oversub for similar reasons.
//	              Linux CFS scheduler time-slices fairly; per-VM cgroup
//	              cpu.max (on fractional shapes) is the strict ceiling.
//	              Tune LOWER (2-3×) for latency-SLA workloads.
//	MEM  = 1.0× — OOM-kill is catastrophic for tenants; don't oversell.
//	              KSM page-dedup gives effective 1.2-1.3× headroom in
//	              practice but is opportunistic — keep the cap honest.
//	DISK = 2.0× — per-VM overlays are sparse ext4 but tenants CAN fill
//	              them (dataset downloads, build caches, log floods).
//	              2× is conservative — covers sparse savings without
//	              risking ENOSPC on the host. Tune higher (5-10×) on
//	              hosts where workloads are known to be read-mostly.
const (
	DefaultCPUOvercommitX10  = 80
	DefaultMemOvercommitX10  = 10
	DefaultDiskOvercommitX10 = 20
)

// OvercommitFilter rejects a host when adding this request would push
// the host past the per-dimension committed-vs-capacity ratio for ANY
// of {CPU, Memory, Disk}. Hosts pass the filter only when EVERY
// dimension's budget is honored. This is the multi-dimensional bin-
// packing admission control e2b / Fly / AWS Lambda all use to prevent
// the "100 idle VMs all degrade together when one bursts" pathology.
//
// The classic memory-only CapacityFilter remains in the pipeline as a
// fast pre-filter; this filter is the strict per-dimension version.
// Mem fits via CapacityFilter → OvercommitFilter rejects if some
// other dimension is full → host dropped, next host evaluated.
//
// When a request has VCPU=0 or DiskMiB=0 the corresponding dimension
// is skipped (backward-compat with older /v1/schedule callers that
// don't send these fields yet). When a host has CPUCount=0 or
// DiskTotalMib=0 the corresponding dimension is also skipped (legacy
// hosts that haven't advertised the new register fields). This makes
// the filter strictly additive — turning it on for a partially-
// upgraded fleet doesn't break anything.
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

	// Memory dimension. CapacityFilter already rejected when
	// InUseMib + reserved memory > MemCapacityMib (the strict 1.0× case);
	// this branch only matters if an operator dialed mem_overcommit
	// above 1.0 — then we permit slight oversell up to the factor.
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
