package plugins

import "github.com/NodeOps-app/sandbox/models"

// DiskCommitLimitMiB returns the maximum logical VM disk commitment after
// sparse-disk overcommit, with physical operational headroom subtracted once.
// Keeping this calculation shared aligns filters, scorers, reservations, and
// the operator-facing capacity endpoint.
func DiskCommitLimitMiB(h *models.Host) int64 {
	if h == nil || h.DiskTotalMib <= 0 {
		return 0
	}
	factor := h.DiskOvercommitX10
	if factor <= 0 {
		factor = DefaultDiskOvercommitX10
	}
	limit := h.DiskTotalMib*int64(factor)/10 - h.DiskHeadroomMib
	if limit < 0 {
		return 0
	}
	return limit
}
