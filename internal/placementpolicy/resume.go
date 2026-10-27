package placementpolicy

import (
	"context"

	schedapi "github.com/NodeOps-app/sandbox/internal/scheduler/api"
	"github.com/NodeOps-app/sandbox/models"
)

type ResumeScheduleOpts struct {
	Region      string
	ClearFailed bool
}

type ResumeBuildError struct {
	Msg       string
	Retryable bool
}

func (e *ResumeBuildError) Error() string { return e.Msg }

// BuildResumeScheduleRequest converts a paused sandbox into scheduler
// placement requirements. It does not contact either scheduler or host.
func BuildResumeScheduleRequest(
	ctx context.Context, repo *models.Repo, rec *models.Sandbox, opts ResumeScheduleOpts,
) (schedapi.ScheduleRequest, error) {
	recRootfs := ""
	if rec.Rootfs != nil {
		recRootfs = *rec.Rootfs
	}
	cachedHostID := ""
	if rec.CachedHostID != nil {
		cachedHostID = *rec.CachedHostID
	}
	if rec.BundleUploadedAt == nil {
		return schedapi.ScheduleRequest{}, &ResumeBuildError{
			Msg: "paused sandbox bundle is not durable in shared storage",
		}
	}

	req := schedapi.ScheduleRequest{
		SandboxID: rec.ID, Shape: rec.Shape, Rootfs: recRootfs,
		MemMiB: rec.MemMib, VCPU: rec.VCPU, DiskMiB: rec.DiskMib,
		Region: opts.Region, CachedHostID: cachedHostID,
	}
	req.PreferredHostIDs = PreferredHosts(rec.CreatedBy, rec.Shape, opts.Region)
	if !opts.ClearFailed {
		req.ExcludeHosts = rec.ResumeFailedHosts
	}

	vendor := ""
	if rec.CPUVendor != nil {
		vendor = *rec.CPUVendor
	}
	if vendor == "" && cachedHostID != "" {
		if srcHost, _ := repo.GetHost(ctx, cachedHostID); srcHost != nil {
			vendor = srcHost.CPUVendor
		}
	}
	if vendor == "" {
		return schedapi.ScheduleRequest{}, &ResumeBuildError{
			Msg: "cannot determine source CPU vendor for snapshot resume (no cpu_vendor on row and no resolvable cached_host_id)",
		}
	}
	req.SourceCPUVendor = vendor

	return req, nil
}
