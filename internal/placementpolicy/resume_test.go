package placementpolicy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NodeOps-app/createos-sandbox/models"
)

func resumeStringPtr(value string) *string { return &value }

func TestBuildResumeScheduleRequest(t *testing.T) {
	uploaded := time.Unix(1, 0)

	t.Run("vendor comes from row lineage", func(t *testing.T) {
		rec := &models.Sandbox{
			ID: "sb-1", Shape: "s-1vcpu-1gb", MemMib: 1024, VCPU: 1, DiskMib: 10240,
			CPUVendor: resumeStringPtr("AuthenticAMD"), BundleUploadedAt: &uploaded,
		}
		req, err := BuildResumeScheduleRequest(context.Background(), nil, rec, ResumeScheduleOpts{Region: "eu"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.SourceCPUVendor != "AuthenticAMD" {
			t.Errorf("SourceCPUVendor = %q, want AuthenticAMD", req.SourceCPUVendor)
		}
		if req.HostID != "" {
			t.Errorf("HostID = %q, want empty", req.HostID)
		}
	})

	t.Run("fail closed when vendor unresolvable", func(t *testing.T) {
		rec := &models.Sandbox{ID: "sb-2", BundleUploadedAt: &uploaded}
		_, err := BuildResumeScheduleRequest(context.Background(), nil, rec, ResumeScheduleOpts{Region: "eu"})
		var buildErr *ResumeBuildError
		if !errors.As(err, &buildErr) || buildErr.Retryable {
			t.Fatalf("want non-retryable ResumeBuildError, got %#v", err)
		}
	})

	t.Run("paused row without durable bundle fails closed", func(t *testing.T) {
		rec := &models.Sandbox{
			ID: "sb-3", CPUVendor: resumeStringPtr("GenuineIntel"), CachedHostID: resumeStringPtr("host-7"),
		}
		_, err := BuildResumeScheduleRequest(context.Background(), nil, rec, ResumeScheduleOpts{Region: "eu"})
		var buildErr *ResumeBuildError
		if !errors.As(err, &buildErr) || buildErr.Retryable {
			t.Fatalf("want non-retryable ResumeBuildError, got %#v", err)
		}
	})

	t.Run("clear failed drops excludes", func(t *testing.T) {
		rec := &models.Sandbox{
			ID: "sb-4", CPUVendor: resumeStringPtr("AuthenticAMD"), BundleUploadedAt: &uploaded,
			ResumeFailedHosts: []string{"host-x"},
		}
		withExcludes, _ := BuildResumeScheduleRequest(context.Background(), nil, rec, ResumeScheduleOpts{Region: "eu"})
		if len(withExcludes.ExcludeHosts) != 1 {
			t.Errorf("ExcludeHosts = %v, want [host-x]", withExcludes.ExcludeHosts)
		}
		cleared, _ := BuildResumeScheduleRequest(context.Background(), nil, rec, ResumeScheduleOpts{Region: "eu", ClearFailed: true})
		if len(cleared.ExcludeHosts) != 0 {
			t.Errorf("ExcludeHosts = %v, want empty", cleared.ExcludeHosts)
		}
	})
}
