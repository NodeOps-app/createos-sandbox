package vm

import (
	"testing"

	"github.com/NodeOps-app/sandbox/internal/proto"
	"github.com/NodeOps-app/sandbox/models"
)

func TestAllDiskReportsSettled(t *testing.T) {
	disks := []proto.MMDSDisk{
		{ID: "disk-a", MountPath: "/mnt/a"},
		{ID: "disk-b", MountPath: "/mnt/b"},
	}
	tests := []struct {
		name    string
		reports []agentDiskReport
		want    bool
	}{
		{name: "missing reports", want: false},
		{name: "one missing", reports: []agentDiskReport{
			{DiskID: "disk-a", MountPath: "/mnt/a", Status: models.SandboxDiskStatusMounted},
		}, want: false},
		{name: "pending", reports: []agentDiskReport{
			{DiskID: "disk-a", MountPath: "/mnt/a", Status: models.SandboxDiskStatusMounted},
			{DiskID: "disk-b", MountPath: "/mnt/b", Status: models.SandboxDiskStatusPending},
		}, want: false},
		{name: "mounted and failed are terminal", reports: []agentDiskReport{
			{DiskID: "disk-a", MountPath: "/mnt/a", Status: models.SandboxDiskStatusMounted},
			{DiskID: "disk-b", MountPath: "/mnt/b", Status: models.SandboxDiskStatusFailed},
		}, want: true},
		{name: "canonical paths match", reports: []agentDiskReport{
			{DiskID: "disk-a", MountPath: "/mnt/a/", Status: models.SandboxDiskStatusMounted},
			{DiskID: "disk-b", MountPath: "/mnt/b", Status: models.SandboxDiskStatusMounted},
			{DiskID: "unexpected", MountPath: "/mnt/x", Status: models.SandboxDiskStatusPending},
		}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allDiskReportsSettled(disks, tt.reports); got != tt.want {
				t.Fatalf("allDiskReportsSettled() = %v, want %v", got, tt.want)
			}
		})
	}
}
