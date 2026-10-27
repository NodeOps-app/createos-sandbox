package audit

import (
	"testing"

	"github.com/NodeOps-app/sandbox/models"
)

func TestBuildSandboxDestroyDescribesAcceptedTransition(t *testing.T) {
	name := "test-sandbox"
	metadata := BuildSandboxDestroy(&models.Sandbox{
		ID:   "sb-test",
		Name: &name,
	}, "user", models.StatusDestroying)

	if metadata.SandboxID != "sb-test" {
		t.Fatalf("sandbox id = %q, want sb-test", metadata.SandboxID)
	}
	if metadata.Cause != "user" {
		t.Fatalf("cause = %q, want user", metadata.Cause)
	}
	if metadata.Status != string(models.StatusDestroying) {
		t.Fatalf("status = %q, want %q", metadata.Status, models.StatusDestroying)
	}
}
