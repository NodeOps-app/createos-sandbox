package sweep

import (
	"testing"

	"github.com/NodeOps-app/sandbox/models"
)

func TestClassifyDrainRowsWaitsForTransitions(t *testing.T) {
	rows := []models.Sandbox{
		{ID: "running", Status: models.StatusRunning},
		{ID: "paused", Status: models.StatusPaused},
		{ID: "creating", Status: models.StatusCreating},
		{ID: "pausing", Status: models.StatusPausing},
		{ID: "resuming", Status: models.StatusResuming},
		{ID: "destroying", Status: models.StatusDestroying},
	}

	running, paused, pending := classifyDrainRows(rows)
	if len(running) != 1 || running[0].ID != "running" {
		t.Fatalf("running = %#v", running)
	}
	if len(paused) != 1 || paused[0].ID != "paused" {
		t.Fatalf("paused = %#v", paused)
	}
	if pending != 4 {
		t.Fatalf("pending = %d, want 4", pending)
	}
}

func TestClassifyDrainRowsIgnoresTerminalRows(t *testing.T) {
	rows := []models.Sandbox{
		{ID: "destroyed", Status: models.StatusDestroyed},
		{ID: "failed", Status: models.StatusFailed},
		{ID: "error", Status: models.StatusError},
	}

	running, paused, pending := classifyDrainRows(rows)
	if len(running) != 0 || len(paused) != 0 || pending != 0 {
		t.Fatalf("running=%d paused=%d pending=%d, want all zero",
			len(running), len(paused), pending)
	}
}
