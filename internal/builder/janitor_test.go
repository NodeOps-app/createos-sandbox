package builder

import (
	"context"
	"testing"
	"time"

	"github.com/NodeOps-app/sandbox/internal/buildqueue"
	"github.com/NodeOps-app/sandbox/internal/buildqueue/memqueue"
)

type janitorExecutor struct {
	sandboxes []BuildSandbox
	destroyed []string
	finished  map[string]bool
}

func (e *janitorExecutor) BuildProcessFinished(_ context.Context, sandbox BuildSandbox) (bool, error) {
	return e.finished[sandbox.ProcessID], nil
}

func (*janitorExecutor) Run(context.Context, BuildSpec) error { return nil }

func (e *janitorExecutor) ListBuildSandboxes(context.Context) ([]BuildSandbox, error) {
	return e.sandboxes, nil
}

func (e *janitorExecutor) DestroyBuildSandbox(_ context.Context, id string) error {
	e.destroyed = append(e.destroyed, id)
	return nil
}

func TestJanitorDeletesOnlyTerminalBuildSandboxes(t *testing.T) {
	ctx := context.Background()
	q := memqueue.New()
	for _, id := range []string{"tpl_building", "tpl_ready"} {
		if err := q.Enqueue(ctx, buildqueue.Job{TplID: id}); err != nil {
			t.Fatal(err)
		}
		if _, err := q.Claim(ctx, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.Complete(ctx, "tpl_ready", buildqueue.Outcome{Status: buildqueue.StatusReady}); err != nil {
		t.Fatal(err)
	}
	executor := &janitorExecutor{sandboxes: []BuildSandbox{
		{ID: "sb_running", TemplateID: "tpl_building"},
		{ID: "sb_done", TemplateID: "tpl_ready"},
		{ID: "sb_deleted_template", TemplateID: "tpl_missing"},
	}}
	service := NewService(Config{BuildTimeout: time.Hour}, q, nil, executor)

	service.runJanitorPass(ctx)

	if len(executor.destroyed) != 2 || executor.destroyed[0] != "sb_done" || executor.destroyed[1] != "sb_deleted_template" {
		t.Fatalf("destroyed = %#v", executor.destroyed)
	}
}

func TestJanitorLeavesTerminalSandboxOwnedByLiveWorker(t *testing.T) {
	ctx := context.Background()
	q := memqueue.New()
	if err := q.Enqueue(ctx, buildqueue.Job{TplID: "tpl_active"}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Claim(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := q.Complete(ctx, "tpl_active", buildqueue.Outcome{Status: buildqueue.StatusReady}); err != nil {
		t.Fatal(err)
	}
	executor := &janitorExecutor{sandboxes: []BuildSandbox{
		{ID: "sb_active", TemplateID: "tpl_active", ProcessID: "proc_active"},
	}}
	service := NewService(Config{BuildTimeout: time.Hour}, q, nil, executor)
	service.active["tpl_active"] = struct{}{}

	service.runJanitorPass(ctx)

	if len(executor.destroyed) != 0 {
		t.Fatalf("janitor destroyed live worker sandbox: %#v", executor.destroyed)
	}
}

func TestJanitorFailsAndDeletesFinishedRecoveredProcess(t *testing.T) {
	ctx := context.Background()
	q := memqueue.New()
	if err := q.Enqueue(ctx, buildqueue.Job{TplID: "tpl_recovered"}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Claim(ctx, nil); err != nil {
		t.Fatal(err)
	}
	executor := &janitorExecutor{
		sandboxes: []BuildSandbox{{ID: "sb_recovered", TemplateID: "tpl_recovered", ProcessID: "proc_recovered"}},
		finished:  map[string]bool{"proc_recovered": true},
	}
	service := NewService(Config{BuildTimeout: time.Hour}, q, nil, executor)

	service.runJanitorPass(ctx)

	terminal, err := q.Terminal(ctx, "tpl_recovered")
	if err != nil {
		t.Fatal(err)
	}
	if !terminal || len(executor.destroyed) != 1 || executor.destroyed[0] != "sb_recovered" {
		t.Fatalf("terminal=%v destroyed=%#v", terminal, executor.destroyed)
	}
}
