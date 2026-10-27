package process

import (
	"context"
	"errors"
	"log"
	"syscall"
	"time"
)

func (m *Manager) TerminateProcess(ctx context.Context, rawID string, grace time.Duration) (ProcessDetails, error) {
	return m.terminate(ctx, rawID, grace)
}

func (m *Manager) terminate(
	ctx context.Context,
	rawID string,
	grace time.Duration,
) (ProcessDetails, error) {
	if ctx == nil {
		return ProcessDetails{}, errors.New("termination context is required")
	}
	if err := ctx.Err(); err != nil {
		return ProcessDetails{}, err
	}
	if grace < 0 {
		return ProcessDetails{}, errors.New("termination grace period cannot be negative")
	}

	record, err := m.lookup(rawID)
	if err != nil {
		return ProcessDetails{}, err
	}

	// Serialize the full terminate-and-wait sequence. Repeated deletion is
	// idempotent and cannot start competing grace timers or signal escalation.
	record.terminateMu.Lock()
	defer record.terminateMu.Unlock()
	if err := ctx.Err(); err != nil {
		return ProcessDetails{}, err
	}

	pgid, cgroup, err := record.beginTermination()
	if err != nil {
		return ProcessDetails{}, err
	}
	if pgid <= 0 {
		return ProcessDetails{}, errors.New("managed process has no process group")
	}

	if cgroup == nil {
		return ProcessDetails{}, errors.New("managed process has no cgroup")
	}

	err = cgroup.signal(syscall.SIGTERM)
	if err != nil {
		return ProcessDetails{}, err
	}
	empty, err := waitProcessCgroupFor(ctx, cgroup, grace)
	if err != nil {
		return ProcessDetails{}, err
	}
	forced := !empty
	if forced {
		if err := cgroup.kill(); err != nil {
			return ProcessDetails{}, err
		}
		if err := waitProcessCgroupEmpty(ctx, cgroup); err != nil {
			return ProcessDetails{}, err
		}
	}

	if _, err := record.wait(ctx); err != nil {
		return ProcessDetails{}, err
	}
	if err := cgroup.remove(); err != nil {
		return ProcessDetails{}, err
	}
	details := processDetailsFromRecord(record)
	log.Printf("agent.process event=terminated process_id=%s kind=%s pid=%d forced=%t grace_ms=%d",
		details.ID, details.Kind, details.PID, forced, grace/time.Millisecond)
	return details, nil
}

func (r *processRecord) beginTermination() (int, *processCgroup, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.pgid <= 0 {
		return 0, nil, errors.New("managed process has not started")
	}
	switch r.state {
	case processStateRunning:
		r.state = processStateTerminating
	case processStateTerminating, processStateExited, processStateFailed:
		// A repeated termination continues observing the original cgroup.
		// This also cleans descendants that outlived an already-exited leader.
	case processStateStarting:
		return 0, nil, errors.New("managed process is still starting")
	default:
		return 0, nil, errors.New("managed process has an unknown lifecycle state")
	}
	return r.pgid, r.cgroup, nil
}

func waitProcessCgroupFor(ctx context.Context, cgroup *processCgroup, grace time.Duration) (bool, error) {
	return cgroup.waitEmptyFor(ctx, grace)
}

func waitProcessCgroupEmpty(ctx context.Context, cgroup *processCgroup) error {
	return cgroup.waitEmpty(ctx)
}
