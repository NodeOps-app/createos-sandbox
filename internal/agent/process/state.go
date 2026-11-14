package process

import (
	"context"
	"errors"

	"github.com/NodeOps-app/createos-sandbox/internal/proto"
)

const (
	ProcessKind = "process"
	PTYKind     = "pty"
)

type LifecycleState = proto.ProcessLifecycleState

const (
	LifecycleStarting    = proto.ProcessLifecycleStarting
	LifecycleRunning     = proto.ProcessLifecycleRunning
	LifecycleTerminating = proto.ProcessLifecycleTerminating
	LifecycleExited      = proto.ProcessLifecycleExited
	LifecycleFailed      = proto.ProcessLifecycleFailed
	LifecycleUnknown     = proto.ProcessLifecycleUnknown
)

// ProcessDetails is an immutable view of a managed process or PTY. ExitCode and
// Signal remain independent so a signal exit is never reported as a synthetic
// numeric exit code.
type ProcessDetails = proto.ProcessDetails

// ForegroundProcess is the process group leader that currently owns a PTY.
// Background jobs are intentionally omitted: this describes what an attached
// terminal user is interacting with right now.
type ForegroundProcess = proto.ProcessForeground

type OutputSummary = proto.ProcessOutputSummary

func (m *Manager) ListProcesses() []ProcessDetails {
	return m.listDetails()
}

func (m *Manager) InspectProcess(rawID string) (ProcessDetails, error) {
	return m.inspect(rawID)
}

func (m *Manager) WaitProcess(ctx context.Context, rawID string) (ProcessDetails, error) {
	return m.wait(ctx, rawID)
}

func (m *Manager) WaitProcessTree(ctx context.Context, rawID string) (ProcessDetails, error) {
	return m.waitTree(ctx, rawID)
}

func (m *Manager) listDetails() []ProcessDetails {
	infos := m.list()
	details := make([]ProcessDetails, 0, len(infos))
	for _, info := range infos {
		record, ok := m.get(info.ID)
		if !ok {
			continue
		}
		details = append(details, processDetailsFromRecord(record))
	}
	return details
}

func (m *Manager) inspect(rawID string) (ProcessDetails, error) {
	record, err := m.lookup(rawID)
	if err != nil {
		return ProcessDetails{}, err
	}
	return processDetailsFromRecord(record), nil
}

func (m *Manager) wait(ctx context.Context, rawID string) (ProcessDetails, error) {
	if ctx == nil {
		return ProcessDetails{}, errors.New("wait context is required")
	}
	record, err := m.lookup(rawID)
	if err != nil {
		return ProcessDetails{}, err
	}
	if _, err := record.wait(ctx); err != nil {
		return ProcessDetails{}, err
	}
	return processDetailsFromRecord(record), nil
}

func (m *Manager) waitTree(ctx context.Context, rawID string) (ProcessDetails, error) {
	if ctx == nil {
		return ProcessDetails{}, errors.New("wait context is required")
	}
	record, err := m.lookup(rawID)
	if err != nil {
		return ProcessDetails{}, err
	}
	if _, err := record.wait(ctx); err != nil {
		return ProcessDetails{}, err
	}
	cgroup := record.processCgroup()
	if cgroup == nil {
		return ProcessDetails{}, errors.New("managed process has no cgroup")
	}
	if err := cgroup.waitEmpty(ctx); err != nil {
		return ProcessDetails{}, err
	}
	return processDetailsFromRecord(record), nil
}

func processDetailsFromRecord(record *processRecord) ProcessDetails {
	info := record.info()
	bounds := record.output.bounds()
	details := ProcessDetails{
		ID:           string(info.ID),
		Kind:         processKindName(info.Mode),
		Cwd:          info.Cwd,
		PID:          info.PID,
		State:        processStateName(info.State),
		LeaderExited: info.State.ended(),
		CreatedAt:    info.CreatedAt,
		Output:       OutputSummary(bounds),
	}
	if len(info.Argv) > 0 {
		details.Cmd = info.Argv[0]
		details.Args = append([]string(nil), info.Argv[1:]...)
	}
	if info.Mode == processModePTY {
		details.Foreground = record.foregroundProcess()
	}
	if cgroup := record.processCgroup(); cgroup != nil {
		if populated, err := cgroup.populated(); err == nil {
			details.TreeExited = !populated
		}
	}
	if info.Result != nil {
		details.ExitCode = cloneInt(info.Result.ExitCode)
		details.Signal = info.Result.Signal
		details.Error = info.Result.Error
		if !info.Result.ExitedAt.IsZero() {
			finishedAt := info.Result.ExitedAt
			details.FinishedAt = &finishedAt
		}
	}
	return details
}

func processKindName(mode processMode) string {
	switch mode {
	case processModePipes:
		return ProcessKind
	case processModePTY:
		return PTYKind
	default:
		return "unknown"
	}
}

func processStateName(state processState) LifecycleState {
	switch state {
	case processStateStarting:
		return LifecycleStarting
	case processStateRunning:
		return LifecycleRunning
	case processStateTerminating:
		return LifecycleTerminating
	case processStateExited:
		return LifecycleExited
	case processStateFailed:
		return LifecycleFailed
	default:
		return LifecycleUnknown
	}
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
