package proto

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

type ProcessLifecycleState string

const (
	ProcessLifecycleStarting    ProcessLifecycleState = "starting"
	ProcessLifecycleRunning     ProcessLifecycleState = "running"
	ProcessLifecycleTerminating ProcessLifecycleState = "terminating"
	ProcessLifecycleExited      ProcessLifecycleState = "exited"
	ProcessLifecycleFailed      ProcessLifecycleState = "failed"
	ProcessLifecycleUnknown     ProcessLifecycleState = "unknown"
)

// ProcessDetails is the managed-process wire representation shared by the
// guest agent, host proxy, control API, and API clients.
type ProcessDetails struct {
	ID           string                `json:"process_id"`
	Kind         string                `json:"kind"`
	Cmd          string                `json:"cmd"`
	Args         []string              `json:"args,omitempty"`
	Cwd          string                `json:"cwd"`
	Foreground   *ProcessForeground    `json:"foreground,omitempty"`
	PID          int                   `json:"pid"`
	State        ProcessLifecycleState `json:"state"`
	LeaderExited bool                  `json:"leader_exited"`
	TreeExited   bool                  `json:"tree_exited"`
	CreatedAt    time.Time             `json:"created_at"`
	FinishedAt   *time.Time            `json:"finished_at"`
	ExitCode     *int                  `json:"exit_code"`
	Signal       string                `json:"signal,omitempty"`
	Error        string                `json:"-"`
	Output       ProcessOutputSummary  `json:"output"`
}

type ProcessForeground struct {
	PID  int      `json:"pid"`
	Cmd  string   `json:"cmd"`
	Args []string `json:"args,omitempty"`
}

type ProcessOutputSummary struct {
	OldestSeq uint64 `json:"oldest_seq"`
	NewestSeq uint64 `json:"newest_seq"`
	Bytes     int    `json:"bytes"`
}

const managedProcessIDRandomBytes = 16

// ValidateManagedProcessID checks the format of opaque guest-agent IDs.
// It does not prove an ID was issued or authorize access to its process.
// Public and host proxies call this before interpolating an ID into an upstream
// URL, preventing encoded separators or path traversal from reaching a router.
func ValidateManagedProcessID(raw string) error {
	prefix := ""
	switch {
	case strings.HasPrefix(raw, "proc_"):
		prefix = "proc_"
	case strings.HasPrefix(raw, "pty_"):
		prefix = "pty_"
	default:
		return errors.New("invalid managed process id")
	}
	encoded := strings.TrimPrefix(raw, prefix)
	if len(encoded) != base64.RawURLEncoding.EncodedLen(managedProcessIDRandomBytes) {
		return errors.New("invalid managed process id")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != managedProcessIDRandomBytes {
		return errors.New("invalid managed process id")
	}
	return nil
}
