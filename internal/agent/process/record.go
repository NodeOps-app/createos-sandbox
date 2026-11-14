package process

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/proto"
)

const processIDRandomBytes = 16

type processID string

type processMode uint8

const (
	processModePipes processMode = iota + 1
	processModePTY
)

func newProcessID(mode processMode) (processID, error) {
	prefix, err := processIDPrefix(mode)
	if err != nil {
		return "", err
	}

	random := make([]byte, processIDRandomBytes)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate process record id: %w", err)
	}
	return processID(prefix + base64.RawURLEncoding.EncodeToString(random)), nil
}

func parseProcessID(raw string) (processID, error) {
	if err := proto.ValidateManagedProcessID(raw); err != nil {
		return "", err
	}
	return processID(raw), nil
}

func processIDPrefix(mode processMode) (string, error) {
	switch mode {
	case processModePipes:
		return "proc_", nil
	case processModePTY:
		return "pty_", nil
	default:
		return "", errors.New("unknown process record mode")
	}
}

type processState uint8

const (
	processStateStarting processState = iota + 1
	processStateRunning
	processStateTerminating
	processStateExited
	processStateFailed
)

func (s processState) ended() bool {
	return s == processStateExited || s == processStateFailed
}

func validProcessTransition(from, to processState) bool {
	switch from {
	case processStateStarting:
		return to == processStateRunning || to == processStateFailed
	case processStateRunning:
		return to == processStateTerminating || to == processStateExited
	case processStateTerminating:
		return to == processStateExited || to == processStateFailed
	default:
		return false
	}
}

type processResult struct {
	ExitCode *int
	Signal   string
	Error    string
	ExitedAt time.Time
}

type processInfo struct {
	ID        processID
	Mode      processMode
	Argv      []string
	Cwd       string
	PID       int
	PGID      int
	State     processState
	CreatedAt time.Time
	Result    *processResult
}

type processRecord struct {
	id        processID
	mode      processMode
	argv      []string
	cwd       string
	pid       int
	pgid      int
	createdAt time.Time

	mu          sync.RWMutex
	terminateMu sync.Mutex
	inputSeq    uint64
	inputClosed bool
	inputOps    chan inputOperation
	state       processState
	result      *processResult
	done        chan struct{}
	doneOnce    sync.Once
	outputDone  chan struct{}
	outputOnce  sync.Once
	output      *processOutputJournal
	stdin       io.WriteCloser
	pty         *os.File
	cgroup      *processCgroup
}

func (r *processRecord) setCgroup(cgroup *processCgroup) error {
	if cgroup == nil {
		return errors.New("process cgroup is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cgroup != nil {
		return errors.New("process cgroup is already set")
	}
	r.cgroup = cgroup
	return nil
}

func (r *processRecord) processCgroup() *processCgroup {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cgroup
}

func (r *processRecord) treeExited() bool {
	cgroup := r.processCgroup()
	if cgroup == nil {
		return false
	}
	populated, err := cgroup.populated()
	return err == nil && !populated
}

func (r *processRecord) started(pid, pgid int, stdin io.WriteCloser, pty *os.File) error {
	if pid <= 0 || pgid <= 0 {
		return errors.New("started process requires positive pid and pgid")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if !validProcessTransition(r.state, processStateRunning) {
		return fmt.Errorf("cannot start process record from state %d", r.state)
	}
	r.pid = pid
	r.pgid = pgid
	r.stdin = stdin
	r.pty = pty
	r.state = processStateRunning
	return nil
}

func newProcessRecord(
	id processID,
	mode processMode,
	pid int,
	pgid int,
	createdAt time.Time,
	output *processOutputJournal,
	argv []string,
	cwd string,
) (*processRecord, error) {
	parsed, err := parseProcessID(string(id))
	if err != nil {
		return nil, err
	}
	prefix, err := processIDPrefix(mode)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(string(parsed), prefix) {
		return nil, errors.New("process record id does not match mode")
	}
	if output == nil {
		return nil, errors.New("process record output journal is required")
	}
	if createdAt.IsZero() {
		createdAt = time.Now()
	}

	record := &processRecord{
		id:         parsed,
		mode:       mode,
		argv:       append([]string(nil), argv...),
		cwd:        cwd,
		pid:        pid,
		pgid:       pgid,
		createdAt:  createdAt,
		state:      processStateStarting,
		done:       make(chan struct{}),
		outputDone: make(chan struct{}),
		output:     output,
		inputOps:   make(chan inputOperation, maxQueuedInputOperations),
	}
	return record, nil
}

func (r *processRecord) finishOutput() {
	r.outputOnce.Do(func() { close(r.outputDone) })
}

func (r *processRecord) outputFinished() bool {
	select {
	case <-r.outputDone:
		return true
	default:
		return false
	}
}

func (r *processRecord) info() processInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return processInfo{
		ID:        r.id,
		Mode:      r.mode,
		Argv:      append([]string(nil), r.argv...),
		Cwd:       r.cwd,
		PID:       r.pid,
		PGID:      r.pgid,
		State:     r.state,
		CreatedAt: r.createdAt,
		Result:    cloneProcessResult(r.result),
	}
}

// finish atomically records the first terminal result. Competing exit and
// termination observers return false without replacing the winning result.
func (r *processRecord) finish(state processState, result processResult) bool {
	if !state.ended() {
		return false
	}

	r.mu.Lock()
	if r.state.ended() || !validProcessTransition(r.state, state) {
		r.mu.Unlock()
		return false
	}
	resultCopy := result
	r.state = state
	r.result = &resultCopy
	r.mu.Unlock()

	r.doneOnce.Do(func() { close(r.done) })
	return true
}

func (r *processRecord) wait(ctx context.Context) (processInfo, error) {
	select {
	case <-r.done:
		return r.info(), nil
	case <-ctx.Done():
		return processInfo{}, ctx.Err()
	}
}

func (r *processRecord) appendOutput(stream processOutputStream, data []byte) (uint64, error) {
	if !r.acceptsOutputStream(stream) {
		return 0, errors.New("output stream does not match process record mode")
	}
	return r.output.append(stream, data)
}

func (r *processRecord) acceptsOutputStream(stream processOutputStream) bool {
	switch r.mode {
	case processModePipes:
		return stream == processOutputStdout || stream == processOutputStderr
	case processModePTY:
		return stream == processOutputPTY
	default:
		return false
	}
}

func (r *processRecord) closeRuntimeIO() {
	r.mu.Lock()
	stdin := r.stdin
	pty := r.pty
	r.stdin = nil
	r.pty = nil
	r.inputClosed = true
	r.mu.Unlock()

	if stdin != nil {
		_ = stdin.Close()
	}
	if pty != nil {
		_ = pty.Close()
	}
}

func cloneProcessResult(result *processResult) *processResult {
	if result == nil {
		return nil
	}
	clone := *result
	if result.ExitCode != nil {
		exitCode := *result.ExitCode
		clone.ExitCode = &exitCode
	}
	return &clone
}
