package process

import (
	"context"
	"errors"
	"io"
	"syscall"
)

var (
	ErrProcessNotFound = errors.New("process not found")
	ErrWrongMode       = errors.New("operation is not supported for this process mode")
	ErrProcessExited   = errors.New("process has exited")
	ErrStdinClosed     = errors.New("process stdin is closed")
)

type InputReceipt struct {
	Seq uint64
}

const maxQueuedInputOperations = 8

type inputOperationKind uint8

const (
	inputOperationWrite inputOperationKind = iota + 1
	inputOperationClose
)

type inputOperation struct {
	ctx    context.Context
	kind   inputOperationKind
	data   []byte
	result chan inputOperationResult
}

type inputOperationResult struct {
	seq uint64
	err error
}

func (m *Manager) WriteInput(ctx context.Context, rawID string, data []byte) (InputReceipt, error) {
	record, err := m.lookup(rawID)
	if err != nil {
		return InputReceipt{}, err
	}
	seq, err := record.submitInput(ctx, inputOperationWrite, data)
	if err != nil {
		return InputReceipt{}, err
	}
	return InputReceipt{Seq: seq}, nil
}

func (m *Manager) CloseStdin(ctx context.Context, rawID string) error {
	record, err := m.lookup(rawID)
	if err != nil {
		return err
	}
	if record.mode != processModePipes {
		return ErrWrongMode
	}
	if record.stdinIsClosed() {
		return nil
	}
	_, err = record.submitInput(ctx, inputOperationClose, nil)
	if errors.Is(err, ErrProcessExited) && record.stdinIsClosed() {
		return nil
	}
	return err
}

func (r *processRecord) stdinIsClosed() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.inputClosed
}

func (m *Manager) ResizePTY(rawID string, rows, cols uint16) error {
	if rows == 0 || cols == 0 {
		return errors.New("PTY rows and columns must be positive")
	}
	record, err := m.lookup(rawID)
	if err != nil {
		return err
	}
	return record.resizePTY(rows, cols)
}

func (m *Manager) Signal(rawID string, signal syscall.Signal) error {
	if signal <= 0 {
		return errors.New("invalid process signal")
	}
	record, err := m.lookup(rawID)
	if err != nil {
		return err
	}
	return record.signal(signal)
}

func (m *Manager) lookup(rawID string) (*processRecord, error) {
	id, err := parseProcessID(rawID)
	if err != nil {
		return nil, ErrProcessNotFound
	}
	record, ok := m.get(id)
	if !ok {
		return nil, ErrProcessNotFound
	}
	return record, nil
}

func (r *processRecord) submitInput(ctx context.Context, kind inputOperationKind, data []byte) (uint64, error) {
	if ctx == nil {
		return 0, errors.New("input context is required")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	operation := inputOperation{
		ctx:    ctx,
		kind:   kind,
		data:   append([]byte(nil), data...),
		result: make(chan inputOperationResult, 1),
	}
	select {
	case r.inputOps <- operation:
	case <-r.done:
		return 0, ErrProcessExited
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	select {
	case result := <-operation.result:
		return result.seq, result.err
	case <-r.done:
		return 0, ErrProcessExited
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (r *processRecord) runInputLoop() {
	for {
		select {
		case operation := <-r.inputOps:
			seq, err := r.applyInputOperation(operation)
			operation.result <- inputOperationResult{seq: seq, err: err}
		case <-r.done:
			return
		}
	}
}

func (r *processRecord) applyInputOperation(operation inputOperation) (uint64, error) {
	// Cancellation while queued must not deliver stale input or close stdin.
	// Once a write has begun, cancellation cannot retract bytes already sent.
	if err := operation.ctx.Err(); err != nil {
		return 0, err
	}
	switch operation.kind {
	case inputOperationWrite:
		writer, err := r.inputWriter()
		if err != nil {
			return 0, err
		}
		if len(operation.data) == 0 {
			return r.inputSeq, nil
		}
		if err := writeAll(writer, operation.data); err != nil {
			return 0, err
		}
		r.inputSeq++
		return r.inputSeq, nil
	case inputOperationClose:
		return r.inputSeq, r.closeStdinDirect()
	default:
		return 0, errors.New("unknown input operation")
	}
}

func (r *processRecord) closeStdinDirect() error {
	r.mu.Lock()
	if r.inputClosed {
		r.mu.Unlock()
		return nil
	}
	stdin := r.stdin
	r.stdin = nil
	state := r.state
	r.inputClosed = true
	r.mu.Unlock()
	if stdin == nil {
		if state.ended() {
			return ErrProcessExited
		}
		return ErrStdinClosed
	}
	return stdin.Close()
}

func (r *processRecord) resizePTY(rows, cols uint16) error {
	if r.mode != processModePTY {
		return ErrWrongMode
	}

	r.mu.RLock()
	master := r.pty
	state := r.state
	r.mu.RUnlock()
	if master == nil || state.ended() {
		return ErrProcessExited
	}
	return setWinsize(master, rows, cols)
}

func (r *processRecord) signal(signal syscall.Signal) error {
	r.mu.RLock()
	mode := r.mode
	pgid := r.pgid
	state := r.state
	r.mu.RUnlock()
	if state.ended() || pgid <= 0 {
		return ErrProcessExited
	}

	if mode == processModePipes {
		return syscall.Kill(-pgid, signal)
	}
	if mode != processModePTY {
		return ErrWrongMode
	}

	r.mu.RLock()
	master := r.pty
	r.mu.RUnlock()
	if master == nil {
		return ErrProcessExited
	}
	foregroundPGID, err := foregroundProcessGroup(master)
	if err != nil {
		return err
	}
	return syscall.Kill(-foregroundPGID, signal)
}

func (r *processRecord) inputWriter() (io.Writer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.inputClosed {
		return nil, ErrStdinClosed
	}
	if r.state.ended() {
		return nil, ErrProcessExited
	}
	switch r.mode {
	case processModePipes:
		if r.stdin == nil {
			return nil, ErrStdinClosed
		}
		return r.stdin, nil
	case processModePTY:
		if r.pty == nil {
			return nil, ErrProcessExited
		}
		return r.pty, nil
	default:
		return nil, ErrWrongMode
	}
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
