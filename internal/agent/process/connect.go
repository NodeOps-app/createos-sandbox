package process

import (
	"context"
	"errors"
	"sync"
)

type OutputStream string

const (
	OutputStdout OutputStream = "stdout"
	OutputStderr OutputStream = "stderr"
	OutputPTY    OutputStream = "pty"
)

type OutputEvent struct {
	Seq    uint64
	Stream OutputStream
	Data   []byte
}

// OutputBatch contains newly available output. Ended is true only after all
// output retained at process completion has been returned. Final is populated
// with the immutable exit details when Ended is true.
type OutputBatch struct {
	Events []OutputEvent
	Ended  bool
	Final  *ProcessDetails
}

// OutputReader is one reconnectable view over a process output journal. It
// keeps only the caller's cursor; reading does not consume shared output.
type OutputReader struct {
	record *processRecord
	after  uint64
	mu     sync.Mutex
}

func (m *Manager) ConnectOutput(rawID string, after uint64) (*OutputReader, error) {
	record, err := m.lookup(rawID)
	if err != nil {
		return nil, err
	}
	if _, err := record.output.after(after); err != nil {
		return nil, err
	}
	return &OutputReader{record: record, after: after}, nil
}

// Next returns immediately when replay is available. Otherwise it waits for
// new output, process completion, or context cancellation.
func (r *OutputReader) Next(ctx context.Context) (OutputBatch, error) {
	if ctx == nil {
		return OutputBatch{}, errors.New("output context is required")
	}
	if err := ctx.Err(); err != nil {
		return OutputBatch{}, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for {
		replay, changed, err := r.record.output.afterAndNotify(r.after)
		if err != nil {
			return OutputBatch{}, err
		}
		if len(replay.Events) > 0 {
			events := make([]OutputEvent, 0, len(replay.Events))
			for _, event := range replay.Events {
				stream, err := outputStreamName(event.Stream)
				if err != nil {
					return OutputBatch{}, err
				}
				events = append(events, OutputEvent{
					Seq:    event.Seq,
					Stream: stream,
					Data:   append([]byte(nil), event.Data...),
				})
			}
			r.after = replay.Events[len(replay.Events)-1].Seq
			return OutputBatch{Events: events}, nil
		}

		select {
		case <-changed:
			continue
		case <-r.record.outputDone:
			// Recheck the journal before reporting completion. The final output
			// append and completion notification may become visible together.
			replay, _, err := r.record.output.afterAndNotify(r.after)
			if err != nil {
				return OutputBatch{}, err
			}
			if len(replay.Events) > 0 {
				continue
			}
			final := processDetailsFromRecord(r.record)
			return OutputBatch{Ended: true, Final: &final}, nil
		case <-ctx.Done():
			return OutputBatch{}, ctx.Err()
		}
	}
}

func outputStreamName(stream processOutputStream) (OutputStream, error) {
	switch stream {
	case processOutputStdout:
		return OutputStdout, nil
	case processOutputStderr:
		return OutputStderr, nil
	case processOutputPTY:
		return OutputPTY, nil
	default:
		return "", errors.New("unknown process output stream")
	}
}
