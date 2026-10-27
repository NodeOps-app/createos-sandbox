package process

import (
	"container/list"
	"errors"
	"fmt"
	"sync"
)

const (
	defaultProcessOutputBytes  = 1 << 20  // 1 MiB per record
	defaultTotalOutputBytes    = 32 << 20 // 32 MiB across all records
	maxProcessOutputEventBytes = 32 << 10 // 32 KiB per event
)

type processOutputStream uint8

const (
	processOutputStdout processOutputStream = iota + 1
	processOutputStderr
	processOutputPTY
)

type processOutputEvent struct {
	Seq    uint64
	Stream processOutputStream
	Data   []byte
	global *list.Element
}

type processOutputReplay struct {
	Events []processOutputEvent
}

type processOutputBounds struct {
	OldestSeq uint64
	NewestSeq uint64
	Bytes     int
}

type OutputOffsetExpiredError struct {
	Requested       uint64
	OldestAvailable uint64
}

func (e *OutputOffsetExpiredError) Error() string {
	return fmt.Sprintf(
		"process output offset %d expired; oldest available sequence is %d",
		e.Requested,
		e.OldestAvailable,
	)
}

type processOutputJournal struct {
	mu sync.RWMutex

	maxBytes       int
	bytes          int
	nextSeq        uint64
	evictedThrough uint64
	events         []processOutputEvent
	changed        chan struct{}
	budget         *processOutputBudget
}

type retainedOutput struct {
	journal *processOutputJournal
	seq     uint64
}

// processOutputBudget bounds replay data across every record in one sandbox.
// Its list is ordered by append time, so pressure discards globally oldest
// output rather than penalizing whichever process happens to write next.
type processOutputBudget struct {
	mu       sync.Mutex
	maxBytes int
	bytes    int
	oldest   list.List
}

func newProcessOutputBudget(maxBytes int) (*processOutputBudget, error) {
	if maxBytes <= 0 {
		return nil, errors.New("total process output limit must be positive")
	}
	return &processOutputBudget{maxBytes: maxBytes}, nil
}

func newProcessOutputJournal(maxBytes int, budget *processOutputBudget) (*processOutputJournal, error) {
	if maxBytes <= 0 {
		return nil, errors.New("process output journal limit must be positive")
	}
	if budget == nil {
		return nil, errors.New("process output budget is required")
	}
	return &processOutputJournal{
		maxBytes: maxBytes,
		nextSeq:  1,
		changed:  make(chan struct{}),
		budget:   budget,
	}, nil
}

func (j *processOutputJournal) append(stream processOutputStream, data []byte) (uint64, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if !validProcessOutputStream(stream) {
		return 0, errors.New("invalid process output stream")
	}
	if len(data) > maxProcessOutputEventBytes || len(data) > j.maxBytes {
		return 0, errors.New("process output event exceeds journal limit")
	}

	// Always acquire budget before a journal. Global eviction may lock a
	// different journal, so this single lock order prevents cross-journal
	// deadlocks.
	j.budget.mu.Lock()
	defer j.budget.mu.Unlock()
	j.mu.Lock()

	seq := j.nextSeq
	j.nextSeq++
	event := processOutputEvent{
		Seq:    seq,
		Stream: stream,
		Data:   append([]byte(nil), data...),
	}
	j.events = append(j.events, event)
	j.bytes += len(event.Data)
	j.budget.bytes += len(event.Data)
	entry := retainedOutput{journal: j, seq: seq}
	j.events[len(j.events)-1].global = j.budget.oldest.PushBack(entry)

	for j.bytes > j.maxBytes && len(j.events) > 0 {
		j.dropOldestLocked()
	}
	close(j.changed)
	j.changed = make(chan struct{})
	j.mu.Unlock()

	for j.budget.bytes > j.budget.maxBytes {
		front := j.budget.oldest.Front()
		if front == nil {
			break
		}
		retained := front.Value.(retainedOutput)
		retained.journal.mu.Lock()
		retained.journal.dropSequenceLocked(retained.seq)
		retained.journal.mu.Unlock()
	}
	return seq, nil
}

func (j *processOutputJournal) dropOldestLocked() {
	if len(j.events) == 0 {
		return
	}
	event := j.events[0]
	j.evictedThrough = event.Seq
	j.bytes -= len(event.Data)
	j.budget.bytes -= len(event.Data)
	if event.global != nil {
		j.budget.oldest.Remove(event.global)
	}
	j.events[0] = processOutputEvent{}
	j.events = j.events[1:]
}

func (j *processOutputJournal) dropSequenceLocked(seq uint64) {
	// Global pressure always points at the oldest retained event. It must also
	// be this journal's oldest event because each journal preserves order.
	if len(j.events) == 0 || j.events[0].Seq != seq {
		return
	}
	j.dropOldestLocked()
}

func (j *processOutputJournal) clear() {
	j.budget.mu.Lock()
	defer j.budget.mu.Unlock()
	j.mu.Lock()
	defer j.mu.Unlock()
	for len(j.events) > 0 {
		j.dropOldestLocked()
	}
}

func (j *processOutputJournal) after(seq uint64) (processOutputReplay, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.afterLocked(seq)
}

func (j *processOutputJournal) afterAndNotify(seq uint64) (processOutputReplay, <-chan struct{}, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	replay, err := j.afterLocked(seq)
	return replay, j.changed, err
}

func (j *processOutputJournal) afterLocked(seq uint64) (processOutputReplay, error) {
	if seq < j.evictedThrough {
		oldestAvailable := j.nextSeq
		if len(j.events) > 0 {
			oldestAvailable = j.events[0].Seq
		}
		return processOutputReplay{}, &OutputOffsetExpiredError{
			Requested:       seq,
			OldestAvailable: oldestAvailable,
		}
	}
	if len(j.events) == 0 {
		return processOutputReplay{}, nil
	}

	replay := processOutputReplay{Events: make([]processOutputEvent, 0, len(j.events))}
	for _, event := range j.events {
		if event.Seq <= seq {
			continue
		}
		clone := event
		clone.Data = append([]byte(nil), event.Data...)
		replay.Events = append(replay.Events, clone)
	}
	return replay, nil
}

func (j *processOutputJournal) bounds() processOutputBounds {
	j.mu.RLock()
	defer j.mu.RUnlock()

	bounds := processOutputBounds{Bytes: j.bytes}
	if len(j.events) > 0 {
		bounds.OldestSeq = j.events[0].Seq
		bounds.NewestSeq = j.events[len(j.events)-1].Seq
	}
	return bounds
}

func validProcessOutputStream(stream processOutputStream) bool {
	return stream == processOutputStdout || stream == processOutputStderr || stream == processOutputPTY
}
