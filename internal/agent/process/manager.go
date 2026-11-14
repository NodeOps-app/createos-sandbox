package process

import (
	"errors"
	"sort"
	"sync"
	"time"
)

const (
	defaultMaxProcesses = 128
	defaultMaxObservers = 64
)

// Config contains guest-local limits for managed processes and observers.
// The agent uses defaults; these values are not exposed as public API or host
// configuration.
type Config struct {
	MaxProcesses     int
	MaxObservers     int
	OutputBytes      int
	TotalOutputBytes int
}

type Manager struct {
	mu           sync.RWMutex
	processes    map[processID]*processRecord
	max          int
	observers    chan struct{}
	outputBytes  int
	outputBudget *processOutputBudget
	now          func() time.Time
}

var (
	errProcessDuplicate = errors.New("process record already exists")
	errProcessLimit     = errors.New("process record limit reached")
	errObserverLimit    = errors.New("process observer limit reached")
)

func NewManager(config Config) (*Manager, error) {
	if config.MaxProcesses == 0 {
		config.MaxProcesses = defaultMaxProcesses
	}
	if config.MaxObservers == 0 {
		config.MaxObservers = defaultMaxObservers
	}
	if config.OutputBytes == 0 {
		config.OutputBytes = defaultProcessOutputBytes
	}
	if config.TotalOutputBytes == 0 {
		config.TotalOutputBytes = defaultTotalOutputBytes
	}
	if config.MaxProcesses < 0 {
		return nil, errors.New("process manager record limit must be positive")
	}
	if config.MaxObservers < 0 {
		return nil, errors.New("process manager observer limit must be positive")
	}
	if config.OutputBytes < maxProcessOutputEventBytes {
		return nil, errors.New("process manager output limit is too small")
	}
	if config.TotalOutputBytes < config.OutputBytes {
		return nil, errors.New("total process output limit must not be smaller than per-process limit")
	}
	budget, err := newProcessOutputBudget(config.TotalOutputBytes)
	if err != nil {
		return nil, err
	}

	return &Manager{
		processes:    make(map[processID]*processRecord),
		max:          config.MaxProcesses,
		observers:    make(chan struct{}, config.MaxObservers),
		outputBytes:  config.OutputBytes,
		outputBudget: budget,
		now:          time.Now,
	}, nil
}

type CreatedProcess struct {
	ID  string
	PID int
}

func (m *Manager) reserveProcess(mode processMode, argv []string, cwd string) (*processRecord, error) {
	journal, err := newProcessOutputJournal(m.outputBytes, m.outputBudget)
	if err != nil {
		return nil, err
	}

	// A collision is cryptographically implausible, but retry rather than
	// making it observable as a creation failure.
	for range 4 {
		id, err := newProcessID(mode)
		if err != nil {
			return nil, err
		}
		record, err := newProcessRecord(id, mode, 0, 0, m.now(), journal, argv, cwd)
		if err != nil {
			return nil, err
		}
		if err := m.add(record); err == nil {
			go record.runInputLoop()
			return record, nil
		} else if !errors.Is(err, errProcessDuplicate) {
			return nil, err
		}
	}
	return nil, errors.New("could not allocate unique process record id")
}

func (m *Manager) add(record *processRecord) error {
	if record == nil {
		return errors.New("process record is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.processes[record.id]; exists {
		return errProcessDuplicate
	}
	if len(m.processes) >= m.max {
		// The limit protects concurrent resources and retained replay data; it
		// must not become a lifetime creation quota. Reclaim the oldest completed
		// record under pressure while never evicting a running process or PTY.
		var oldest *processRecord
		for _, candidate := range m.processes {
			info := candidate.info()
			if !info.State.ended() || !candidate.outputFinished() || !candidate.treeExited() {
				continue
			}
			if oldest == nil || info.CreatedAt.Before(oldest.info().CreatedAt) {
				oldest = candidate
			}
		}
		if oldest == nil {
			return errProcessLimit
		}
		delete(m.processes, oldest.id)
		oldest.output.clear()
	}
	m.processes[record.id] = record
	return nil
}

func (m *Manager) acquireObserver() (func(), error) {
	select {
	case m.observers <- struct{}{}:
		return func() { <-m.observers }, nil
	default:
		return nil, errObserverLimit
	}
}

func (m *Manager) get(id processID) (*processRecord, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	record, ok := m.processes[id]
	return record, ok
}

func (m *Manager) list() []processInfo {
	m.mu.RLock()
	processes := make([]*processRecord, 0, len(m.processes))
	for _, record := range m.processes {
		processes = append(processes, record)
	}
	m.mu.RUnlock()

	infos := make([]processInfo, 0, len(processes))
	for _, record := range processes {
		infos = append(infos, record.info())
	}
	sort.Slice(infos, func(i, j int) bool {
		if infos[i].CreatedAt.Equal(infos[j].CreatedAt) {
			return infos[i].ID < infos[j].ID
		}
		return infos[i].CreatedAt.Before(infos[j].CreatedAt)
	})
	return infos
}

func (m *Manager) remove(id processID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	record, exists := m.processes[id]
	if !exists {
		return false
	}
	delete(m.processes, id)
	record.output.clear()
	return true
}
