package leader

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewFillsDefaults(t *testing.T) {
	e := New(Config{}, Callbacks{})
	if e.cfg.AcquirePeriod != defaultAcquirePeriod {
		t.Errorf("AcquirePeriod default = %v, want %v", e.cfg.AcquirePeriod, defaultAcquirePeriod)
	}
	if e.cfg.LivenessPeriod != defaultLivenessPeriod {
		t.Errorf("LivenessPeriod default = %v, want %v", e.cfg.LivenessPeriod, defaultLivenessPeriod)
	}
	if e.IsLeader() {
		t.Error("IsLeader() = true before Run; want false")
	}
	if e.Epoch() != 0 {
		t.Errorf("Epoch() = %d before Run; want 0", e.Epoch())
	}
}

// fakeAcquirer drives the elector deterministically.
type fakeAcquirer struct {
	mu               sync.Mutex
	got              bool // value pg_try_advisory_lock returns
	acquireErr       error
	queryErr         error
	conns            int32 // outstanding held conns
	released         int32
	probes           int32
	probeErr         error // returned by Exec after `probesBeforeFail` calls
	probesBeforeFail int32
}

func (f *fakeAcquirer) Acquire(ctx context.Context) (heldConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.acquireErr != nil {
		return nil, f.acquireErr
	}
	atomic.AddInt32(&f.conns, 1)
	return &fakeConn{a: f}, nil
}

type fakeConn struct {
	a *fakeAcquirer
}

func (c *fakeConn) Exec(ctx context.Context, sql string, args ...any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.a.mu.Lock()
	defer c.a.mu.Unlock()
	n := atomic.AddInt32(&c.a.probes, 1)
	if c.a.probeErr != nil && n > c.a.probesBeforeFail {
		return c.a.probeErr
	}
	return nil
}

func (c *fakeConn) QueryBool(ctx context.Context, sql string, args ...any) (bool, error) {
	c.a.mu.Lock()
	defer c.a.mu.Unlock()
	if c.a.queryErr != nil {
		return false, c.a.queryErr
	}
	return c.a.got, nil
}

func (c *fakeConn) Release() {
	atomic.AddInt32(&c.a.released, 1)
}

func TestRunReturnsOnContextCancel(t *testing.T) {
	e := New(Config{AcquirePeriod: 5 * time.Millisecond}, Callbacks{})
	e.acq = &fakeAcquirer{got: false}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

func TestRunSurvivesAcquireErrors(t *testing.T) {
	fa := &fakeAcquirer{acquireErr: errors.New("dial error")}
	e := New(Config{AcquirePeriod: 2 * time.Millisecond}, Callbacks{})
	e.acq = fa
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := e.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run = %v, want DeadlineExceeded", err)
	}
	if e.IsLeader() {
		t.Error("IsLeader=true after run with no successful acquire")
	}
	if e.Epoch() != 0 {
		t.Errorf("Epoch=%d after no acquisitions; want 0", e.Epoch())
	}
}

func TestAcquireAndHold(t *testing.T) {
	fa := &fakeAcquirer{got: true}
	onAcquireFired := make(chan int64, 1)
	onLoseFired := make(chan struct{}, 1)
	e := New(Config{AcquirePeriod: 5 * time.Millisecond, LivenessPeriod: 5 * time.Millisecond}, Callbacks{
		OnAcquire: func(ctx context.Context) error {
			onAcquireFired <- 1
			<-ctx.Done()
			return ctx.Err()
		},
		OnLose: func() {
			onLoseFired <- struct{}{}
		},
	})
	e.acq = fa

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()

	select {
	case <-onAcquireFired:
	case <-time.After(time.Second):
		t.Fatal("OnAcquire did not fire")
	}
	if !e.IsLeader() {
		t.Error("IsLeader=false after acquisition")
	}
	if e.Epoch() != 1 {
		t.Errorf("Epoch=%d after acquisition; want 1", e.Epoch())
	}

	cancel()
	select {
	case <-onLoseFired:
	case <-time.After(time.Second):
		t.Fatal("OnLose did not fire after shutdown")
	}
	<-done
	if e.IsLeader() {
		t.Error("IsLeader=true after shutdown")
	}
	if atomic.LoadInt32(&fa.released) == 0 {
		t.Error("conn was never released")
	}
}

func TestLivenessFailureLosesLeadership(t *testing.T) {
	fa := &fakeAcquirer{
		got:              true,
		probeErr:         errors.New("conn dead"),
		probesBeforeFail: 1, // succeed once, then fail
	}
	loseCount := atomic.Int32{}
	acqCount := atomic.Int32{}
	e := New(Config{AcquirePeriod: 5 * time.Millisecond, LivenessPeriod: 5 * time.Millisecond}, Callbacks{
		OnAcquire: func(ctx context.Context) error {
			acqCount.Add(1)
			<-ctx.Done()
			return nil
		},
		OnLose: func() { loseCount.Add(1) },
	})
	e.acq = fa
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = e.Run(ctx)
	if loseCount.Load() == 0 {
		t.Error("OnLose never fired")
	}
	if acqCount.Load() < 1 {
		t.Error("OnAcquire never fired")
	}
	if e.Epoch() < 1 {
		t.Errorf("Epoch=%d, expected at least 1", e.Epoch())
	}
}
