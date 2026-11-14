// Package leader elects a leader with a session-scoped PostgreSQL advisory
// lock. PostgreSQL releases the lock when the owning session ends. Network
// failures may take time to detect; callbacks must honor cancellation, and
// the lock alone does not fence already-running external work.
package leader

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultAcquirePeriod   = 1 * time.Second
	defaultLivenessPeriod  = 3 * time.Second
	onAcquireShutdownGrace = 5 * time.Second
)

// Config configures the elector.
type Config struct {
	Pool           *pgxpool.Pool
	Key            int64         // advisory lock key shared by replicas of the same role
	AcquirePeriod  time.Duration // default 1s
	LivenessPeriod time.Duration // default 3s
	Logger         *slog.Logger  // default slog.Default()
}

// Callbacks are fired on leadership transitions.
type Callbacks struct {
	// OnAcquire runs in a goroutine after acquisition. The ctx is cancelled
	// when leadership is lost. OnAcquire should block until ctx.Done(); its
	// return value is logged but does not stop the elector loop.
	OnAcquire func(ctx context.Context) error
	// OnLose is called synchronously after leadership is lost, before the
	// acquire loop resumes. Use it to clean up leader-only state.
	OnLose func()
}

// acquirer is an internal seam that lets tests inject a fake without
// constructing a real pgxpool.
type acquirer interface {
	Acquire(ctx context.Context) (heldConn, error)
}

// heldConn is the slice of *pgxpool.Conn the elector actually uses.
// Tests substitute a fake.
type heldConn interface {
	Exec(ctx context.Context, sql string, args ...any) error
	QueryBool(ctx context.Context, sql string, args ...any) (bool, error)
	Release()
}

// Elector runs a leader-election loop. Construct with New, then call Run.
type Elector struct {
	cfg      Config
	cb       Callbacks
	logger   *slog.Logger
	acq      acquirer
	isLeader atomic.Bool
	epoch    atomic.Int64
}

// New constructs an Elector against a real pgxpool.
func New(cfg Config, cb Callbacks) *Elector {
	if cfg.AcquirePeriod == 0 {
		cfg.AcquirePeriod = defaultAcquirePeriod
	}
	if cfg.LivenessPeriod == 0 {
		cfg.LivenessPeriod = defaultLivenessPeriod
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With(slog.String("component", "leader"), slog.Int64("key", cfg.Key))
	return &Elector{
		cfg:    cfg,
		cb:     cb,
		logger: logger,
		acq:    &pgxAcquirer{pool: cfg.Pool},
	}
}

// IsLeader reports current leader status. Safe from any goroutine.
func (e *Elector) IsLeader() bool { return e.isLeader.Load() }

// Epoch returns the monotonic counter that increments on every successful
// acquisition within this Elector instance. It resets with a new process and
// is not a globally monotonic database fencing token.
func (e *Elector) Epoch() int64 { return e.epoch.Load() }

// Run blocks until ctx is cancelled. Returns ctx.Err() on shutdown.
func (e *Elector) Run(ctx context.Context) error {
	t := time.NewTicker(e.cfg.AcquirePeriod)
	defer t.Stop()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		conn, err := e.tryAcquire(ctx)
		if err != nil {
			e.logger.Debug("acquire attempt failed", slog.String("err", err.Error()))
		} else if conn != nil {
			e.holdLeadership(ctx, conn)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// tryAcquire opens a dedicated connection and attempts pg_try_advisory_lock.
// Returns the held conn on success, nil on a clean miss (lock held elsewhere).
func (e *Elector) tryAcquire(ctx context.Context) (heldConn, error) {
	conn, err := e.acq.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire conn: %w", err)
	}
	got, err := conn.QueryBool(ctx, "SELECT pg_try_advisory_lock($1)", e.cfg.Key)
	if err != nil {
		conn.Release()
		return nil, fmt.Errorf("pg_try_advisory_lock: %w", err)
	}
	if !got {
		conn.Release()
		return nil, nil
	}
	return conn, nil
}

// holdLeadership runs while we own the lock. Spawns OnAcquire, runs liveness
// probes, and tears everything down on loss or shutdown.
func (e *Elector) holdLeadership(parent context.Context, conn heldConn) {
	leaderCtx, cancelLeader := context.WithCancel(parent)
	epoch := e.epoch.Add(1)
	e.isLeader.Store(true)
	e.logger.Info("acquired leadership", slog.Int64("epoch", epoch))

	done := make(chan struct{})
	go func() {
		defer close(done)
		if e.cb.OnAcquire == nil {
			<-leaderCtx.Done()
			return
		}
		if err := e.cb.OnAcquire(leaderCtx); err != nil && !errors.Is(err, context.Canceled) {
			e.logger.Warn("OnAcquire returned error", slog.String("err", err.Error()))
		}
	}()

	loseReason := e.runLiveness(parent, leaderCtx, conn)

	cancelLeader()
	select {
	case <-done:
	case <-time.After(onAcquireShutdownGrace):
		e.logger.Warn("OnAcquire did not return within grace period; continuing teardown")
	}

	e.isLeader.Store(false)
	if e.cb.OnLose != nil {
		e.cb.OnLose()
	}
	conn.Release()
	e.logger.Info("released leadership", slog.Int64("epoch", epoch), slog.String("reason", loseReason))
}

// runLiveness probes the held connection until it fails or shutdown is
// requested. Returns a short reason string for logging.
func (e *Elector) runLiveness(parent, leaderCtx context.Context, conn heldConn) string {
	t := time.NewTicker(e.cfg.LivenessPeriod)
	defer t.Stop()
	for {
		select {
		case <-parent.Done():
			return "shutdown"
		case <-leaderCtx.Done():
			return "leader-ctx-cancelled"
		case <-t.C:
			probeCtx, cancel := context.WithTimeout(parent, e.cfg.LivenessPeriod)
			err := conn.Exec(probeCtx, "SELECT 1")
			cancel()
			if err != nil {
				e.logger.Warn("liveness probe failed", slog.String("err", err.Error()))
				return "liveness-failed"
			}
		}
	}
}

// pgxAcquirer adapts a *pgxpool.Pool to the acquirer interface.
type pgxAcquirer struct {
	pool *pgxpool.Pool
}

func (a *pgxAcquirer) Acquire(ctx context.Context) (heldConn, error) {
	if a.pool == nil {
		return nil, errors.New("nil pool")
	}
	c, err := a.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	return &pgxHeldConn{c: c}, nil
}

type pgxHeldConn struct {
	c *pgxpool.Conn
}

func (p *pgxHeldConn) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := p.c.Exec(ctx, sql, args...)
	return err
}

func (p *pgxHeldConn) QueryBool(ctx context.Context, sql string, args ...any) (bool, error) {
	var got bool
	err := p.c.QueryRow(ctx, sql, args...).Scan(&got)
	return got, err
}

func (p *pgxHeldConn) Release() { p.c.Release() }
