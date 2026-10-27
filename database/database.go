package database

import (
	"context"
	_ "embed"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/knadh/goyesql/v2"
)

//go:embed queries.sql
var queriesSQL []byte

// Db wraps the pgxpool connection + parsed named queries.
//
// Schema is operator-managed via the standalone goose CLI (see
// `make migrate-up` / `make migrate-status`); the binary never reads
// or applies migrations. The migration files live under
// internal/store/migrations_fs/ as plain .sql files for goose to
// consume — the Go code does not embed or reference them.
type Db struct {
	Con     *pgxpool.Pool
	queries goyesql.Queries
}

// PoolConfig overrides the process-default pgxpool bounds for callers with a
// known concurrency profile. Zero values retain the defaults. WarmConns are
// acquired and held once during startup so readiness cannot race the first
// production burst while pgx is still growing the pool.
type PoolConfig struct {
	MinConns  int32
	MaxConns  int32
	WarmConns int32
}

// GetQuery returns the SQL string registered under the given name in
// queries.sql (the "-- name:" tag). Second return is false when missing.
func (d *Db) GetQuery(name string) (string, bool) {
	q, ok := d.queries[name]
	if !ok {
		return "", false
	}
	return q.Query, true
}

// Close releases the underlying pgxpool.
func (d *Db) Close() {
	if d.Con != nil {
		d.Con.Close()
	}
}

// OpenDb opens a pgxpool against dsn and returns a ready-to-use *Db.
//
// The app refuses no schema state from here — `goose status` and
// `goose up` are operator runbook commands. If the binary's expected
// columns aren't present, queries fail at first use; that's the
// intended fail-fast signal that a migration was missed during
// rollout.
func OpenDb(ctx context.Context, dsn string) (*Db, error) {
	return OpenDbWithPoolConfig(ctx, dsn, PoolConfig{})
}

// OpenDbWithPoolConfig is OpenDb with caller-specific connection-pool bounds.
func OpenDbWithPoolConfig(ctx context.Context, dsn string, poolConfig PoolConfig) (*Db, error) {
	queries, err := goyesql.ParseBytes(queriesSQL)
	if err != nil {
		return nil, fmt.Errorf("parse queries.sql: %w", err)
	}

	// Parse config so we can pin lifecycle knobs regardless of the DSN.
	// Without these, CLOSE_WAIT conns accumulate silently when Postgres
	// closes sessions (idle-in-tx timeout, restart, backend kill) — pgx
	// doesn't notice until the next Acquire returns a dead conn that
	// hangs on Read. Aggressive lifetime + healthcheck forces churn so
	// half-dead conns get discovered proactively.
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("pgxpool parse: %w", err)
	}
	if traceEnabled.Load() {
		cfg.ConnConfig.Tracer = latencyTracer{}
	}
	// Pool sizing: default is runtime.NumCPU() which is 4 on a typical
	// k8s pod — pathologically small for a control plane fanning 3+
	// hosts plus 100-concurrent user creates. Under burst we exhaust
	// in milliseconds and every downstream stalls on Acquire.
	//
	// Bumped 60 → 120 after N=100 [pool-claim-stages] histogram showed
	// `begin` (pgxpool.Acquire + tx.Begin) p99 = 132 ms — pure Acquire
	// queue wait when 100 concurrent creates hit 60/pod × 3 = 180 slots
	// (each pool_hit does TWO Begins: main claim tx + separate billing
	// INSERT tx, so 200 concurrent Acquires competing for 180 slots).
	// 120 per pod leaves enough headroom for the current double-Begin
	// pattern. Trade-off: ~10 MB of idle backend memory per slot, so size
	// Postgres max_connections for pods × 120. Revert if pg memory becomes
	// constrained.
	if cfg.MaxConns < 120 {
		cfg.MaxConns = 120
	}
	if cfg.MinConns == 0 {
		cfg.MinConns = 2
	}
	if poolConfig.MaxConns > 0 {
		cfg.MaxConns = poolConfig.MaxConns
	}
	if poolConfig.MinConns > 0 {
		cfg.MinConns = poolConfig.MinConns
	}
	if cfg.MinConns > cfg.MaxConns {
		return nil, fmt.Errorf("pgxpool min conns %d exceeds max conns %d", cfg.MinConns, cfg.MaxConns)
	}
	if cfg.MaxConnLifetime == 0 {
		cfg.MaxConnLifetime = 30 * time.Minute
	}
	if cfg.MaxConnIdleTime == 0 {
		cfg.MaxConnIdleTime = 2 * time.Minute
	}
	if cfg.HealthCheckPeriod == 0 {
		cfg.HealthCheckPeriod = 30 * time.Second
	}
	// Server-side per-query timeout. Any single statement running past
	// 30s gets killed by Postgres — pgx sees the error, releases the
	// conn. Prevents a hung Read from silently pinning a pool slot
	// forever when the socket is half-dead.
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	if _, ok := cfg.ConnConfig.RuntimeParams["statement_timeout"]; !ok {
		cfg.ConnConfig.RuntimeParams["statement_timeout"] = "30000" // 30s in ms
	}
	// TCP keepalive at socket layer: without it, silent link death (LB
	// idle drops, NAT rebinding, postgres FIN unseen) never reaches Go
	// and Read blocks forever. 60s idle + 10s probes + 3 fails =
	// broken conn declared within ~90s.
	if cfg.ConnConfig.ConnectTimeout == 0 {
		cfg.ConnConfig.ConnectTimeout = 5 * time.Second
	}
	baseDial := cfg.ConnConfig.DialFunc
	if baseDial == nil {
		baseDial = (&net.Dialer{KeepAlive: -1}).DialContext
	}
	cfg.ConnConfig.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := baseDial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(60 * time.Second)
		}
		return c, nil
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pgxpool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pgxpool ping: %w", err)
	}
	if poolConfig.WarmConns > 0 {
		if poolConfig.WarmConns > cfg.MaxConns {
			pool.Close()
			return nil, fmt.Errorf("pgxpool warm conns %d exceeds max conns %d", poolConfig.WarmConns, cfg.MaxConns)
		}
		conns := make([]*pgxpool.Conn, 0, poolConfig.WarmConns)
		for range poolConfig.WarmConns {
			conn, err := pool.Acquire(ctx)
			if err != nil {
				for _, held := range conns {
					held.Release()
				}
				pool.Close()
				return nil, fmt.Errorf("pgxpool warm acquire %d/%d: %w", len(conns)+1, poolConfig.WarmConns, err)
			}
			conns = append(conns, conn)
		}
		for _, conn := range conns {
			conn.Release()
		}
	}
	return &Db{Con: pool, queries: queries}, nil
}
