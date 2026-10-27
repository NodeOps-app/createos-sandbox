package database

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/requestctx"
)

var traceEnabled atomic.Bool

// SetTraceEnabled controls pgx query and pool-acquisition timing. It is set
// before OpenDb by long-running services, so it adds no hot-path branch when
// disabled beyond pgx's own nil-tracer check.
func SetTraceEnabled(enabled bool) { traceEnabled.Store(enabled) }

type dbTraceStart struct {
	at      time.Time
	sqlHash string
}
type acquireTraceStart struct{ at time.Time }
type latencyTracer struct{}

func (latencyTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	sum := sha256.Sum256([]byte(d.SQL))
	return context.WithValue(ctx, dbTraceStart{}, dbTraceStart{at: time.Now(), sqlHash: fmt.Sprintf("%x", sum[:6])})
}

func (latencyTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	s, _ := ctx.Value(dbTraceStart{}).(dbTraceStart)
	log.WithFields(log.Fields{"request_id": requestctx.RequestID(ctx), "sql_hash": s.sqlHash,
		"duration_ms": float64(time.Since(s.at).Microseconds()) / 1000, "error": d.Err}).Info("[db-query]")
}

func (latencyTracer) TraceAcquireStart(ctx context.Context, _ *pgxpool.Pool, _ pgxpool.TraceAcquireStartData) context.Context {
	return context.WithValue(ctx, acquireTraceStart{}, acquireTraceStart{at: time.Now()})
}

func (latencyTracer) TraceAcquireEnd(ctx context.Context, pool *pgxpool.Pool, d pgxpool.TraceAcquireEndData) {
	s, _ := ctx.Value(acquireTraceStart{}).(acquireTraceStart)
	stats := pool.Stat()
	log.WithFields(log.Fields{"request_id": requestctx.RequestID(ctx),
		"wait_ms": float64(time.Since(s.at).Microseconds()) / 1000, "error": d.Err,
		"acquired": stats.AcquiredConns(), "idle": stats.IdleConns(), "max": stats.MaxConns()}).Info("[db-acquire]")
}
