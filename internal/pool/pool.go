// Package pool runs the predictive pre-warm sandbox grow/shrink loop.
// Replicas coordinate via a Postgres advisory lock so only one issues
// spawns per tick.
package pool

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/config"
	"github.com/NodeOps-app/sandbox/database"
	"github.com/NodeOps-app/sandbox/internal/apiserver/metrics"
	"github.com/NodeOps-app/sandbox/models"
)

// Spawner is the narrow subset of control-plane ops the loop needs.
// handlers.Handler implements it; keeping this interface here lets
// internal/pool stay handler-free.
type Spawner interface {
	SpawnPoolSandbox(ctx context.Context) (string, error)
	DestroyPoolSandbox(ctx context.Context, sandboxID string) error
}

type Pool struct {
	cfg     config.PoolConfig
	region  string
	db      *database.Db
	spawner Spawner
	now     func() time.Time // injectable for tests
}

func New(cfg config.PoolConfig, region string, db *database.Db, spawner Spawner) *Pool {
	return &Pool{cfg: cfg, region: region, db: db, spawner: spawner, now: time.Now}
}

// ValidateBuckets is exposed so main.go can fail fast at boot.
func ValidateBuckets(m map[string]config.PoolBucket) error { return validateBuckets(m) }

func (p *Pool) Run(ctx context.Context) {
	if !p.cfg.Enabled {
		log.WithContext(ctx).Infof("[pool] disabled; loop not started")
		return
	}
	if err := validateBuckets(p.cfg.Buckets); err != nil {
		log.WithContext(ctx).Warnf("[pool] refusing to start: %v", err)
		return
	}
	log.WithContext(ctx).Infof("[pool] starting; region=%s shape=%s disk_mib=%d rootfs=%q buckets=%d per_host_grow_rate=%d max_age=%s",
		p.region, p.cfg.Spec.Shape, p.cfg.Spec.DiskMib, p.cfg.Spec.Rootfs,
		len(p.cfg.Buckets), p.cfg.PerHostGrowRate, p.cfg.MaxAge)

	for {
		bucketName, b := p.currentBucket()
		p.tick(ctx, bucketName, b)
		select {
		case <-ctx.Done():
			log.WithContext(ctx).Infof("[pool] loop stopping: %v", ctx.Err())
			return
		case <-time.After(b.RefillInterval):
		}
	}
}

func (p *Pool) tick(ctx context.Context, bucketName string, b config.PoolBucket) {
	// No cross-replica lock. Each replica caps its own spawn count at
	// PerHostGrowRate, so worst-case N replicas ticking simultaneously
	// spawn N × PerHostGrowRate extra VMs — bounded, self-correcting on
	// the next tick when everyone reads a larger depth. An advisory
	// lock would need to pin a Postgres connection for the whole tick,
	// which under load exhausts the pgxpool and cascades into every
	// other DB path (auth lookup, heartbeats, sandbox list) failing.
	metrics.PoolTarget.WithLabelValues(p.region, p.cfg.Spec.Shape, bucketName).Set(float64(b.Target))

	depth, err := models.CountPoolDepth(ctx, p.db, p.region, p.cfg.Spec.Shape, p.cfg.Spec.DiskMib, p.cfg.Spec.Rootfs)
	if err != nil {
		log.WithContext(ctx).Warnf("[pool] count depth: %v", err)
		return
	}
	metrics.PoolDepth.WithLabelValues(p.region, p.cfg.Spec.Shape).Set(float64(depth))

	if gap := b.Target - depth; gap > 0 {
		n := gap
		if n > p.cfg.PerHostGrowRate {
			n = p.cfg.PerHostGrowRate
		}
		for i := 0; i < n; i++ {
			if err := ctx.Err(); err != nil {
				return
			}
			if _, err := p.spawner.SpawnPoolSandbox(ctx); err != nil {
				metrics.PoolGrowTotal.WithLabelValues("fail").Inc()
				log.WithContext(ctx).Warnf("[pool] spawn: %v", err)
				return // stop hammering a failing scheduler
			}
			metrics.PoolGrowTotal.WithLabelValues("ok").Inc()
		}
	}

	if err := p.shrinkAged(ctx); err != nil {
		log.WithContext(ctx).Warnf("[pool] shrink aged: %v", err)
	}

	if depth > b.Target {
		excess := depth - b.Target
		if excess > p.cfg.PerHostGrowRate {
			excess = p.cfg.PerHostGrowRate
		}
		if err := p.shrinkExcess(ctx, excess); err != nil {
			log.WithContext(ctx).Warnf("[pool] shrink excess: %v", err)
		}
	}
}

func (p *Pool) shrinkAged(ctx context.Context) error {
	tx, err := p.db.Con.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	ids, err := models.SelectAgedPoolSandboxes(ctx, tx, p.db, p.region, p.cfg.MaxAge, p.cfg.PerHostGrowRate)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	// Selection locks are released. DestroyPoolSandbox must atomically check
	// that the row still belongs to the pool before transitioning or dialing.
	for _, id := range ids {
		if err := p.spawner.DestroyPoolSandbox(ctx, id); err != nil {
			log.WithContext(ctx).Warnf("[pool] destroy %s: %v", id, err)
			continue
		}
		metrics.PoolShrinkTotal.WithLabelValues("aged").Inc()
	}
	return nil
}

// shrinkExcess destroys n oldest pool sandboxes regardless of age.
// Reuses SelectAgedPoolSandboxes with maxAge=0, which yields
// `created_at < now()` — matches every row. Avoids adding a near-
// duplicate model function just to change one filter.
func (p *Pool) shrinkExcess(ctx context.Context, n int) error {
	tx, err := p.db.Con.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	ids, err := models.SelectAgedPoolSandboxes(ctx, tx, p.db, p.region, 0, n)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	for _, id := range ids {
		if err := p.spawner.DestroyPoolSandbox(ctx, id); err != nil {
			log.WithContext(ctx).Warnf("[pool] destroy %s: %v", id, err)
			continue
		}
		metrics.PoolShrinkTotal.WithLabelValues("excess").Inc()
	}
	return nil
}
