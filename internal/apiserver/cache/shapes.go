package cache

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/proto"
	"github.com/NodeOps-app/sandbox/models"
)

// Shapes is a TTL cache over the shapes DB table. Operators manage the
// catalog via direct SQL; the cache picks up changes within its configured
// TTL. On a DB error or empty result it returns the last-good value so a
// transient outage cannot black out /v1/shapes or heartbeat shape pushes.
type Shapes struct {
	repo *models.Repo
	ttl  time.Duration

	mu      sync.Mutex
	cached  atomic.Pointer[[]proto.Shape]
	expires time.Time

	emptyWarn sync.Once
}

// NewShapes constructs a shape-catalog cache. There is no fallback catalog:
// the shapes DB table is the single source of truth. A non-positive TTL uses
// the 30-second default.
func NewShapes(repo *models.Repo, ttl time.Duration) *Shapes {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &Shapes{repo: repo, ttl: ttl}
}

// Shapes returns the current catalog. It refreshes from the DB when the TTL
// expires. Concurrent callers wait on one refresh. A failed refresh returns
// the last good value, or an empty slice when the cache has never warmed.
func (c *Shapes) Shapes(ctx context.Context) []proto.Shape {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p := c.cached.Load(); p != nil && time.Now().Before(c.expires) {
		return *p
	}
	rows, err := c.repo.ListEnabledShapes(ctx)
	if err != nil || len(rows) == 0 {
		if p := c.cached.Load(); p != nil {
			return *p
		}
		c.emptyWarn.Do(func() {
			log.WithContext(ctx).Warn("[control] shapes table unavailable and no cached catalog; serving empty list until DB recovers")
		})
		return []proto.Shape{}
	}
	fresh := make([]proto.Shape, len(rows))
	for i, r := range rows {
		fresh[i] = proto.Shape{
			ID:          r.ID,
			VCPU:        r.VCPU,
			MemMib:      r.MemMib,
			DefaultDisk: r.DefaultDisk,
			CPUQuotaPct: r.CPUQuotaPct,
		}
	}
	c.cached.Store(&fresh)
	c.expires = time.Now().Add(c.ttl)
	return fresh
}
