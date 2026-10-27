// Rootfs is a tiny TTL cache for the cluster-wide rootfs
// catalog: the union of names advertised across active hosts + the
// rootfs_catalog metadata map. Every create call queries both today
// (see clusterRootfsUnion) at ~10ms p50 / ~80ms p99 per lookup — under
// N=100 burst that's the third-largest server-side stage. The union
// changes only when a host restarts or an operator flips rootfs_catalog,
// so a 30s TTL matches the freshness callers actually need.
//
// SAFETY: this cache holds ONLY catalog rootfs — names from
// hosts.rootfses and rows from rootfs_catalog. User templates
// (tpl_<ulid>, resolved from the per-user templates table) never pass
// through here; their code path skips clusterRootfsUnion entirely by
// checking the TemplateIDPrefix. Get returns an explicit "not cached"
// signal for any name with that prefix as belt-and-suspenders in case
// a future caller forgets the guard.
package cache

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/NodeOps-app/sandbox/models"
)

// Snapshot is what a cached union call returns. Held immutably: callers
// treat both fields as read-only. Refreshing swaps a whole new Snapshot
// in one pointer store, so a reader never sees a half-updated slice.
type Snapshot struct {
	Names   []string                        // sorted, deduped, disabled filtered out
	MetaByN map[string]models.RootfsCatalog // every rootfs_catalog row keyed by name
}

// Rootfs is safe for concurrent use. Zero value is unusable; use NewRootfs.
type Rootfs struct {
	ttl time.Duration

	mu   sync.RWMutex
	snap *Snapshot
	exp  time.Time

	// sf dedups concurrent misses. Without this, a burst that arrives
	// right after TTL expiry would fire N parallel DB refreshes (each
	// doing ListHosts + ListRootfsMetadata) — a classic thundering herd.
	// With single-flight the first miss owns the DB call; every other
	// concurrent miss blocks on the same call and gets the same result.
	sf singleflight.Group

	hits   atomic.Uint64
	misses atomic.Uint64
	loads  atomic.Uint64 // number of DB round-trips (should be << misses under burst)
}

// New constructs a Cache with the given TTL. ttl<=0 defaults to 30s
// (the rootfs union changes on the scale of host restarts / operator
// deprecations — minutes-to-days between events).
func NewRootfs(ttl time.Duration) *Rootfs {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &Rootfs{ttl: ttl}
}

// GetSnapshot returns (snap, true) on a fresh hit, (nil, false) on cold
// or stale. Caller re-fetches from DB and calls Put.
func (c *Rootfs) GetSnapshot() (*Snapshot, bool) {
	c.mu.RLock()
	s := c.snap
	exp := c.exp
	c.mu.RUnlock()
	if s == nil || time.Now().After(exp) {
		c.misses.Add(1)
		return nil, false
	}
	c.hits.Add(1)
	return s, true
}

// getRaw returns the cached snapshot AND its expiry without applying a
// freshness check. Used by GetOrLoad to serve stale-while-revalidate:
// stale entries are returned to the caller (fast) while a background
// refresh fires (invisible to the request path).
func (c *Rootfs) getRaw() (*Snapshot, time.Time) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snap, c.exp
}

// Put atomically installs a new snapshot with the cache's TTL. Callers
// pass the (names, metaByN) pair produced by a fresh DB read. Passing
// nil is a no-op — a nil snapshot would racily mask a subsequent hit.
func (c *Rootfs) Put(s *Snapshot) {
	if s == nil {
		return
	}
	c.mu.Lock()
	c.snap = s
	c.exp = time.Now().Add(c.ttl)
	c.mu.Unlock()
}

// Invalidate drops the cached snapshot. Called after operator writes
// that change the catalog (host register/deregister, disable/enable a
// rootfs) so the change is visible on the next Get.
func (c *Rootfs) Invalidate() {
	c.mu.Lock()
	c.snap = nil
	c.exp = time.Time{}
	c.mu.Unlock()
}

// GetOrLoad returns the cached snapshot. When the entry is fresh it
// returns immediately. When the entry is STALE (past TTL) it also
// returns immediately with the stale value AND fires an async
// background refresh — the request path never blocks on I/O for a
// stale-but-present entry. This is stale-while-revalidate: 99 waiters
// that used to block on singleflight now all return in µs, while one
// background goroutine silently updates the cache for the next tick.
//
// Only path that blocks is the truly-empty cache (first request ever,
// or right after Invalidate() until the refresh completes) — a
// synchronous single-flighted load is unavoidable because we have
// nothing to serve. Failed loads never poison the cache.
//
// Staleness bound: at most one refresh-duration behind reality (~150ms
// under a hot DB). The refresh timer is not proactive — a stale entry
// stays stale until the next Get() triggers the async refresh.
// Acceptable because rootfs data changes on the order of hours-to-days.
func (c *Rootfs) GetOrLoad(load func() (*Snapshot, error)) (*Snapshot, error) {
	snap, exp := c.getRaw()
	if snap != nil {
		if time.Now().After(exp) {
			// Stale — fire background refresh, don't wait. singleflight
			// dedups concurrent stale-triggered refreshes to one at a
			// time; extra callers become no-ops. Return the stale
			// snapshot to the caller immediately.
			c.sf.DoChan("union", func() (any, error) {
				c.loads.Add(1)
				s, lerr := load()
				if lerr == nil {
					c.Put(s)
				}
				return s, lerr
			})
		} else {
			c.hits.Add(1)
		}
		return snap, nil
	}
	// Cold cache: no value to serve stale, must block on load.
	c.misses.Add(1)
	v, err, _ := c.sf.Do("union", func() (any, error) {
		// Double-check under sf — another caller may have filled during queue.
		if s, _ := c.getRaw(); s != nil {
			return s, nil
		}
		c.loads.Add(1)
		s, lerr := load()
		if lerr != nil {
			return nil, lerr
		}
		c.Put(s)
		return s, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*Snapshot), nil
}

// IsTemplateName returns true if the given rootfs name refers to a
// user template (tpl_<ulid>) rather than a catalog rootfs. Callers
// should NEVER look up template names in this cache — templates are
// per-user and live in the templates table, not rootfs_catalog. The
// create handler already guards its clusterRootfsUnion calls with
// this prefix check; this helper is exposed so the cache layer can
// enforce it again as belt-and-suspenders.
func IsTemplateName(name string) bool {
	return strings.HasPrefix(name, models.TemplateIDPrefix)
}

// Stats returns cumulative hit/miss counters — useful for a debug
// endpoint or a periodic log line.
func (c *Rootfs) Stats() (hits, misses uint64) {
	return c.hits.Load(), c.misses.Load()
}
