// Rootfs caches the cluster-wide rootfs catalog: image names advertised by
// available hosts and metadata from rootfs_catalog. Nonempty catalogs default
// to a 30-second TTL with request-triggered background refresh; missing or empty
// catalogs refresh synchronously before use.
//
// User templates are resolved through their owner-scoped template records and
// must not enter this shared catalog. Callers use IsTemplateName to distinguish
// template references before consulting the catalog; the cache stores snapshots,
// not individual name lookups.
package cache

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/NodeOps-app/createos-sandbox/models"
)

// Snapshot is what a cached union call returns. Held immutably: callers
// treat both fields as read-only. Refreshing swaps a whole new Snapshot
// under the cache mutex, so a reader never sees a half-updated slice.
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

	// sf deduplicates refreshes. Cold/empty-cache callers wait for one load;
	// callers with a stale nonempty snapshot keep using it during refresh.
	sf singleflight.Group

	hits   atomic.Uint64
	misses atomic.Uint64
	loads  atomic.Uint64 // number of DB round-trips (should be << misses under burst)
}

// NewRootfs constructs a catalog cache. A non-positive TTL defaults to 30s.
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

// Invalidate drops the cached snapshot. Host registration calls it so the
// next lookup reloads the catalog. Other catalog changes rely on TTL refresh.
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
// A missing snapshot or a catalog with no image names blocks on a
// refresh, including before TTL expiry. This lets recovered hosts become
// visible without first rejecting a create using an empty catalog. A
// synchronous single-flighted load is unavoidable because we have
// nothing to serve. Failed loads never poison the cache.
//
// Nonempty catalogs use request-triggered refresh: the first request after
// expiry still receives the old catalog while the refresh runs.
func (c *Rootfs) GetOrLoad(load func() (*Snapshot, error)) (*Snapshot, error) {
	snap, exp := c.getRaw()
	if snap != nil && len(snap.Names) != 0 {
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
	// A missing or empty catalog must refresh synchronously. An empty union
	// may mean all hosts were temporarily dead, not that the requested image
	// is invalid. Serving it until TTL expiry would reject recovered hosts.
	c.misses.Add(1)
	v, err, _ := c.sf.Do("union", func() (any, error) {
		// Double-check under sf — another caller may have filled during queue.
		if s, _ := c.getRaw(); s != nil && len(s.Names) != 0 {
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
// this prefix check; this helper does not filter snapshots stored by Put.
func IsTemplateName(name string) bool {
	return strings.HasPrefix(name, models.TemplateIDPrefix)
}

// Stats returns cumulative hit/miss counters — useful for a debug
// endpoint or a periodic log line.
func (c *Rootfs) Stats() (hits, misses uint64) {
	return c.hits.Load(), c.misses.Load()
}
