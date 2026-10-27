// Package cache contains API-server caches whose lifecycle is independent
// from a particular handler.
//
// Hosts is a tiny TTL cache for models.Host rows keyed by
// host id. Repo.GetHost is a plain Postgres round-trip; under N=100
// burst it costs 3ms p50 / 100ms p99 per exec-forwarded request. The
// hosts table changes at heartbeat cadence (~5s), so a 5s TTL matches
// the DB's own freshness — the cache never returns data older than
// what a fresh DB query would.
//
// Invalidation: HandleHostHeartbeat calls Invalidate(id) right after
// its DB write so status changes propagate to the next Get within the
// tick, not at TTL expiry.
package cache

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/NodeOps-app/sandbox/models"
)

type hostEntry struct {
	host *models.Host
	exp  time.Time
}

// Cache is safe for concurrent use.
type Hosts struct {
	mu  sync.RWMutex
	m   map[string]hostEntry
	ttl time.Duration

	hits   atomic.Uint64
	misses atomic.Uint64
}

// New constructs a Cache with the given TTL. ttl<=0 defaults to 5s
// (matches the heartbeat cadence — see internal/hosts/heartbeat.go).
func NewHosts(ttl time.Duration) *Hosts {
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return &Hosts{m: make(map[string]hostEntry), ttl: ttl}
}

// Get returns (host, true) on a fresh hit, (nil, false) otherwise.
// Stale entries are treated as misses; caller re-fetches and Puts.
func (c *Hosts) Get(id string) (*models.Host, bool) {
	c.mu.RLock()
	e, ok := c.m[id]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.exp) {
		c.misses.Add(1)
		return nil, false
	}
	c.hits.Add(1)
	return e.host, true
}

// Put stores host under id with the cache's TTL. Callers should Put
// only after a successful DB fetch; nil hosts are not cached (a nil
// return from Repo.GetHost means "not found" — caching that would
// racily mask a subsequent register).
func (c *Hosts) Put(id string, h *models.Host) {
	if h == nil {
		return
	}
	c.mu.Lock()
	c.m[id] = hostEntry{host: h, exp: time.Now().Add(c.ttl)}
	c.mu.Unlock()
}

// Invalidate drops the entry for id. Called by HandleHostHeartbeat
// after every heartbeat write so status/last_seen changes are visible
// on the next Get without waiting for TTL.
func (c *Hosts) Invalidate(id string) {
	c.mu.Lock()
	delete(c.m, id)
	c.mu.Unlock()
}

// Stats returns cumulative hit/miss counters + current size — useful
// for a debug endpoint or periodic log line.
func (c *Hosts) Stats() (hits, misses, size uint64) {
	c.mu.RLock()
	size = uint64(len(c.m))
	c.mu.RUnlock()
	return c.hits.Load(), c.misses.Load(), size
}
