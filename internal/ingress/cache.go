package ingress

import (
	"sync"
	"time"
)

const (
	maxRouteCacheEntries = 4096
	routeCacheEvictBatch = 512
)

// cache is a bounded per-id positive/negative TTL cache. Plain RWMutex+map
// — no sync.Map (the codebase has been bitten by Go's HashTrieMap panic
// twice already).
type cache struct {
	posTTL time.Duration
	negTTL time.Duration

	mu   sync.RWMutex
	data map[string]cacheEntry
}

type cacheEntry struct {
	route    ingressRoute // zero on negative
	negative bool
	expires  time.Time
}

func newCache(posTTL, negTTL time.Duration) *cache {
	return &cache{
		posTTL: posTTL,
		negTTL: negTTL,
		data:   make(map[string]cacheEntry),
	}
}

func (c *cache) get(id string) (ingressRoute, bool, bool) {
	c.mu.RLock()
	e, ok := c.data[id]
	c.mu.RUnlock()
	if !ok {
		return ingressRoute{}, false, false
	}
	if !time.Now().Before(e.expires) {
		c.mu.Lock()
		// Do not remove a concurrent refresh using the stale snapshot above.
		if current, exists := c.data[id]; exists && !time.Now().Before(current.expires) {
			delete(c.data, id)
		}
		c.mu.Unlock()
		return ingressRoute{}, false, false
	}
	return e.route, !e.negative, true
}

// putPositive caches a valid route for ttl. Callers pass posTTL for stable
// (`running`) routes and negTTL for transitional states (paused/resuming/
// creating/…): those are being actively polled to change, so caching them
// for the full posTTL would leave the ingress serving a stale "paused"
// route — and the waking page — for up to posTTL after the sandbox is
// already running. The short TTL lets the flip to `running` be seen within
// a poll cycle.
func (c *cache) putPositive(id string, route ingressRoute, ttl time.Duration) {
	c.put(id, cacheEntry{route: route, expires: time.Now().Add(ttl)})
}

func (c *cache) putNegative(id string) {
	c.put(id, cacheEntry{negative: true, expires: time.Now().Add(c.negTTL)})
}

// TTL controls freshness; the entry cap bounds memory under unique-hostname traffic.
func (c *cache) put(id string, entry cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.data[id]; !exists && len(c.data) >= maxRouteCacheEntries {
		now := time.Now()
		for key, old := range c.data {
			if !now.Before(old.expires) {
				delete(c.data, key)
			}
		}
		// Evict a batch to avoid scanning the full cache on every unique miss.
		if len(c.data) >= maxRouteCacheEntries {
			for key := range c.data {
				delete(c.data, key)
				if len(c.data) <= maxRouteCacheEntries-routeCacheEvictBatch {
					break
				}
			}
		}
	}
	c.data[id] = entry
}
