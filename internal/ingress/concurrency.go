package ingress

import (
	"sync"
	"sync/atomic"
)

// concurrencyCap enforces a per-sandbox concurrent-tunnel limit. Plain
// RWMutex+map so we can clean up empty entries lazily; sync.Map is
// banned project-wide (HashTrieMap panic).
type concurrencyCap struct {
	max int64

	mu       sync.RWMutex
	counters map[string]*atomic.Int64
}

func newConcurrencyCap(max int) *concurrencyCap {
	if max <= 0 {
		max = 64
	}
	return &concurrencyCap{
		max:      int64(max),
		counters: make(map[string]*atomic.Int64),
	}
}

// Acquire returns true on success, false if the sandbox is at its cap.
// On success, the caller MUST call Release(id) when the tunnel closes.
func (c *concurrencyCap) Acquire(id string) bool {
	c.mu.RLock()
	cnt, ok := c.counters[id]
	c.mu.RUnlock()
	if !ok {
		c.mu.Lock()
		if cnt, ok = c.counters[id]; !ok {
			cnt = new(atomic.Int64)
			c.counters[id] = cnt
		}
		c.mu.Unlock()
	}
	if cnt.Add(1) > c.max {
		cnt.Add(-1)
		return false
	}
	return true
}

// Release drops one in-flight tunnel for the sandbox. Lazily reclaims
// the map entry when the counter hits zero so id-churn doesn't leak.
func (c *concurrencyCap) Release(id string) {
	c.mu.RLock()
	cnt, ok := c.counters[id]
	c.mu.RUnlock()
	if !ok {
		return
	}
	if cnt.Add(-1) == 0 {
		c.mu.Lock()
		// Re-check under write lock — another caller may have raced past 0.
		if cnt.Load() == 0 {
			delete(c.counters, id)
		}
		c.mu.Unlock()
	}
}
