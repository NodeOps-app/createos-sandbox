package ingress

import "sync"

// concurrencyCap tracks per-sandbox concurrent tunnels using a map of
// counters. Acquire and Release are paired for each admitted tunnel.
type concurrencyCap struct {
	max int64

	mu       sync.Mutex
	counters map[string]int64
}

func newConcurrencyCap(max int) *concurrencyCap {
	if max <= 0 {
		max = 64
	}
	return &concurrencyCap{
		max:      int64(max),
		counters: make(map[string]int64),
	}
}

// Acquire returns true on success, false if the sandbox is at its cap.
// On success, the caller MUST call Release(id) when the tunnel closes.
func (c *concurrencyCap) Acquire(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counters[id] >= c.max {
		return false
	}
	c.counters[id]++
	return true
}

// Release drops one in-flight tunnel and reclaims an idle counter. Admission
// and removal share the lock so no caller can increment a detached counter.
func (c *concurrencyCap) Release(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counters[id] <= 1 {
		delete(c.counters, id)
		return
	}
	c.counters[id]--
}
