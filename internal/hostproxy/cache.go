package hostproxy

import (
	"context"
	"sync"
	"time"
)

// Entry is a cached egress policy for a source IP.
type Entry struct {
	SandboxID string
	Rules     []Rule
	ExpiresAt time.Time
	// Negative is true when the API returned "unknown IP" and we're caching
	// the absence for the TTL to avoid hammering it.
	Negative bool
}

// Cache caches src-IP → egress rules for a TTL. Both positive and negative
// lookups are cached.
type Cache struct {
	ttl   time.Duration
	fetch func(ctx context.Context, ip string) (*Entry, error)

	mu sync.Mutex
	m  map[string]*Entry
}

// NewCache creates a cache with the given TTL and fetch backend.
// fetch should return (*Entry, nil) on a hit, (nil, nil) on "unknown IP"
// (404), and (nil, err) on transport/server errors.
func NewCache(ttl time.Duration, fetch func(ctx context.Context, ip string) (*Entry, error)) *Cache {
	return &Cache{
		ttl:   ttl,
		fetch: fetch,
		m:     make(map[string]*Entry),
	}
}

// Lookup returns the cached entry for ip or fetches + caches a new one.
// The returned entry may be a Negative entry (known-absent within TTL).
func (c *Cache) Lookup(ctx context.Context, ip string) (*Entry, error) {
	now := time.Now()
	c.mu.Lock()
	if e, ok := c.m[ip]; ok && now.Before(e.ExpiresAt) {
		c.mu.Unlock()
		return e, nil
	}
	c.mu.Unlock()

	e, err := c.fetch(ctx, ip)
	if err != nil {
		return nil, err
	}
	if e == nil {
		e = &Entry{Negative: true}
	}
	e.ExpiresAt = time.Now().Add(c.ttl)

	c.mu.Lock()
	c.m[ip] = e
	c.mu.Unlock()
	return e, nil
}

// Invalidate drops any cached entry for ip.
func (c *Cache) Invalidate(ip string) {
	c.mu.Lock()
	delete(c.m, ip)
	c.mu.Unlock()
}
