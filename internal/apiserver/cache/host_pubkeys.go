package cache

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"github.com/NodeOps-app/createos-sandbox/models"
)

const maxHostPubkeyEntries = 16 * 1024

type pubkeyEntry struct {
	pub       ed25519.PublicKey
	status    string
	notFound  bool
	expiresAt time.Time
}

// HostPubkeys caches host signing keys and status by host id.
//
// Negative entries live for half the positive TTL, so a lookup can
// discover a newly registered host without repeatedly querying the DB.
type HostPubkeys struct {
	repo  *models.Repo
	ttl   time.Duration
	mu    sync.RWMutex
	cache map[string]pubkeyEntry
}

func NewHostPubkeys(repo *models.Repo, ttl time.Duration) *HostPubkeys {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &HostPubkeys{repo: repo, ttl: ttl, cache: make(map[string]pubkeyEntry)}
}

// Lookup returns the host's public key. Returns nil with status="" on
// unknown host (cached negatively for ttl/2). Returns the cached pubkey
// even if status=="dead"; callers must interpret status themselves.
// The control server does not use this cache for inbound JWT verification.
func (c *HostPubkeys) Lookup(ctx context.Context, hostID string) (ed25519.PublicKey, string, error) {
	c.mu.RLock()
	e, ok := c.cache[hostID]
	c.mu.RUnlock()
	if ok && time.Now().Before(e.expiresAt) {
		if e.notFound {
			return nil, "", nil
		}
		return e.pub, e.status, nil
	}

	rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	host, err := c.repo.GetHost(rctx, hostID)
	if err != nil {
		return nil, "", err
	}
	if host == nil || len(host.PublicKey) == 0 {
		c.store(hostID, pubkeyEntry{notFound: true, expiresAt: time.Now().Add(c.ttl / 2)})
		return nil, "", nil
	}
	if len(host.PublicKey) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("host %s has malformed public_key (%d bytes)", hostID, len(host.PublicKey))
	}
	pub := ed25519.PublicKey(host.PublicKey)
	c.store(hostID, pubkeyEntry{pub: pub, status: host.Status, expiresAt: time.Now().Add(c.ttl)})
	return pub, host.Status, nil
}

// store bounds positive and negative entries together. Expiry alone does not
// free map entries; sweep expired keys at capacity, then evict a batch so
// distinct misses cannot cause an unbounded map or a full scan on every insert.
func (c *HostPubkeys) store(hostID string, entry pubkeyEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.cache[hostID]; !exists && len(c.cache) >= maxHostPubkeyEntries {
		now := time.Now()
		for key, cached := range c.cache {
			if !now.Before(cached.expiresAt) {
				delete(c.cache, key)
			}
		}
		if len(c.cache) >= maxHostPubkeyEntries {
			for key := range c.cache {
				delete(c.cache, key)
				if len(c.cache) <= maxHostPubkeyEntries-1024 {
					break
				}
			}
		}
	}
	c.cache[hostID] = entry
}

// Invalidate drops a host from the cache (e.g. after revocation or status
// change). Operator-driven cordon and drain don't touch the cache directly;
// the next lookup re-reads via TTL.
func (c *HostPubkeys) Invalidate(hostID string) {
	c.mu.Lock()
	delete(c.cache, hostID)
	c.mu.Unlock()
}
