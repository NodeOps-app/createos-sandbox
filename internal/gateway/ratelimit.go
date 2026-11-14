package gateway

import (
	"sync"
	"time"
)

// connRateLimiter is a per-source-IP token bucket fronting the SSH
// public-key auth path. Without it, an attacker can drive up to
// MaxAuthTries control-plane lookups per TCP connect to enumerate
// sandbox-id existence via lookup latency.
//
// Bucket size 10, refill 1 per 10s. Mutex-protected map of buckets.
// Tokens are consumed BEFORE the control-plane round-trip; once a
// bucket is empty subsequent attempts return immediately without a lookup.
// Allowed attempts can still have different timings.
type connRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	tokens  float64
	updated time.Time
}

const (
	rlBucketCap       = 10.0
	rlRefillPerSecond = 0.1 // 1 token / 10s
	rlReapAfter       = 30 * time.Minute
)

func newConnRateLimiter() *connRateLimiter {
	return &connRateLimiter{buckets: make(map[string]*tokenBucket)}
}

// Allow returns true if a token was available (and consumed) for the
// given source-IP key. False = caller should fail fast without doing
// any expensive lookup.
func (r *connRateLimiter) Allow(key string) bool {
	if key == "" {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	b, ok := r.buckets[key]
	if !ok {
		b = &tokenBucket{tokens: rlBucketCap, updated: now}
		r.buckets[key] = b
	}
	elapsed := now.Sub(b.updated).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rlRefillPerSecond
		if b.tokens > rlBucketCap {
			b.tokens = rlBucketCap
		}
		b.updated = now
	}
	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0

	// Reap cold buckets opportunistically. Recent source-IP churn can still
	// grow the map beyond 1024; this threshold is not a hard entry cap.
	if len(r.buckets) > 1024 {
		for k, v := range r.buckets {
			if now.Sub(v.updated) > rlReapAfter {
				delete(r.buckets, k)
			}
		}
	}
	return true
}
