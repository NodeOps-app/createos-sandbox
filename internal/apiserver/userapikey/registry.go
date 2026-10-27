// Package apikey implements API-key resolution for createos's HTTP
// servers: opaque tokens (under any of four supported headers) resolved
// through a Resolver that combines a Postgres-backed registry with an
// in-process TTL cache and an optional external-validator fallback.
//
// Inbound tokens are HMAC-SHA256'd with a server-side pepper before
// they ever touch the DB. Lookups are by (auth_type, key_hash); the
// plaintext token is never persisted.
package userapikey

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// AuthType tags which header an inbound token arrived on. Cached and
// upserted as a string so the same opaque value sent under two
// different headers is treated as two distinct rows (matches upstream's
// per-header interpretation).
const (
	AuthTypeAPIKey      = "api_key"
	AuthTypeAccessToken = "access_token"
	AuthTypeAuthToken   = "auth_token"
	AuthTypeMPPAgent    = "mpp_agent"
)

// Resolver maps (auth_type, opaque token) to a user_id. Implementations
// are expected to be hot-path safe (cached, lock-free reads).
type Resolver interface {
	// Resolve returns (user_id, is_internal, true) on hit,
	// ("", false, false) on miss/revoked. extraHeaders are forwarded
	// verbatim to the upstream auth service (e.g. X-Agent-Shared-Key
	// alongside X-Agent-Token). Nil is safe.
	Resolve(authType, token string, extraHeaders map[string]string) (userID string, isInternal, ok bool)
}

// keyStore is the subset of models.Repo this package needs. Defined
// here so the auth package doesn't import models directly — keeps the
// import graph one-directional.
type keyStore interface {
	// LookupByHash returns the row for (authType, keyHash) or
	// (found=false) if not present.
	LookupByHash(ctx context.Context, authType string, keyHash []byte) (userID, name string, revoked, isInternal bool, expiresAt *time.Time, found bool, err error)

	// UpsertWithHash writes a row keyed on (auth_type, key_hash).
	// The plaintext parameter is vestigial — kept on the wire so
	// upstream-validator and admin-mint paths share one signature —
	// and is discarded by the closure that calls models.UpsertAPIKey.
	UpsertWithHash(ctx context.Context, plaintext, userID, name string, isInternal bool, expiresAt *time.Time, authType string, keyHash []byte) error

	// DeleteByHash drops a row when upstream rejects the token. Used by
	// the resolver right after /v1/users/me returns 401/403/404 so the
	// next request re-validates from scratch.
	DeleteByHash(ctx context.Context, authType string, keyHash []byte) error
}

// LookupByHashFunc / UpsertWithHashFunc / DeleteByHashFunc are tiny
// adapters so the wiring layer can hand keyStore closures that reshape
// the models package's concrete types into this package's contract.
type LookupByHashFunc func(ctx context.Context, authType string, keyHash []byte) (userID, name string, revoked, isInternal bool, expiresAt *time.Time, found bool, err error)
type UpsertWithHashFunc func(ctx context.Context, plaintext, userID, name string, isInternal bool, expiresAt *time.Time, authType string, keyHash []byte) error
type DeleteByHashFunc func(ctx context.Context, authType string, keyHash []byte) error

type funcStore struct {
	lookup LookupByHashFunc
	upsert UpsertWithHashFunc
	delete DeleteByHashFunc
}

func (f funcStore) LookupByHash(ctx context.Context, authType string, keyHash []byte) (string, string, bool, bool, *time.Time, bool, error) {
	return f.lookup(ctx, authType, keyHash)
}

func (f funcStore) UpsertWithHash(ctx context.Context, plaintext, userID, name string, isInternal bool, expiresAt *time.Time, authType string, keyHash []byte) error {
	if f.upsert == nil {
		return nil
	}
	return f.upsert(ctx, plaintext, userID, name, isInternal, expiresAt, authType, keyHash)
}

func (f funcStore) DeleteByHash(ctx context.Context, authType string, keyHash []byte) error {
	if f.delete == nil {
		return nil
	}
	return f.delete(ctx, authType, keyHash)
}

// NewKeyStore builds a keyStore from lookup / upsert / delete closures.
func NewKeyStore(lookup LookupByHashFunc, upsert UpsertWithHashFunc, del DeleteByHashFunc) keyStore {
	return funcStore{lookup: lookup, upsert: upsert, delete: del}
}

// cacheKey is the in-process map key — small struct comparison is
// faster than string concatenation per request.
type cacheKey struct {
	authType string
	hashHex  string // hex of the 32-byte HMAC digest
}

type cacheEntry struct {
	userID     string
	isInternal bool
	revoked    bool
	expiresAt  time.Time
}

const (
	// Tokens are attacker-controlled, so a TTL alone is not a memory bound:
	// expired map entries still occupy space until explicitly deleted.
	maxCacheEntries = 16 * 1024
	cacheEvictBatch = 1024
)

// Cache is an in-process Resolver that caches LookupByHash results.
// Sub-µs hot path on cache hit.
//
// Validation flow (in order):
//  1. in-process cache keyed by (auth_type, key_hash) — shaved-µs hot path
//  2. local api_keys table lookup by (auth_type, key_hash)
//     - is_internal=true → trust forever, no external call
//     - is_internal=false + expires_at in future → trust
//     - is_internal=false + expired → fall through to external
//  3. external validator (if configured) → GET /v1/users/me forwarding
//     the same header the user sent. On 200 → upsert to api_keys
//     with is_internal=false, expires_at=now+externalTTL. On
//     401/403/404 → ErrExternalKeyInvalid, DELETE the row inline,
//     cache negative for ttl/2.
//
// Removal latency from the external auth service: ≤ externalTTL.
// Local Invalidate is provided so the control plane can drop its
// cache entry immediately after admin DELETE.
type Cache struct {
	store       keyStore
	hasher      *Hasher           // HMAC pepper; nil = hashing disabled (legacy mode)
	external    ExternalValidator // nil = skip external step (DB-only mode)
	ttl         time.Duration     // in-process cache TTL
	externalTTL time.Duration     // upstream cache TTL written to api_keys.expires_at
	mu          sync.RWMutex
	cache       map[cacheKey]cacheEntry
	// Dedup concurrent same-key misses; without this a burst can race
	// LookupByHash and poison the cache negatively while the row is valid.
	sf singleflight.Group
}

// NewCache wraps a key lookup with an in-process TTL cache.
// ttl <= 0 falls back to 60 seconds. externalTTL <= 0 falls back to
// 5 minutes (only used when external is non-nil).
func NewCache(store keyStore, hasher *Hasher, ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &Cache{
		store:       store,
		hasher:      hasher,
		ttl:         ttl,
		externalTTL: 5 * time.Minute,
		cache:       make(map[cacheKey]cacheEntry),
	}
}

// WithExternal enables the external-validator fallback. Called once at
// wiring time. external nil disables it (DB-only mode).
func (r *Cache) WithExternal(external ExternalValidator, externalTTL time.Duration) *Cache {
	r.external = external
	if externalTTL > 0 {
		r.externalTTL = externalTTL
	}
	return r
}

// Resolve implements Resolver. Hashes the token with the pepper and
// looks it up by (authType, key_hash). Returns ("", false) for unknown
// or revoked keys. Errors talking to storage / external also return
// ("", false) — fail-closed. extraHeaders are forwarded to the
// external validator on cache miss (e.g. X-Agent-Shared-Key).
func (r *Cache) Resolve(authType, token string, extraHeaders map[string]string) (string, bool, bool) {
	if authType == "" || token == "" {
		return "", false, false
	}
	keyHash := r.hasher.Hash(token)
	if keyHash == nil {
		// Hashing not configured — phase-A startup before pepper landed.
		// Fail-closed; operators must wire the pepper for any traffic.
		return "", false, false
	}
	ck := cacheKey{authType: authType, hashHex: hex.EncodeToString(keyHash)}

	now := time.Now()
	r.mu.RLock()
	e, ok := r.cache[ck]
	r.mu.RUnlock()
	if ok {
		if now.Before(e.expiresAt) {
			if e.revoked {
				return "", false, false
			}
			return e.userID, e.isInternal, true
		}
		// Lazy deletion keeps ordinary traffic from leaving expired entries
		// behind. Re-check under the write lock so a concurrent refresh is
		// never deleted using the stale value read above.
		r.mu.Lock()
		if current, exists := r.cache[ck]; exists && !now.Before(current.expiresAt) {
			delete(r.cache, ck)
		}
		r.mu.Unlock()
	}

	type resolved struct {
		userID     string
		isInternal bool
	}
	sfKey := ck.authType + ":" + ck.hashHex
	v, _, _ := r.sf.Do(sfKey, func() (any, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()

		userID, name, revoked, isInternal, dbExpiresAt, found, err := r.store.LookupByHash(ctx, authType, keyHash)
		if err != nil {
			// Storage error — fail-closed WITHOUT poisoning so the next
			// request retries the DB instead of trusting a stale negative.
			return resolved{}, nil
		}

		now := time.Now()
		switch {
		case found && revoked:
			r.cacheNegative(ck)
			return resolved{}, nil
		case found && isInternal:
			r.cachePositive(ck, userID, true)
			return resolved{userID: userID, isInternal: true}, nil
		case found && !isInternal && dbExpiresAt != nil && now.Before(*dbExpiresAt):
			r.cachePositive(ck, userID, false)
			return resolved{userID: userID}, nil
		case found && !isInternal:
			_ = name
		case !found:
			// Fall through to external validate.
		}

		if r.external == nil {
			r.cacheNegative(ck)
			return resolved{}, nil
		}

		ext, err := r.external.Validate(ctx, authType, token, extraHeaders)
		if err != nil {
			if errors.Is(err, ErrExternalKeyInvalid) {
				_ = r.store.DeleteByHash(ctx, authType, keyHash)
				r.cacheNegative(ck)
			}
			return resolved{}, nil
		}

		exp := now.Add(r.externalTTL)
		if ext.ExpiresAt != nil && ext.ExpiresAt.Before(exp) {
			exp = *ext.ExpiresAt
		}
		_ = r.store.UpsertWithHash(ctx, token, ext.UserID, ext.Name, false, &exp, authType, keyHash)
		r.cachePositive(ck, ext.UserID, false)
		return resolved{userID: ext.UserID}, nil
	})
	res, _ := v.(resolved)
	return res.userID, res.isInternal, res.userID != ""
}

func (r *Cache) cachePositive(ck cacheKey, userID string, isInternal bool) {
	r.storeCacheEntry(ck, cacheEntry{
		userID:     userID,
		isInternal: isInternal,
		expiresAt:  time.Now().Add(r.ttl),
	})
}

func (r *Cache) cacheNegative(ck cacheKey) {
	r.storeCacheEntry(ck, cacheEntry{
		revoked:   true,
		expiresAt: time.Now().Add(r.ttl / 2),
	})
}

func (r *Cache) storeCacheEntry(ck cacheKey, entry cacheEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.cache[ck]; !exists && len(r.cache) >= maxCacheEntries {
		r.evictCacheEntriesLocked(time.Now())
	}
	r.cache[ck] = entry
}

// evictCacheEntriesLocked first removes every expired entry, then prefers
// negative entries before sacrificing valid positive entries. Removing a
// batch amortizes the map scan under sustained unique-token attacks.
func (r *Cache) evictCacheEntriesLocked(now time.Time) {
	for key, entry := range r.cache {
		if !now.Before(entry.expiresAt) {
			delete(r.cache, key)
		}
	}
	if len(r.cache) < maxCacheEntries {
		return
	}

	target := maxCacheEntries - cacheEvictBatch
	for key, entry := range r.cache {
		if len(r.cache) <= target {
			return
		}
		if entry.revoked {
			delete(r.cache, key)
		}
	}
	for key := range r.cache {
		if len(r.cache) <= target {
			return
		}
		delete(r.cache, key)
	}
}

// Invalidate drops a cache entry. Called locally on the control plane
// right after an admin POST/DELETE so the change is visible immediately
// to subsequent requests on the same process.
func (r *Cache) Invalidate(authType, token string) {
	keyHash := r.hasher.Hash(token)
	if keyHash == nil {
		return
	}
	ck := cacheKey{authType: authType, hashHex: hex.EncodeToString(keyHash)}
	r.mu.Lock()
	delete(r.cache, ck)
	r.mu.Unlock()
}
