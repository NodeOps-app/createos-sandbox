// Package handlers — per-user effective-limits resolver.
//
// Today the control plane enforces per-user creation caps using a static
// config struct plus a per-user-id override map. The createos credit/plan
// API now returns the same caps per-user inside `data.plan.limit`. This
// file wires the two together with the following precedence (highest
// first):
//
//  1. is_internal=true API key  → bypass everything (caller-side; this
//     provider just returns zero limits).
//  2. operator override map     → wins over createos when set.
//  3. createos plan response    → primary per-user dynamic source.
//  4. static config default     → fallback for quota fields when createos
//     errors, is disabled, or returned zero. Credit fails closed on errors.
//
// Caching: every Get hit is memo'd per user for limitsCacheTTL (30s). The
// cache is intentionally tiny and lock-coarse — quota checks are rare
// (only on create) and the underlying createos call costs ~10ms, so 30s
// is plenty.
package handlers

import (
	"context"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/NodeOps-app/sandbox/internal/createos"
)

// Limits is the effective per-user policy resolved from the precedence
// chain above. Cap fields use a three-way sentinel: -1 = unlimited
// (skip check), 0 = denied, positive = cap. Every check site is
// `if cap >= 0 && n >= cap { reject }`.
type Limits struct {
	MaxSandboxes              int
	MaxSandboxesPerDay        int
	MaxSandboxNetworks        int
	MaxSandboxNetworksPerDay  int
	MaxSandboxDisks           int
	MaxSandboxDisksPerDay     int
	MaxSandboxTemplates       int
	MaxSandboxTemplatesPerDay int
	// MaxDevices caps registered (non-revoked) devices per user. -1 = no
	// cap. Guards against exhausting the CGNAT 100.64.0.0/10 IP pool.
	MaxDevices int
	// AllowedShapes is the plan's sandbox-shape allowlist. Empty = no
	// allowlist (every enabled shape OK); non-empty = user may only
	// create those shapes.
	AllowedShapes []string
	// MaxDiskMib is the plan's per-sandbox disk-size ceiling in MiB.
	// 0 = no extra cap beyond the static AllowedDiskSizesMib menu.
	MaxDiskMib int64
	// CreditBalance is the user's remaining credit at fetch time. <=0
	// means out of credit — every create-flow handler refuses with 402
	// Payment Required. Refreshed on the same cadence as the rest of
	// Limits (stale-while-revalidate, 30s TTL). When createos is
	// disabled, this defaults to math.Inf(+1) so unconfigured local-dev
	// setups never gate.
	CreditBalance float64
}

// HasCredit returns true when the user still has positive balance.
// Used as a precondition by every create handler (sandboxes, networks,
// disks, templates). Internal keys bypass (their Limits is zero-valued
// — CreditBalance stays 0, but isInternal short-circuits the check at
// the handler).
func (L Limits) HasCredit() bool { return L.CreditBalance > 0 }

// IsShapeAllowed returns true when shape is in the allowlist OR the
// allowlist is empty (no restriction). Comparison is case-insensitive
// to match the rest of the catalog plumbing.
func (L Limits) IsShapeAllowed(shape string) bool {
	if len(L.AllowedShapes) == 0 {
		return true
	}
	for _, s := range L.AllowedShapes {
		if strings.EqualFold(s, shape) {
			return true
		}
	}
	return false
}

// LimitsProvider produces the effective Limits for one (userID,
// isInternal) pair. Handlers depend on this interface, not on the
// concrete LimitsCache, so tests can swap a static stub in.
type LimitsProvider interface {
	Get(ctx context.Context, userID string, isInternal bool) Limits
}

// LimitsCache resolves per-user limits from createos (or defaults when
// createos is disabled) and caches each user's resolved Limits for
// limitsCacheTTL. The cache is safe for concurrent use.
type LimitsCache struct {
	client   *createos.Client // nil = createos disabled (use defaults)
	defaults Limits
	ttl      time.Duration

	mu         sync.Mutex
	byUser     map[string]limitsEntry
	refreshing map[string]struct{} // single-flight per-user background refresh
}

type limitsEntry struct {
	limits  Limits
	expires time.Time
}

// limitsCacheTTL is the per-user memo lifetime. 30s matches the
// userapikey cache TTL — short enough that plan upgrades show up
// promptly, long enough that a rapid burst of creates hits createos
// once per user instead of per request.
const limitsCacheTTL = 30 * time.Second

// NewLimitsCache constructs the provider. client may be nil (createos
// deliberately disabled — every user gets the static defaults with an
// infinite credit balance). defaults supplies quota fields when createos is
// unreachable, but a configured client error produces zero credit.
func NewLimitsCache(client *createos.Client, defaults Limits) *LimitsCache {
	return &LimitsCache{
		client:     client,
		defaults:   defaults,
		ttl:        limitsCacheTTL,
		byUser:     make(map[string]limitsEntry, 256),
		refreshing: make(map[string]struct{}, 16),
	}
}

// Get returns the effective Limits for the caller. Internal keys
// bypass — they get every cap = -1 (unlimited sentinel). All other
// users get the createos plan value. Quota fields fall back to defaults when
// createos is unreachable; credit fails closed. A nil client means billing was
// deliberately disabled and therefore does not gate credit.
//
// Stale-while-revalidate: a cached value (fresh OR expired) is returned
// immediately. When stale, a single background goroutine refreshes it
// from createos so the next caller sees fresh data without blocking.
// Only the FIRST-EVER request for a user blocks on createos — every
// subsequent request hits this in-memory cache and returns in <100µs.
func (c *LimitsCache) Get(ctx context.Context, userID string, isInternal bool) Limits {
	if isInternal {
		return Limits{
			MaxSandboxes:              -1,
			MaxSandboxesPerDay:        -1,
			MaxSandboxNetworks:        -1,
			MaxSandboxNetworksPerDay:  -1,
			MaxSandboxDisks:           -1,
			MaxSandboxDisksPerDay:     -1,
			MaxSandboxTemplates:       -1,
			MaxSandboxTemplatesPerDay: -1,
			MaxDevices:                -1,
			CreditBalance:             math.Inf(+1),
		}
	}
	now := time.Now()
	c.mu.Lock()
	e, ok := c.byUser[userID]
	if ok {
		// Cache hit — serve immediately. If stale, trigger a background
		// refresh (single-flight per user).
		base := e.limits
		stale := !e.expires.After(now)
		if stale {
			if _, busy := c.refreshing[userID]; !busy {
				c.refreshing[userID] = struct{}{}
				go c.refreshAsync(userID)
			}
		}
		c.mu.Unlock()
		return base
	}
	c.mu.Unlock()

	// Cold cache — synchronous fetch. Only happens once per user per
	// process lifetime; afterwards every request is stale-while-revalidate.
	fresh := c.fetch(ctx, userID)
	c.mu.Lock()
	c.byUser[userID] = limitsEntry{limits: fresh, expires: now.Add(c.ttl)}
	c.mu.Unlock()
	return fresh
}

// refreshAsync runs the upstream createos lookup off the request hot
// path. Uses its own short-lived context with a generous timeout —
// the goroutine isn't bound to any caller's context, and a stuck
// refresh shouldn't pin memory indefinitely.
func (c *LimitsCache) refreshAsync(userID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fresh := c.fetch(ctx, userID)
	c.mu.Lock()
	c.byUser[userID] = limitsEntry{limits: fresh, expires: time.Now().Add(c.ttl)}
	delete(c.refreshing, userID)
	c.mu.Unlock()
}

// fetch returns the resolved Limits BEFORE per-user operator overrides
// are layered on. On any createos error (or when createos is disabled),
// it returns the static defaults verbatim — the meter's hard cap stays
// in effect, just as before this wiring landed.
func (c *LimitsCache) fetch(ctx context.Context, userID string) Limits {
	if c.client == nil {
		// createos disabled (local-dev / on-prem-no-billing). Treat as
		// infinite credit so the credit gate is a no-op until billing
		// is wired in.
		L := c.defaults
		L.CreditBalance = math.Inf(+1)
		return L
	}
	resp, err := c.client.GetCurrentPlan(ctx, userID)
	if err != nil {
		// A configured createos client that cannot verify the balance fails
		// CLOSED. Static quota defaults still apply, but zero credit blocks
		// cost-incurring actions until billing recovers.
		L := c.defaults
		L.CreditBalance = 0
		return L
	}
	L := c.defaults
	L.CreditBalance = resp.Amount
	lim := resp.Plan.Limit
	if lim.MaxSandboxes != nil {
		L.MaxSandboxes = *lim.MaxSandboxes
	}
	if lim.MaxSandboxesPerDay != nil {
		L.MaxSandboxesPerDay = *lim.MaxSandboxesPerDay
	}
	if lim.MaxSandboxNetworks != nil {
		L.MaxSandboxNetworks = *lim.MaxSandboxNetworks
	}
	if lim.MaxSandboxNetworksPerDay != nil {
		L.MaxSandboxNetworksPerDay = *lim.MaxSandboxNetworksPerDay
	}
	if lim.MaxSandboxDisks != nil {
		L.MaxSandboxDisks = *lim.MaxSandboxDisks
	}
	if lim.MaxSandboxDisksPerDay != nil {
		L.MaxSandboxDisksPerDay = *lim.MaxSandboxDisksPerDay
	}
	if lim.MaxSandboxTemplates != nil {
		L.MaxSandboxTemplates = *lim.MaxSandboxTemplates
	}
	if lim.MaxSandboxTemplatesPerDay != nil {
		L.MaxSandboxTemplatesPerDay = *lim.MaxSandboxTemplatesPerDay
	}
	if lim.MaxDevices != nil {
		L.MaxDevices = *lim.MaxDevices
	}
	if len(lim.SandboxSizes) > 0 {
		L.AllowedShapes = append([]string(nil), lim.SandboxSizes...)
	}
	if lim.MaxDiskSizeAllowedInGib != nil && *lim.MaxDiskSizeAllowedInGib > 0 {
		L.MaxDiskMib = int64(*lim.MaxDiskSizeAllowedInGib) * 1024
	}
	return L
}
