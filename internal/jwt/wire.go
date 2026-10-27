package jwt

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"sync"
)

// PubkeyMap is a static map of "<role>:<id>" → pubkey, populated from
// operator config files (builder.pub, billing.pub). Hosts' pubkeys
// are NOT in here — those live in Postgres and are fetched via
// HostPubkeyResolver (the cache at internal/auth/host_pubkey_cache.go).
type PubkeyMap struct {
	mu sync.RWMutex
	m  map[string]ed25519.PublicKey
}

func NewPubkeyMap() *PubkeyMap {
	return &PubkeyMap{m: make(map[string]ed25519.PublicKey)}
}

// Set registers a pubkey for kid. Overwrites any existing value.
func (p *PubkeyMap) Set(kid string, pub ed25519.PublicKey) {
	if pub == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.m[kid] = pub
}

// LoadAndSet reads the pubkey file at path and registers it under kid.
// Empty path is a no-op (operator hasn't configured this actor).
func (p *PubkeyMap) LoadAndSet(kid, path string) error {
	if path == "" {
		return nil
	}
	pub, err := LoadPublicKey(path)
	if err != nil {
		return fmt.Errorf("load pubkey for %q: %w", kid, err)
	}
	p.Set(kid, pub)
	return nil
}

// Get returns the registered pubkey for kid, or nil if absent.
func (p *PubkeyMap) Get(kid string) ed25519.PublicKey {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.m[kid]
}

// HostPubkeyResolver is a strategy interface implemented by the
// host-public-key cache. Defined here so this package doesn't import
// internal/auth (avoids cycle); the wiring layer adapts whatever cache
// type into one of these.
type HostPubkeyResolver interface {
	Lookup(kid string) (ed25519.PublicKey, error)
}

// HostResolverFunc adapts a closure to HostPubkeyResolver.
type HostResolverFunc func(kid string) (ed25519.PublicKey, error)

func (f HostResolverFunc) Lookup(kid string) (ed25519.PublicKey, error) { return f(kid) }

// CombinedResolver returns a PublicKeyResolver that consults `hosts` for
// kids beginning with "host:" and `staticActors` for everything else
// ("ingress:*", "gateway:*", "control:*"). Either side can be nil.
//
// This is the single entry point used by control's and host's
// InternalJWTMiddleware setup — it captures the design decision that
// hosts are dynamic (registered, cached) and ingress/gateway/control are
// static (config-loaded).
func CombinedResolver(hosts HostPubkeyResolver, staticActors *PubkeyMap) PublicKeyResolver {
	return func(kid string) (ed25519.PublicKey, error) {
		if strings.HasPrefix(kid, "host:") {
			if hosts == nil {
				return nil, nil
			}
			return hosts.Lookup(kid)
		}
		if staticActors == nil {
			return nil, nil
		}
		return staticActors.Get(kid), nil
	}
}
