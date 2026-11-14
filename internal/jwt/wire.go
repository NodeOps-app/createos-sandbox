package jwt

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"sync"
)

// PubkeyMap stores issuer keys with synchronized map access. Set and Get
// retain/return the supplied key slices without copying them; callers must
// treat those slices as immutable.
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

// HostPubkeyResolver supplies dynamic host keys without coupling this package
// to a particular repository or cache implementation.
type HostPubkeyResolver interface {
	Lookup(kid string) (ed25519.PublicKey, error)
}

// HostResolverFunc adapts a closure to HostPubkeyResolver.
type HostResolverFunc func(kid string) (ed25519.PublicKey, error)

func (f HostResolverFunc) Lookup(kid string) (ed25519.PublicKey, error) { return f(kid) }

// CombinedResolver consults hosts for kids beginning with "host:" and
// staticActors for all others. Either side can be nil, rejecting that class
// of issuer. The control server currently supplies nil for hosts.
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
