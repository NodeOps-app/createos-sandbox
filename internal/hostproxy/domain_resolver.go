package hostproxy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	domainLookupTimeout   = 2 * time.Second
	domainDialTimeout     = 5 * time.Second
	domainCacheMaxEntries = 4096
)

var sharedAddressSpace = mustCIDR("100.64.0.0/10")

type cachedDomain struct {
	ips       []net.IP
	expiresAt time.Time
}

// domainResolver binds an untrusted HTTP Host/TLS SNI assertion to addresses
// selected by the host. Its bounded cache keeps domain-filtered connection
// setup fast without allowing wildcard rules to create an unbounded map.
type domainResolver struct {
	resolver *net.Resolver
	ttl      time.Duration

	mu    sync.Mutex
	cache map[string]cachedDomain
	sf    singleflight.Group
}

func newDomainResolver(resolver *net.Resolver, ttl time.Duration) *domainResolver {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &domainResolver{
		resolver: resolver,
		ttl:      ttl,
		cache:    make(map[string]cachedDomain),
	}
}

// Dial resolves the exact matched hostname in the host namespace and dials
// only a public IPv4 result. The original destination chosen inside the VM is
// deliberately not an input to this operation.
func (r *domainResolver) Dial(ctx context.Context, host string, port int) (net.Conn, net.IP, error) {
	ips, err := r.lookup(ctx, host)
	if err != nil {
		return nil, nil, err
	}

	dialCtx, cancel := context.WithTimeout(ctx, domainDialTimeout)
	defer cancel()
	dialer := net.Dialer{}
	var lastErr error
	for _, ip := range ips {
		conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(ip.String(), itoa(port)))
		if err == nil {
			return conn, ip, nil
		}
		lastErr = err
		if dialCtx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no usable address")
	}
	return nil, nil, fmt.Errorf("dial resolved domain %q: %w", host, lastErr)
}

func (r *domainResolver) lookup(ctx context.Context, host string) ([]net.IP, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return nil, fmt.Errorf("empty domain")
	}

	now := time.Now()
	r.mu.Lock()
	if entry, ok := r.cache[host]; ok && now.Before(entry.expiresAt) {
		ips := cloneIPs(entry.ips)
		r.mu.Unlock()
		return ips, nil
	}
	r.mu.Unlock()

	value, err, _ := r.sf.Do(host, func() (any, error) {
		lookupCtx, cancel := context.WithTimeout(ctx, domainLookupTimeout)
		defer cancel()
		addrs, err := r.resolver.LookupIPAddr(lookupCtx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve allowed domain %q: %w", host, err)
		}

		ips := make([]net.IP, 0, len(addrs))
		seen := make(map[string]struct{}, len(addrs))
		for _, addr := range addrs {
			ip := addr.IP.To4()
			if !publicDomainDestination(ip) {
				continue
			}
			key := ip.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			ips = append(ips, append(net.IP(nil), ip...))
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("allowed domain %q has no public IPv4 address", host)
		}

		r.store(host, ips, time.Now().Add(r.ttl))
		return ips, nil
	})
	if err != nil {
		return nil, err
	}
	return cloneIPs(value.([]net.IP)), nil
}

func (r *domainResolver) store(host string, ips []net.IP, expiresAt time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cache) >= domainCacheMaxEntries {
		now := time.Now()
		for key, entry := range r.cache {
			if !now.Before(entry.expiresAt) {
				delete(r.cache, key)
			}
		}
		// A wildcard allowlist lets the VM manufacture arbitrary names. Keep
		// memory bounded even when every lookup is for a different hostname.
		if len(r.cache) >= domainCacheMaxEntries {
			for key := range r.cache {
				delete(r.cache, key)
				break
			}
		}
	}
	r.cache[host] = cachedDomain{ips: cloneIPs(ips), expiresAt: expiresAt}
}

func publicDomainDestination(ip net.IP) bool {
	return ip != nil &&
		ip.IsGlobalUnicast() &&
		!ip.IsPrivate() &&
		!ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() &&
		!sharedAddressSpace.Contains(ip)
}

func cloneIPs(ips []net.IP) []net.IP {
	out := make([]net.IP, len(ips))
	for i, ip := range ips {
		out[i] = append(net.IP(nil), ip...)
	}
	return out
}

func mustCIDR(value string) *net.IPNet {
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		panic(err)
	}
	return network
}
