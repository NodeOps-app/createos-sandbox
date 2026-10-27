package hostproxy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Rule is one parsed allowlist entry.
type Rule struct {
	Host string     // domain (may start "*." for wildcard), or "" if rule is IP-based
	IP   net.IP     // set if rule was an IP literal, else nil
	CIDR *net.IPNet // set if rule was a CIDR, else nil
	Port int        // 0 = any port
	// Wild indicates the "*" match-anything rule.
	Wild bool
}

// Parse parses a single rule string: "host[:port]" | "ip[:port]" | "cidr[:port]" | "*"
func Parse(s string) (Rule, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Rule{}, fmt.Errorf("empty rule")
	}
	if s == "*" {
		return Rule{Wild: true}, nil
	}

	// CIDR: has a slash. May or may not have :port suffix.
	if strings.Contains(s, "/") {
		hostPart, portPart, hasPort := splitHostPortMaybe(s)
		_, cidr, err := net.ParseCIDR(hostPart)
		if err != nil {
			return Rule{}, fmt.Errorf("invalid cidr %q: %w", hostPart, err)
		}
		r := Rule{CIDR: cidr}
		if hasPort {
			p, err := strconv.Atoi(portPart)
			if err != nil {
				return Rule{}, fmt.Errorf("invalid port %q: %w", portPart, err)
			}
			r.Port = p
		}
		return r, nil
	}

	hostPart, portPart, hasPort := splitHostPortMaybe(s)
	r := Rule{}
	if ip := net.ParseIP(hostPart); ip != nil {
		r.IP = ip
	} else {
		r.Host = strings.ToLower(hostPart)
	}
	if hasPort {
		p, err := strconv.Atoi(portPart)
		if err != nil {
			return Rule{}, fmt.Errorf("invalid port %q: %w", portPart, err)
		}
		r.Port = p
	}
	return r, nil
}

// splitHostPortMaybe splits "host:port" but leaves "host" alone if no port.
// It only treats the trailing ":NNN" (all digits) as a port — domains never
// contain colons and IPv4 has none either. IPv6 literals aren't supported
// here (would need brackets); callers don't expect them.
func splitHostPortMaybe(s string) (host, port string, hasPort bool) {
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return s, "", false
	}
	cand := s[idx+1:]
	if cand == "" {
		return s, "", false
	}
	for _, r := range cand {
		if r < '0' || r > '9' {
			return s, "", false
		}
	}
	return s[:idx], cand, true
}

// ParseList parses all rules, skipping empty entries.
func ParseList(entries []string) ([]Rule, error) {
	out := make([]Rule, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		r, err := Parse(e)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// MatchDomain reports whether any rule allows dst (domain, port).
func MatchDomain(rules []Rule, host string, port int) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, r := range rules {
		if r.Wild {
			return true
		}
		if r.Host == "" {
			continue
		}
		if !portMatch(r.Port, port) {
			continue
		}
		if strings.HasPrefix(r.Host, "*.") {
			suffix := r.Host[1:] // ".foo.com"
			// wildcard: matches "bar.foo.com" but not "foo.com" or "a.b.foo.com"
			if !strings.HasSuffix(host, suffix) {
				continue
			}
			prefix := strings.TrimSuffix(host, suffix)
			if prefix == "" {
				continue
			}
			if strings.Contains(prefix, ".") {
				continue
			}
			return true
		}
		if r.Host == host {
			return true
		}
	}
	return false
}

// MatchIP reports whether any rule allows dst (ip, port).
func MatchIP(rules []Rule, ip net.IP, port int) bool {
	for _, r := range rules {
		if r.Wild {
			return true
		}
		if !portMatch(r.Port, port) {
			continue
		}
		if r.IP != nil && r.IP.Equal(ip) {
			return true
		}
		if r.CIDR != nil && r.CIDR.Contains(ip) {
			return true
		}
	}
	return false
}

// AllowAll reports whether the ruleset permits everything (empty list or contains "*").
func AllowAll(rules []Rule) bool {
	if len(rules) == 0 {
		return true
	}
	for _, r := range rules {
		if r.Wild {
			return true
		}
	}
	return false
}

func portMatch(rule, dst int) bool {
	return rule == 0 || rule == dst
}
