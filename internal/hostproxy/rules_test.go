package hostproxy

import (
	"net"
	"testing"
)

func mustParse(t *testing.T, s string) Rule {
	t.Helper()
	r, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return r
}

func TestParse_Domain(t *testing.T) {
	r := mustParse(t, "pypi.org")
	if r.Host != "pypi.org" || r.Port != 0 || r.IP != nil || r.CIDR != nil || r.Wild {
		t.Fatalf("unexpected rule: %+v", r)
	}
}

func TestParse_DomainPort(t *testing.T) {
	r := mustParse(t, "pypi.org:443")
	if r.Host != "pypi.org" || r.Port != 443 {
		t.Fatalf("unexpected rule: %+v", r)
	}
}

func TestParse_WildcardDomain(t *testing.T) {
	r := mustParse(t, "*.pythonhosted.org")
	if r.Host != "*.pythonhosted.org" {
		t.Fatalf("unexpected rule: %+v", r)
	}
}

func TestParse_IP(t *testing.T) {
	r := mustParse(t, "1.1.1.1")
	if r.IP == nil || !r.IP.Equal(net.ParseIP("1.1.1.1")) || r.Host != "" || r.Port != 0 {
		t.Fatalf("unexpected rule: %+v", r)
	}
}

func TestParse_IPPort(t *testing.T) {
	r := mustParse(t, "1.1.1.1:1234")
	if r.IP == nil || !r.IP.Equal(net.ParseIP("1.1.1.1")) || r.Port != 1234 {
		t.Fatalf("unexpected rule: %+v", r)
	}
}

func TestParse_CIDR(t *testing.T) {
	r := mustParse(t, "10.0.0.0/8")
	if r.CIDR == nil || r.CIDR.String() != "10.0.0.0/8" || r.Port != 0 {
		t.Fatalf("unexpected rule: %+v", r)
	}
}

func TestParse_CIDRPort(t *testing.T) {
	r := mustParse(t, "10.0.0.0/8:443")
	if r.CIDR == nil || r.CIDR.String() != "10.0.0.0/8" || r.Port != 443 {
		t.Fatalf("unexpected rule: %+v", r)
	}
}

func TestParse_Wildcard(t *testing.T) {
	r := mustParse(t, "*")
	if !r.Wild {
		t.Fatalf("expected wild rule: %+v", r)
	}
}

func TestMatchDomain_Exact(t *testing.T) {
	rs := []Rule{mustParse(t, "pypi.org")}
	if !MatchDomain(rs, "pypi.org", 443) {
		t.Fatalf("exact match failed")
	}
	if MatchDomain(rs, "api.pypi.org", 443) {
		t.Fatalf("should not match subdomain")
	}
}

func TestMatchDomain_WildcardPositive(t *testing.T) {
	rs := []Rule{mustParse(t, "*.foo.com")}
	if !MatchDomain(rs, "bar.foo.com", 443) {
		t.Fatalf("wildcard positive failed")
	}
}

func TestMatchDomain_WildcardNegative(t *testing.T) {
	rs := []Rule{mustParse(t, "*.foo.com")}
	if MatchDomain(rs, "foo.com", 443) {
		t.Fatalf("wildcard matched bare domain")
	}
	if MatchDomain(rs, "a.b.foo.com", 443) {
		t.Fatalf("wildcard matched double subdomain")
	}
	if MatchDomain(rs, "xfoo.com", 443) {
		t.Fatalf("wildcard matched wrong suffix")
	}
}

func TestMatchDomain_Port(t *testing.T) {
	rs := []Rule{mustParse(t, "pypi.org:443")}
	if !MatchDomain(rs, "pypi.org", 443) {
		t.Fatalf("port match failed")
	}
	if MatchDomain(rs, "pypi.org", 80) {
		t.Fatalf("port mismatch should not match")
	}
}

func TestMatchIP_Exact(t *testing.T) {
	rs := []Rule{mustParse(t, "1.1.1.1")}
	if !MatchIP(rs, net.ParseIP("1.1.1.1"), 443) {
		t.Fatalf("exact ip failed")
	}
	if MatchIP(rs, net.ParseIP("192.0.2.31"), 443) {
		t.Fatalf("wrong ip matched")
	}
}

func TestMatchIP_CIDR(t *testing.T) {
	rs := []Rule{mustParse(t, "10.0.0.0/8")}
	if !MatchIP(rs, net.ParseIP("10.5.6.7"), 443) {
		t.Fatalf("cidr contains failed")
	}
	if MatchIP(rs, net.ParseIP("192.0.2.32"), 443) {
		t.Fatalf("cidr miss matched")
	}
}

func TestMatchIP_Port(t *testing.T) {
	rs := []Rule{mustParse(t, "1.1.1.1:1234")}
	if !MatchIP(rs, net.ParseIP("1.1.1.1"), 1234) {
		t.Fatalf("ip port match failed")
	}
	if MatchIP(rs, net.ParseIP("1.1.1.1"), 80) {
		t.Fatalf("ip port mismatch should not match")
	}
}

func TestAllowAll(t *testing.T) {
	if !AllowAll(nil) {
		t.Fatalf("nil should be allow-all")
	}
	if !AllowAll([]Rule{}) {
		t.Fatalf("empty should be allow-all")
	}
	rs, _ := ParseList([]string{"pypi.org", "*"})
	if !AllowAll(rs) {
		t.Fatalf("wildcard in list should be allow-all")
	}
	rs, _ = ParseList([]string{"pypi.org"})
	if AllowAll(rs) {
		t.Fatalf("specific-only should not be allow-all")
	}
}
