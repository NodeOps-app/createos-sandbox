package ca

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestHostCertificateSANScope(t *testing.T) {
	d := t.TempDir()
	authority, err := LoadOrCreateCA(filepath.Join(d, "key"), filepath.Join(d, "cert"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		id   URIIdentity
		dns  []string
		ips  []net.IP
		deny bool
	}{
		{"foreign service", URIIdentity{HostID: "worker-1"}, []string{"control.example"}, nil, true},
		{"foreign IP", URIIdentity{HostID: "192.0.2.10"}, nil, []net.IP{net.ParseIP("192.0.2.20")}, true},
		{"wildcard", URIIdentity{HostID: "worker-1"}, []string{"*.example"}, nil, true},
		{"IP onboarding", URIIdentity{HostID: "192.0.2.10"}, []string{"host-192.0.2.10"}, []net.IP{net.ParseIP("192.0.2.10"), net.IPv4(127, 0, 0, 1)}, false},
		{"hostname onboarding", URIIdentity{HostID: "worker-1"}, []string{"worker-1"}, []net.IP{net.IPv4(127, 0, 0, 1)}, false},
		{"relay client", URIIdentity{HostID: "relay-1"}, nil, nil, false},
		{"offline actor", URIIdentity{Role: RoleControl}, []string{"control.example"}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, csr, err := GenerateKeyAndCSR(tc.id, tc.dns, tc.ips)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(csr)
			der, _, err := authority.IssueCert(block.Bytes, tc.id, time.Hour)
			if tc.deny {
				if !errors.Is(err, ErrHostSANNotAllowed) {
					t.Fatalf("unauthorized certificate issued: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			if len(leaf.URIs) != 1 || leaf.URIs[0].String() != FormatSpiffeURI(tc.id) {
				t.Fatal("identity changed")
			}
			if len(tc.dns) > 0 {
				roots := x509.NewCertPool()
				roots.AddCert(authority.Cert)
				if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: tc.dns[0]}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
