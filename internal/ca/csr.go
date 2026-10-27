package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// GenerateKeyAndCSR mints a fresh Ed25519 keypair and a CSR whose SAN
// carries the SPIFFE URI for the supplied identity. Returns PEM-
// encoded key + CSR ready to write to disk / ship to the CA.
//
// extraDNS and extraIPs are propagated into the CSR's DNS / IP SANs.
// Without them, control's TLS handshake to host:9090 fails with
// "doesn't contain any IP SANs" because control dials hosts by IP.
// Original onboarding (install.sh) seeds these via openssl req's
// subjectAltName; this function is what the in-process renewer uses
// to mint the same shape.
func GenerateKeyAndCSR(ident URIIdentity, extraDNS []string, extraIPs []net.IP) ([]byte, []byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate Ed25519 key: %w", err)
	}
	spiffe, err := url.Parse(FormatSpiffeURI(ident))
	if err != nil {
		return nil, nil, fmt.Errorf("format SPIFFE URI: %w", err)
	}
	cn := ident.Role
	if ident.HostID != "" {
		cn = "host-" + ident.HostID
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"createos"},
		},
		URIs:        []*url.URL{spiffe},
		DNSNames:    extraDNS,
		IPAddresses: extraIPs,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return keyPEM, csrPEM, nil
}

// ErrHostSANNotAllowed identifies a CSR attempting to claim a server name
// outside its host identity. Actor certificates are issued by the offline CLI.
var ErrHostSANNotAllowed = errors.New("host CSR contains an unauthorized SAN")

func validateHostSANs(csr *x509.CertificateRequest, hostID string) error {
	// Match the host onboarding names, not the caller-controlled hosts.addr row.
	// Bootstrap credentials authorize enrollment of this host identity; they do
	// not authorize adding arbitrary service names to that identity's certificate.
	identity := strings.ToLower(strings.TrimSuffix(hostID, "."))
	hostIP := net.ParseIP(hostID)
	for _, name := range csr.DNSNames {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		if strings.Contains(name, "*") || (name != identity && !(hostIP != nil && name == "host-"+identity)) {
			return fmt.Errorf("%w: DNS %q", ErrHostSANNotAllowed, name)
		}
	}
	for _, ip := range csr.IPAddresses {
		if !ip.Equal(hostIP) && !ip.Equal(net.IPv4(127, 0, 0, 1)) && !ip.Equal(net.IPv6loopback) {
			return fmt.Errorf("%w: IP %s", ErrHostSANNotAllowed, ip)
		}
	}
	if len(csr.EmailAddresses) != 0 {
		return fmt.Errorf("%w: email", ErrHostSANNotAllowed)
	}
	return nil
}
