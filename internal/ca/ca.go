package ca

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// CA is the in-process certificate authority. Holds the parsed root
// cert + private key plus their on-disk PEM encodings (handy for
// distribution to verifiers).
type CA struct {
	Cert    *x509.Certificate
	Key     crypto.Signer
	CertPEM []byte
	KeyPEM  []byte
}

// rootValidity is the lifetime stamped on a freshly-generated root CA.
// Deliberately long — rotating the root means redistributing the
// trust anchor to every verifier, so 10y matches what mTLS deployments
// typically use as the outer envelope.
const rootValidity = 10 * 365 * 24 * time.Hour

// LoadOrCreateCA returns the CA. If both keyPath and certPath exist,
// loads them; otherwise mints a fresh Ed25519 root, persists key at
// mode 0600 and cert at mode 0644, and returns the new CA. Parent
// directories are created with mode 0700 when missing.
func LoadOrCreateCA(keyPath, certPath string) (*CA, error) {
	if fileExists(keyPath) && fileExists(certPath) {
		return loadCA(keyPath, certPath)
	}
	return createCA(keyPath, certPath)
}

func loadCA(keyPath, certPath string) (*CA, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("CA key: no PEM block")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	signer, ok := keyAny.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("CA key is not a crypto.Signer: %T", keyAny)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("CA cert: no PEM block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	return &CA{Cert: cert, Key: signer, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

func createCA(keyPath, certPath string) (*CA, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Ed25519 root: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "createos root CA",
			Organization: []string{"createos"},
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(rootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("sign root cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("re-parse root cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal root key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := writeFileMode(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write CA key: %w", err)
	}
	if err := writeFileMode(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("write CA cert: %w", err)
	}
	return &CA{Cert: cert, Key: priv, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// IssueCert verifies a CSR, then mints a leaf cert binding the CSR's
// public key to the supplied SPIFFE identity. Returns the leaf DER
// bytes and the serial (caller persists the serial so the CRL builder
// can revoke later).
func (c *CA) IssueCert(csrDER []byte, ident URIIdentity, ttl time.Duration) ([]byte, *big.Int, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("CSR signature: %w", err)
	}
	if ident.HostID != "" {
		if err := validateHostSANs(csr, ident.HostID); err != nil {
			return nil, nil, err
		}
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	spiffe, err := url.Parse(FormatSpiffeURI(ident))
	if err != nil {
		return nil, nil, fmt.Errorf("format SPIFFE URI: %w", err)
	}
	cn := ident.Role
	if ident.HostID != "" {
		cn = "host-" + ident.HostID
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"createos"},
		},
		NotBefore: now.Add(-1 * time.Minute),
		NotAfter:  now.Add(ttl),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		// Copy validated host SANs (or offline operator-approved actor SANs)
		// from the CSR so Go's TLS verifier accepts
		// connections targeted at the host by IP or DNS name (control
		// dials hosts via host.Addr which is typically "<ip>:9090"; without
		// matching IP SAN, the handshake fails with "doesn't contain any
		// IP SANs"). URI SAN is set explicitly below to the SPIFFE identity
		// we want — the CSR's URI is verified for shape, not trusted.
		IPAddresses:           csr.IPAddresses,
		DNSNames:              csr.DNSNames,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{spiffe},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, csr.PublicKey, c.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign leaf cert: %w", err)
	}
	return der, serial, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("random serial: %w", err)
	}
	return n, nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func writeFileMode(path string, data []byte, mode os.FileMode) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, mode)
}
