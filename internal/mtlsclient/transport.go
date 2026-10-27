// Package mtlsclient builds outbound TLS configurations and HTTP transports
// shared by CreateOS control-plane and machine roles.
package mtlsclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/NodeOps-app/sandbox/internal/ca/crl"
)

const certificateReloadInterval = 2 * time.Minute

// certificateReloader retains the last complete cert/key pair and periodically
// checks disk during TLS handshakes. Certificate renewal replaces the two files
// separately, so a transient mismatched pair must not break new connections.
type certificateReloader struct {
	certPath string
	keyPath  string

	mu        sync.Mutex
	current   *tls.Certificate
	lastCheck time.Time
}

func newCertificateReloader(certPath, keyPath string) (*certificateReloader, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &certificateReloader{
		certPath:  certPath,
		keyPath:   keyPath,
		current:   &cert,
		lastCheck: time.Now(),
	}, nil
}

func (r *certificateReloader) get(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.lastCheck) < certificateReloadInterval {
		return r.current, nil
	}
	r.lastCheck = time.Now()
	if cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath); err == nil {
		r.current = &cert
	}
	return r.current, nil
}

// NewTLSConfig builds a TLS 1.3 client configuration with a reloadable client
// certificate and the supplied CA bundle. It returns nil when any path is
// empty, preserving plaintext local-development behavior for callers that
// explicitly allow it.
func NewTLSConfig(certPath, keyPath, caPath string) (*tls.Config, error) {
	if certPath == "" || keyPath == "" || caPath == "" {
		return nil, nil
	}
	reloader, err := newCertificateReloader(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client keypair (%s, %s): %w", certPath, keyPath, err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle %s: %w", caPath, err)
	}
	pool, _ := x509.SystemCertPool()
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA bundle %s contained no usable PEM certificates", caPath)
	}
	return &tls.Config{
		MinVersion:           tls.VersionTLS13,
		GetClientCertificate: reloader.get,
		RootCAs:              pool,
	}, nil
}

// NewTransport returns a clone of base configured for outbound mTLS. When any
// TLS path is empty it returns base unchanged.
func NewTransport(certPath, keyPath, caPath string, base *http.Transport) (*http.Transport, error) {
	return NewTransportWithVerify(certPath, keyPath, caPath, base, nil)
}

// NewTransportWithVerify additionally applies a peer-certificate callback,
// normally a CRL verifier, to both full and resumed TLS sessions.
func NewTransportWithVerify(
	certPath, keyPath, caPath string,
	base *http.Transport,
	verify func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error,
) (*http.Transport, error) {
	tlsCfg, err := NewTLSConfig(certPath, keyPath, caPath)
	if err != nil {
		return nil, err
	}
	if tlsCfg == nil {
		return base, nil
	}
	tlsCfg.VerifyPeerCertificate = verify
	tlsCfg.VerifyConnection = crl.VerifyConnectionFunc(verify)
	if base == nil {
		base = http.DefaultTransport.(*http.Transport)
	}
	transport := base.Clone()
	transport.TLSClientConfig = tlsCfg
	return transport, nil
}
