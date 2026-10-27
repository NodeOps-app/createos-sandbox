// Package renew implements a background goroutine that watches a leaf
// cert on disk and, when it gets close to expiring, mints a fresh
// keypair + CSR, ships the CSR to control, and atomically replaces
// the on-disk cert + key + CA bundle with the signed reply.
//
// The renewer is host-only. Callers supply an *http.Client pre-wired
// with the bootstrap credential required by the host CSR endpoint; the
// package never adds headers of its own. Non-host actor certificates
// are rotated offline with the admin CA CLI.
package renew

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/ca"
)

// Renewer watches a leaf cert and renews it before it expires.
type Renewer struct {
	CertPath       string
	KeyPath        string
	CAPath         string
	ControlURL     string
	HTTPClient     *http.Client
	Identity       ca.URIIdentity
	Interval       time.Duration
	RenewThreshold time.Duration
	Logger         logrus.FieldLogger

	// SANs to put in every renewal CSR. Control's IssueCert copies
	// these into the leaf so Go's TLS verifier accepts dials like
	// `https://<ip>:9090` (without IP SANs the handshake fails with
	// "doesn't contain any IP SANs"). Always populate ExtraIPs with
	// the host's own routable IP; ExtraDNS optional. The renewer
	// also inherits SANs from the current cert as a fallback, but
	// these explicit values win.
	ExtraDNS []string
	ExtraIPs []net.IP
}

type hostCSRRequest struct {
	HostID string `json:"host_id"`
	CSRPEM string `json:"csr_pem"`
}

type csrResponse struct {
	CertPEM   string    `json:"cert_pem"`
	CAPEM     string    `json:"ca_pem"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Run blocks until ctx is cancelled, ticking on r.Interval (default
// 1h) and renewing whenever the current cert is within RenewThreshold
// (default 12h) of NotAfter.
func (r *Renewer) Run(ctx context.Context) {
	interval := r.Interval
	if interval <= 0 {
		interval = time.Hour
	}
	threshold := r.RenewThreshold
	if threshold <= 0 {
		threshold = 12 * time.Hour
	}
	log := r.Logger
	if log == nil {
		log = logrus.StandardLogger()
	}

	t := time.NewTicker(interval)
	defer t.Stop()

	// Check once immediately so a freshly-started process with an
	// already-expiring cert doesn't have to wait a full interval.
	r.tick(ctx, log, threshold)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.tick(ctx, log, threshold)
		}
	}
}

func (r *Renewer) tick(ctx context.Context, log logrus.FieldLogger, threshold time.Duration) {
	cert, err := loadCert(r.CertPath)
	if err != nil {
		log.WithError(err).WithField("path", r.CertPath).Warn("cert-renew: cannot read current cert")
		return
	}
	remaining := time.Until(cert.NotAfter)
	if remaining > threshold {
		return
	}
	log.WithFields(logrus.Fields{
		"not_after": cert.NotAfter,
		"remaining": remaining.String(),
	}).Info("cert-renew: cert close to expiry, requesting renewal")

	if err := r.renew(ctx, log); err != nil {
		log.WithError(err).Warn("cert-renew: renewal failed; will retry next tick")
	}
}

func (r *Renewer) renew(ctx context.Context, log logrus.FieldLogger) error {
	// SAN policy: explicit ExtraDNS/ExtraIPs win, otherwise inherit
	// from the current cert. Control dials hosts by IP, so the leaf
	// must contain those IPs as SANs; without them Go's TLS verifier
	// fails with "doesn't contain any IP SANs".
	extraDNS := r.ExtraDNS
	extraIPs := r.ExtraIPs
	if len(extraDNS) == 0 && len(extraIPs) == 0 {
		if cur, err := loadCert(r.CertPath); err == nil {
			extraDNS = cur.DNSNames
			extraIPs = cur.IPAddresses
		}
	}
	keyPEM, csrPEM, err := ca.GenerateKeyAndCSR(r.Identity, extraDNS, extraIPs)
	if err != nil {
		return fmt.Errorf("generate CSR: %w", err)
	}

	if r.Identity.HostID == "" {
		return fmt.Errorf("cert renew: host identity required; actor certificates rotate offline")
	}
	url := r.ControlURL + "/v1/internal/hosts/csr"
	bodyAny := hostCSRRequest{HostID: r.Identity.HostID, CSRPEM: string(csrPEM)}

	payload, err := json.Marshal(bodyAny)
	if err != nil {
		return fmt.Errorf("marshal CSR request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build CSR request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := r.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST CSR: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("CSR endpoint returned %d: %s", resp.StatusCode, truncate(body, 256))
	}
	// Control wraps the response in JSend: {"status":"success","data":{...}}.
	// Try wrapped first; fall back to bare object for compatibility with
	// any external CSR endpoints that don't wrap.
	var wrapped struct {
		Status string      `json:"status"`
		Data   csrResponse `json:"data"`
	}
	var parsed csrResponse
	if err := json.Unmarshal(body, &wrapped); err == nil && wrapped.Data.CertPEM != "" {
		parsed = wrapped.Data
	} else if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("decode CSR response: %w", err)
	}
	if parsed.CertPEM == "" || parsed.CAPEM == "" {
		return fmt.Errorf("CSR response missing cert_pem or ca_pem")
	}

	if err := atomicWrite(r.CertPath, []byte(parsed.CertPEM), 0o600); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := atomicWrite(r.KeyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	if r.CAPath != "" {
		if err := atomicWrite(r.CAPath, []byte(parsed.CAPEM), 0o600); err != nil {
			return fmt.Errorf("write CA: %w", err)
		}
	}
	log.WithField("new_expiry", parsed.ExpiresAt).Info("cert-renew: rotated leaf cert + key")
	return nil
}

func loadCert(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

// atomicWrite writes data via a temp file in the same directory and a
// rename, so a torn write can't leave a half-written cert in place.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	f, err := os.CreateTemp(dir, ".renew-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
