// Package crl provides a periodic CRL fetcher + peer-cert verifier usable
// from tls.Config.VerifyPeerCertificate.
package crl

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Fetcher periodically pulls the CRL from control and exposes
// O(1) revocation lookups by serial.
type Fetcher struct {
	ControlURL string
	HTTPClient *http.Client
	Interval   time.Duration
	Logger     logrus.FieldLogger

	mu      sync.RWMutex
	revoked map[string]struct{}
}

type crlEntry struct {
	Serial string `json:"serial"`
	Reason string `json:"reason"`
}

type crlResponse struct {
	IssuedAt     time.Time  `json:"issued_at"`
	NextUpdateAt time.Time  `json:"next_update_at"`
	Revoked      []crlEntry `json:"revoked"`
}

// New constructs a Fetcher. If httpClient is nil, http.DefaultClient is used.
func New(controlURL string, httpClient *http.Client) *Fetcher {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Fetcher{
		ControlURL: controlURL,
		HTTPClient: httpClient,
		revoked:    make(map[string]struct{}),
	}
}

// Run blocks until ctx is cancelled, refreshing the CRL each tick.
// Default interval is 60s if not set.
func (f *Fetcher) Run(ctx context.Context) {
	if f.Interval <= 0 {
		f.Interval = 60 * time.Second
	}
	// Initial fetch immediately, then on each tick.
	_ = f.refresh(ctx)
	t := time.NewTicker(f.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = f.refresh(ctx)
		}
	}
}

// Refresh synchronously replaces the cached revocation set from control.
// Callers that must fail closed during startup can require this to succeed
// before accepting traffic. Run retries afterward; failed refreshes retain
// the previous set, and verification does not enforce a cache-age deadline.
func (f *Fetcher) Refresh(ctx context.Context) error {
	return f.refresh(ctx)
}

func (f *Fetcher) refresh(ctx context.Context) error {
	url := strings.TrimRight(f.ControlURL, "/") + "/v1/internal/crl"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		if f.Logger != nil {
			f.Logger.Warnf("[crl] build request: %v", err)
		}
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := f.HTTPClient.Do(req)
	if err != nil {
		if f.Logger != nil {
			f.Logger.Warnf("[crl] fetch: %v", err)
		}
		return fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if f.Logger != nil {
			f.Logger.Warnf("[crl] status %d", resp.StatusCode)
		}
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	// Control wraps responses in JSend: {"status":"success","data":{...}}.
	// Try wrapped first; fall back to bare object so the fetcher also
	// works against external CRL endpoints that don't wrap.
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		if f.Logger != nil {
			f.Logger.Warnf("[crl] read: %v", err)
		}
		return fmt.Errorf("read: %w", err)
	}
	var wrapped struct {
		Status string      `json:"status"`
		Data   crlResponse `json:"data"`
	}
	var body crlResponse
	if err := json.Unmarshal(raw, &wrapped); err == nil && wrapped.Status == "success" {
		body = wrapped.Data
	} else if err := json.Unmarshal(raw, &body); err != nil {
		if f.Logger != nil {
			f.Logger.Warnf("[crl] decode: %v", err)
		}
		return fmt.Errorf("decode: %w", err)
	}
	fresh := make(map[string]struct{}, len(body.Revoked))
	for _, e := range body.Revoked {
		s := normalizeSerial(e.Serial)
		if s == "" {
			continue
		}
		fresh[s] = struct{}{}
	}

	f.mu.Lock()
	prevCount := len(f.revoked)
	f.revoked = fresh
	f.mu.Unlock()

	if prevCount != len(fresh) && f.Logger != nil {
		f.Logger.Infof("[crl] refreshed n=%d", len(fresh))
	}
	return nil
}

// IsRevoked returns true if serialHex (lowercase hex, no 0x prefix) is in the CRL.
func (f *Fetcher) IsRevoked(serialHex string) bool {
	s := normalizeSerial(serialHex)
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.revoked[s]
	return ok
}

// VerifyPeerCertificate is suitable for tls.Config.VerifyPeerCertificate.
// It parses the first leaf cert in rawCerts and rejects it if its serial
// appears in the CRL.
func (f *Fetcher) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("no peer certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse leaf cert: %w", err)
	}
	serial := hex.EncodeToString(leaf.SerialNumber.Bytes())
	if f.IsRevoked(serial) {
		return fmt.Errorf("revoked cert serial=%s", serial)
	}
	return nil
}
