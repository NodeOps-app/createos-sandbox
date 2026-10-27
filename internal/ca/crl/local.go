package crl

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/models"
)

// localCRL is control's own revocation cache, populated by polling the
// `issued_certs` ledger directly via models.ListRevokedSerialsLedger.
// Avoids the chicken-and-egg of HTTP-fetching its own CRL endpoint.
// VerifyPeerCertificate is suitable for tls.Config.VerifyPeerCertificate
// on control's :8443 inbound listener AND on control's outbound mTLS
// transport (control → host) — same in-memory map serves both.
type Local struct {
	repo *models.Repo

	mu      sync.RWMutex
	revoked map[string]struct{}
}

// NewLocal constructs a Local CRL cache. repo is the source-of-truth
// `issued_certs` ledger. Call Run to start the polling goroutine.
func NewLocal(repo *models.Repo) *Local {
	return &Local{repo: repo, revoked: make(map[string]struct{})}
}

// Run polls the issued_certs ledger every interval, populating the
// in-memory revoked set. Blocks until ctx is cancelled.
func (c *Local) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	c.refresh(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.refresh(ctx)
		}
	}
}

func (c *Local) refresh(ctx context.Context) {
	serials, err := models.ListRevokedSerialsLedger(ctx, c.repo.DB)
	if err != nil {
		log.WithContext(ctx).Warnf("[crl-local] refresh: %v", err)
		return
	}
	fresh := make(map[string]struct{}, len(serials))
	for _, s := range serials {
		fresh[normalizeSerial(s)] = struct{}{}
	}
	c.mu.Lock()
	prev := len(c.revoked)
	c.revoked = fresh
	c.mu.Unlock()
	if prev != len(fresh) {
		log.WithContext(ctx).Infof("[crl-local] refreshed n=%d", len(fresh))
	}
}

// VerifyPeerCertificate installs into tls.Config. Returns an error
// when the peer's leaf serial is in the cached revoked set.
func (c *Local) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("no peer certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse leaf cert: %w", err)
	}
	serial := normalizeSerial(hex.EncodeToString(leaf.SerialNumber.Bytes()))
	c.mu.RLock()
	_, revoked := c.revoked[serial]
	c.mu.RUnlock()
	if revoked {
		return fmt.Errorf("revoked cert serial=%s", serial)
	}
	return nil
}

// normalizeSerial is shared with fetcher.go; defined once in local.go.
func normalizeSerial(s string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
}
