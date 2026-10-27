package relay

// csr.go — first-issue mTLS leaf cert via control's bootstrap-token
// endpoint. Idempotent: skipped (returns nil) if the cert file already
// exists on disk. Pulled into the relay package alongside bootstrap.go
// so the relay binary owns its full bring-up surface — no top-level
// "hostbootstrap" package to import.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/ca"
	"github.com/NodeOps-app/sandbox/internal/proto"
)

// csrConfig is the input for firstIssueCert. Stripped to first-time
// issuance — renewal is owned separately by internal/ca/renew.
type csrConfig struct {
	HostID         string
	ControlURL     string
	BootstrapToken string

	CertPath string // where to write the leaf cert PEM
	KeyPath  string // where to write the leaf key PEM
	CAPath   string // where to write the CA bundle PEM

	// SANs the cert should carry beyond the SPIFFE URI. Empty = no
	// extras (sufficient for outbound mTLS clients like the relay).
	ExtraDNS []string
	ExtraIPs []net.IP
}

type csrRequest struct {
	HostID string `json:"host_id"`
	CSRPEM string `json:"csr_pem"`
}

type csrResponse struct {
	CertPEM   string    `json:"cert_pem"`
	CAPEM     string    `json:"ca_pem"`
	ExpiresAt time.Time `json:"expires_at"`
}

// firstIssueCert generates a fresh keypair + CSR and exchanges it at
// control's /v1/internal/hosts/csr with the bootstrap token for an mTLS
// leaf cert + CA bundle. Writes all three files to disk.
//
// First-issue path is bootstrap-token-authenticated, NOT mTLS. The
// http.Client trusts the SYSTEM cert pool because control's public
// endpoint (Cloudflare / ingress) serves a real CA-signed cert. For
// strictly-internal deployments (no public TLS), extend csrConfig with
// a CA bundle when that case appears.
func firstIssueCert(ctx context.Context, cfg csrConfig) error {
	if _, err := os.Stat(cfg.CertPath); err == nil {
		log.WithContext(ctx).Debugf("[relay-csr] cert exists at %s; skipping first-issue", cfg.CertPath)
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", cfg.CertPath, err)
	}

	keyPEM, csrPEM, err := ca.GenerateKeyAndCSR(ca.URIIdentity{HostID: cfg.HostID}, cfg.ExtraDNS, cfg.ExtraIPs)
	if err != nil {
		return fmt.Errorf("generate key+CSR: %w", err)
	}

	body, err := json.Marshal(csrRequest{HostID: cfg.HostID, CSRPEM: string(csrPEM)})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		cfg.ControlURL+"/v1/internal/hosts/csr", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(proto.HeaderBootstrapToken, cfg.BootstrapToken)

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{}}, // system roots
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST CSR: %w", err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		const max = 256
		snippet := string(rawBody)
		if len(snippet) > max {
			snippet = snippet[:max] + "..."
		}
		return fmt.Errorf("CSR endpoint returned %d: %s", resp.StatusCode, snippet)
	}

	var wrapped struct {
		Status string      `json:"status"`
		Data   csrResponse `json:"data"`
	}
	var parsed csrResponse
	if err := json.Unmarshal(rawBody, &wrapped); err == nil && wrapped.Data.CertPEM != "" {
		parsed = wrapped.Data
	} else if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return fmt.Errorf("decode CSR response: %w", err)
	}
	if parsed.CertPEM == "" || parsed.CAPEM == "" {
		return fmt.Errorf("CSR response missing cert_pem or ca_pem")
	}

	if err := os.WriteFile(cfg.CertPath, []byte(parsed.CertPEM), 0o600); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(cfg.KeyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	if err := os.WriteFile(cfg.CAPath, []byte(parsed.CAPEM), 0o600); err != nil {
		return fmt.Errorf("write CA: %w", err)
	}
	log.WithContext(ctx).Infof("[relay-csr] first-issued mTLS leaf cert (expires %s)", parsed.ExpiresAt)
	return nil
}
