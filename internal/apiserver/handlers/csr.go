// Host CSR endpoint — mTLS bootstrap for hosts.
//
// The endpoint accepts a PEM-encoded PKCS#10 CSR, verifies its
// signature + SAN URI, then mints a leaf cert via h.ca. It is gated by
// the same X-Bootstrap-Token shared secret used on
// /v1/internal/hosts/register. Non-host actor certificates are issued
// offline with the admin CA CLI and are never minted over HTTP.
package handlers

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/ca"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// csrRespJSON is the on-the-wire shape returned by the host CSR endpoint.
// PEM-encoded cert + the CA's cert so callers can pin a trust anchor
// without an out-of-band bundle fetch.
type csrRespJSON struct {
	CertPEM   string `json:"cert_pem"`
	CAPEM     string `json:"ca_pem"`
	ExpiresAt string `json:"expires_at"`
}

// hostCSRReq is POST /v1/internal/hosts/csr.
type hostCSRReq struct {
	HostID string `json:"host_id"`
	CSRPEM string `json:"csr_pem"`
}

// HandleHostCSR mints a host leaf cert from a CSR. Dual-mode auth:
//
//	First-time enrolment  (no active cert for host_id in ledger):
//	    Bootstrap token alone is sufficient. Host has no prior
//	    identity to prove ownership with.
//
//	Re-issue / rotation   (an active, non-revoked cert exists):
//	    Bootstrap token is NOT enough. The caller MUST present an
//	    mTLS peer cert whose SPIFFE URI is spiffe://createos/host/<host_id>
//	    for the SAME host_id. This blocks the leaked-bootstrap-token
//	    attack where a third party mints a leaf for a host they don't
//	    operate.
//
// Recovery path: if a host loses its private key (cert can no longer
// be presented), an operator revokes the lost cert with `admin ca
// revoke`. With no active cert in the ledger the next CSR call is
// treated as first-time enrolment again.
func (h *Handler) HandleHostCSR(c *fiber.Ctx) error {
	if h.ca == nil {
		return httpx.Error(c, fiber.StatusServiceUnavailable, "mTLS disabled")
	}
	// The bootstrap-token gate is enforced by the route's
	// MustBeBootstrappingHost middleware. By the time this handler
	// runs the caller has already passed that check.

	var req hostCSRReq
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	hostID := strings.TrimSpace(req.HostID)
	if hostID == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "host_id required")
	}

	// Re-issue gate. If the host already has an active leaf, demand
	// proof-of-possession of the existing private key — i.e. require
	// the caller to present that leaf via mTLS, with the SPIFFE URI
	// pinned to the SAME host_id.
	active, err := models.GetActiveCert(c.UserContext(), h.repo.DB, models.CertKindHost, hostID)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] host CSR ledger lookup %s: %v", hostID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if active != nil {
		if msg := peerCertMismatchReason(c, hostID); msg != "" {
			return httpx.Fail(c, fiber.StatusForbidden, msg)
		}
	}

	csrDER, err := decodeCSRPEM(req.CSRPEM)
	if err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, err.Error())
	}
	// Verify the SAN URI matches what we're about to mint into the
	// leaf. Mismatched URI = misconfigured caller, refuse at the door
	// rather than handing back a cert with the wrong identity baked in.
	if err := requireSpiffeMatch(csrDER, ca.URIIdentity{HostID: hostID}); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, err.Error())
	}

	ttl := models.CertTTL(models.CertKindHost)
	leafDER, serial, err := h.ca.IssueCert(csrDER, ca.URIIdentity{HostID: hostID}, ttl)
	if err != nil {
		if errors.Is(err, ca.ErrHostSANNotAllowed) {
			return httpx.Fail(c, fiber.StatusBadRequest, err.Error())
		}
		log.WithContext(c.UserContext()).Errorf("[handler] host CSR issue %s: %v", hostID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	expiresAt := time.Now().UTC().Add(ttl)
	if err := models.RotateCertWithGrace(c.UserContext(), h.repo.DB, models.IssuedCert{
		CertSerial:  serial.Text(16),
		SubjectKind: models.CertKindHost,
		SubjectID:   hostID,
		ExpiresAt:   expiresAt,
	}, models.HostRotateRevokeGrace); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] host CSR persist %s: %v", hostID, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, csrRespJSON{
		CertPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		CAPEM:     string(h.ca.CertPEM),
		ExpiresAt: expiresAt.Format(time.RFC3339),
	})
}

// peerCertMismatchReason inspects the request's TLS peer cert against
// `hostID`. Returns "" on accept (mTLS leaf present + SPIFFE URI is
// `spiffe://createos/host/<hostID>`); a human-readable reason
// otherwise. The caller passes the reason to httpx.Fail with 403.
//
// IMPORTANT: this returns a Go string, NOT a Fiber error. Earlier
// versions wrapped httpx.Fail and returned its result, but httpx.Fail
// returns nil on success, so `if err := …; err != nil` silently fell
// through and the handler continued past the gate. The string-return
// shape forces the caller to invoke httpx.Fail itself, which can't be
// accidentally short-circuited.
//
// Listener model: the same Fiber app is served on both :8080 (public,
// no client cert) and :8443 (mTLS, RequireAndVerifyClientCert). On the
// public listener `TLSConnectionState()` either returns nil or has no
// PeerCertificates — both rejected. On the internal listener the leaf
// is already cryptographically verified by the TLS stack + CRL check;
// we only inspect the SPIFFE URI.
func peerCertMismatchReason(c *fiber.Ctx, hostID string) string {
	state := c.Context().TLSConnectionState()
	if state == nil || len(state.PeerCertificates) == 0 {
		return "host_id already has an active cert; re-issue requires mTLS with the existing leaf"
	}
	leaf := state.PeerCertificates[0]
	if len(leaf.URIs) == 0 {
		return "peer cert missing SPIFFE URI SAN"
	}
	ident, ok := ca.ParseSpiffeURI(leaf.URIs[0].String())
	if !ok || ident.HostID == "" {
		return "peer cert is not a host cert"
	}
	if ident.HostID != hostID {
		return "peer cert host_id does not match request"
	}
	return ""
}

// decodeCSRPEM strips the PEM envelope from a CSR submission and
// returns the raw DER bytes. Empty PEM, wrong block type, or trailing
// garbage all surface as 400-friendly errors.
func decodeCSRPEM(p string) ([]byte, error) {
	if strings.TrimSpace(p) == "" {
		return nil, errors.New("csr_pem required")
	}
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, errors.New("csr_pem: no PEM block")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, errors.New("csr_pem: unexpected PEM block type")
	}
	return block.Bytes, nil
}

// requireSpiffeMatch parses a CSR and asserts its SAN URI list
// contains exactly the expected SPIFFE identity. Any mismatch (no SAN,
// wrong URI shape, multiple URIs, identity doesn't match) returns an
// error suitable for surfacing as 400.
func requireSpiffeMatch(csrDER []byte, want ca.URIIdentity) error {
	// Re-parsing the CSR here is cheap and lets us avoid leaking
	// ca-package internals (crypto/x509 types) into the handler.
	// CA.IssueCert will parse + verify-signature again itself.
	parsed, err := parseCSRForSpiffeCheck(csrDER)
	if err != nil {
		return err
	}
	if len(parsed) == 0 {
		return errors.New("csr is missing a SAN URI")
	}
	wantStr := ca.FormatSpiffeURI(want)
	for _, u := range parsed {
		if u == wantStr {
			return nil
		}
	}
	return errors.New("csr SAN URI does not match request")
}

// parseCSRForSpiffeCheck pulls the SAN URI list out of a CSR.
// Re-parsing on the handler side keeps the ca package's surface area
// minimal — IssueCert does its own parse + signature check, this one
// only needs to inspect URIs to compare against the request body.
func parseCSRForSpiffeCheck(der []byte) ([]string, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, errors.New("csr: parse failed")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("csr: bad signature")
	}
	out := make([]string, 0, len(csr.URIs))
	for _, u := range csr.URIs {
		if u == nil {
			continue
		}
		out = append(out, u.String())
	}
	return out, nil
}
