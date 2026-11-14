// CRL endpoint — unauthenticated read of revoked leaf serials.
//
// Every verifier (host, ingress, gateway, proxy, scheduler) polls
// GET /v1/internal/crl on a short interval and refuses TLS handshakes
// whose peer's cert serial appears in the list. The endpoint is
// intentionally unauthenticated: it contains zero secret material —
// just opaque random serial numbers — and any verifier that can't
// fetch it must fail-closed, so gating it behind a token would only
// shift the failure mode without raising the bar against attackers.
package handlers

import (
	"time"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// crlNextUpdateOffset is the validity window the CRL response
// advertises. TLS verifiers use next_update_at to detect stale revocation
// data; this window is independent of JWT expiry and certificate lifetime.
const crlNextUpdateOffset = 60 * time.Second

type crlEntryJSON struct {
	Serial string `json:"serial"`
	Reason string `json:"reason,omitempty"`
}

type crlRespJSON struct {
	IssuedAt     string         `json:"issued_at"`
	NextUpdateAt string         `json:"next_update_at"`
	Revoked      []crlEntryJSON `json:"revoked"`
}

// HandleCRL returns the current revoked-serial list. No auth — see
// the package comment for why.
func (h *Handler) HandleCRL(c *fiber.Ctx) error {
	serials, err := models.ListRevokedSerialsLedger(c.UserContext(), h.repo.DB)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] CRL list: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	now := time.Now().UTC()
	entries := make([]crlEntryJSON, 0, len(serials))
	for _, s := range serials {
		// ListRevokedSerialsLedger returns serials only; the ledger's
		// per-row revoked_by column isn't surfaced on the CRL today
		// since verifiers don't act on reason.
		entries = append(entries, crlEntryJSON{Serial: s})
	}
	return httpx.Success(c, crlRespJSON{
		IssuedAt:     now.Format(time.RFC3339),
		NextUpdateAt: now.Add(crlNextUpdateOffset).Format(time.RFC3339),
		Revoked:      entries,
	})
}
