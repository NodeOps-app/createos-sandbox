package handlers

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/httpx"
)

// forwardToPeerControl relays the current request to the control plane
// in the target region. Used for cross-region create/resume/fork where
// the owning region's scheduler is authoritative for placement.
//
// The peer URL points at the peer's DIRECT ORIGIN (no CDN in the path)
// — peer serves a real TLS cert (Let's Encrypt / similar) that the
// forwarder verifies against system root CAs via h.peerHTTPClient.
// The forwarder passes the caller's API key, body, and non-hop
// headers verbatim. The peer authenticates the request via its
// normal user-auth path, identical to the user dialing directly.
// No mTLS between controls is required — auth is at the HTTP layer.
//
// Returns the peer's response transparently to the caller. Failure
// modes: unknown target region → 503; peer unreachable → 502.
func (h *Handler) forwardToPeerControl(c *fiber.Ctx, targetRegion, method, path string) error {
	peerURL, ok := h.peerControls[targetRegion]
	if !ok || strings.TrimSpace(peerURL) == "" {
		log.WithContext(c.UserContext()).Warnf("[forward] no peer URL configured for region=%s (origin=%s)", targetRegion, h.region)
		return httpx.Error(c, fiber.StatusServiceUnavailable,
			fmt.Sprintf("region %q has no peer control configured on this cluster", targetRegion))
	}

	upstream := strings.TrimRight(peerURL, "/") + path
	if qs := c.Context().QueryArgs().String(); qs != "" {
		upstream += "?" + qs
	}

	// Fiber strings alias fasthttp's reusable request buffer. net/http's
	// HTTP/2 transport retains method and header strings in its HPACK table
	// after this handler returns, so detach everything crossing that boundary.
	req, err := http.NewRequestWithContext(c.UserContext(), strings.Clone(method), upstream, bytes.NewReader(c.Body()))
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[forward] build request: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	// Pass through the caller's auth + content headers. Hop-by-hop and
	// internal-only headers are dropped — peer must re-derive context
	// from the user's API key, exactly as if the user had dialed it directly.
	for k, vs := range c.GetReqHeaders() {
		if shouldDropForwardHeader(k) {
			continue
		}
		for _, v := range vs {
			req.Header.Add(strings.Clone(k), strings.Clone(v))
		}
	}
	req.Header.Set("X-Forwarded-By", "control:"+h.region)

	resp, err := h.peerHTTPClient.Do(req)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[forward] dial peer %s for region=%s: %v", upstream, targetRegion, err)
		return httpx.Error(c, fiber.StatusBadGateway,
			fmt.Sprintf("peer control for region %q unreachable", targetRegion))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[forward] read peer response: %v", err)
		return httpx.Error(c, fiber.StatusBadGateway, "peer response read failed")
	}
	// Copy non-hop response headers back.
	for k, vs := range resp.Header {
		if shouldDropForwardHeader(k) {
			continue
		}
		for _, v := range vs {
			c.Set(k, v)
		}
	}
	c.Status(resp.StatusCode)
	return c.Send(body)
}

// shouldDropForwardHeader returns true for headers that must not be
// proxied between control planes — hop-by-hop headers per RFC 7230
// plus the internal user-id stamp (it's re-derived from the API key
// on the peer side; passing it would let any caller pin the resolved
// user id rather than going through the API key cache).
func shouldDropForwardHeader(k string) bool {
	switch strings.ToLower(k) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailer", "transfer-encoding", "upgrade",
		"host", "content-length",
		"x-createos-user-id":
		return true
	}
	return false
}
