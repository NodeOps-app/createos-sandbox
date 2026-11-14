package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/NodeOps-app/createos-sandbox/models"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
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
			"service unavailable")
	}

	upstream := strings.TrimRight(peerURL, "/") + path
	if qs := c.Context().QueryArgs().String(); qs != "" {
		upstream += "?" + qs
	}

	req, err := h.peerControlRequest(c, method, upstream, c.Body())
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[forward] build request: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}

	resp, err := h.peerHTTPClient.Do(req)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[forward] dial peer %s for region=%s: %v", upstream, targetRegion, err)
		return httpx.Error(c, fiber.StatusBadGateway,
			"service unavailable")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[forward] read peer response: %v", err)
		return httpx.Error(c, fiber.StatusBadGateway, "service unavailable")
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

// peerControlRequest shares the ordinary caller-authenticated forwarding path
// with the read-only replication check; neither trusts forwarded user identity.
func (h *Handler) peerControlRequest(c *fiber.Ctx, method, upstream string, body []byte) (*http.Request, error) {
	// Fiber strings alias fasthttp's reusable request buffer. net/http's
	// HTTP/2 transport retains method and header strings in its HPACK table
	// after this handler returns, so detach everything crossing that boundary.
	req, err := http.NewRequestWithContext(c.UserContext(), strings.Clone(method), upstream, bytes.NewReader(body))
	if err != nil {
		return nil, err
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
	httpx.SetRequestIDHeader(c.UserContext(), req)
	req.Header.Set("X-Forwarded-By", "control:"+h.region)

	return req, nil
}

// Wait for the exact failed origin row, including when it has not arrived yet.
// A conflict-only retry misses that case: the peer could insert the new named
// row before receiving the origin's creating row and break replication on the
// unique-name index. GET reads the peer's local replica and enforces ownership.
// No create is sent until the peer has applied the terminal update.
func (h *Handler) waitForPeerFailedSandbox(c *fiber.Ctx, region, id string) (waitErr error) {
	started := time.Now()
	attempts := 0
	defer func() {
		entry := log.WithContext(c.UserContext()).WithFields(log.Fields{
			"origin_region": h.region,
			"target_region": region,
			"sandbox_id":    id,
			"attempts":      attempts,
			"wait_ms":       time.Since(started).Milliseconds(),
		})
		if waitErr != nil {
			entry.WithError(waitErr).WithField("outcome", "failed").Warn("[create-fallback] replication wait")
		} else {
			entry.WithField("outcome", "ready").Info("[create-fallback] replication wait")
		}
	}()
	ctx, cancel := context.WithTimeout(c.UserContext(), 5*time.Second)
	defer cancel()
	upstream := strings.TrimRight(h.peerControls[region], "/") + "/v1/sandboxes/" + id
	req, err := h.peerControlRequest(c, http.MethodGet, upstream, nil)
	if err != nil {
		return err
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		attempts++
		resp, err := h.peerHTTPClient.Do(req.Clone(ctx))
		if err != nil {
			return err
		}
		var result struct {
			Data struct {
				ID     string        `json:"id"`
				Status models.Status `json:"status"`
			} `json:"data"`
		}
		if resp.StatusCode == http.StatusOK {
			err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result)
		}
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("decode peer sandbox: %w", err)
		}
		if resp.StatusCode == http.StatusOK {
			if result.Data.ID != id {
				return fmt.Errorf("peer returned a different sandbox")
			}
			if result.Data.Status == models.StatusFailed {
				return nil
			}
		} else if resp.StatusCode != http.StatusNotFound {
			return fmt.Errorf("peer sandbox lookup returned HTTP %d", resp.StatusCode)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
