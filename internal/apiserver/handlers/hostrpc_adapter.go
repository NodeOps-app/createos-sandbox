package handlers

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"

	"github.com/NodeOps-app/createos-sandbox/internal/hostrpc"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/internal/requestctx"
	"github.com/NodeOps-app/createos-sandbox/internal/utils"
	"github.com/NodeOps-app/createos-sandbox/models"
)

// Buffered host operations should return compact JSON. Computer responses can
// legitimately approach 32 MiB, so retain headroom while preventing an
// unhealthy or compromised host from making control allocate without bound.
const maxBufferedHostResponseBytes int64 = 64 << 20

// hopByHop are response headers that must never cross the Fiber adapter.
// Request filtering belongs to hostrpc.Forward.
var hopByHop = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

func forwardHeaders(c *fiber.Ctx) http.Header {
	headers := make(http.Header)
	for key, value := range c.Request().Header.All() {
		headers.Add(strings.Clone(string(key)), strings.Clone(string(value)))
	}
	return headers
}

// ForwardResponseTo relays the current Fiber request to host.Addr + path over HTTP,
// preserving method, body, and non-hop-by-hop headers. The upstream response
// status and body are written back to the Fiber context verbatim so any
// JSend envelope emitted by the host is passed through untouched.
//
// A transport-level failure is surfaced as a 502 error envelope.
func ForwardResponseTo(c *fiber.Ctx, host models.Host, path string, httpClient *http.Client) error {
	return ForwardToWithHeaders(c, host, path, httpClient, nil)
}

// ForwardResponseToAs is ForwardResponseTo with an explicit end-user identity
// stamped onto the host request. Like ForwardResponseTo, it writes the host's
// complete response into c; callers should return its error result directly.
func ForwardResponseToAs(c *fiber.Ctx, host models.Host, path string, httpClient *http.Client, userID string) error {
	return ForwardToWithHeaders(c, host, path, httpClient, map[string]string{
		utils.HeaderUserID: userID,
	})
}

// ForwardFileUploadTo streams a file request directly from the client to the
// host. Unlike ForwardResponseTo it never calls c.Body(), so control-plane memory use
// stays bounded independently of the file size.
func ForwardFileUploadTo(c *fiber.Ctx, host models.Host, path string, httpClient *http.Client) error {
	return ForwardFileUploadToAs(c, host, path, httpClient, utils.UserID(c))
}

func ForwardFileUploadToAs(c *fiber.Ctx, host models.Host, path string, httpClient *http.Client, userID string) error {
	contentLength := int64(c.Request().Header.ContentLength())
	if contentLength > proto.MaxFileUploadBytes {
		return httpx.Fail(c, fiber.StatusRequestEntityTooLarge, "file exceeds 10 GiB limit")
	}

	transferCtx, finish := requestctx.WithFileTransfer(c.UserContext(), c.Context().Conn())
	defer finish()
	body := c.Context().RequestBodyStream()
	if body == nil {
		body = bytes.NewReader(c.Body())
	}
	body = io.LimitReader(body, proto.MaxFileUploadBytes+1)
	uploadCtx, bodyReader, stopUpload := requestctx.WithFileUpload(transferCtx, body, c.Context().Conn())
	defer stopUpload()
	resp, err := hostrpc.Forward(uploadCtx, httpClient, host, hostrpc.ForwardRequest{
		Method:        strings.Clone(c.Method()),
		Path:          path,
		Query:         string(c.Request().URI().QueryString()),
		Header:        forwardHeaders(c),
		Body:          bodyReader,
		ContentLength: contentLength,
		UserID:        userID,
	})
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[files] host upload: %v", err)
		return httpx.Error(c, fiber.StatusBadGateway, "upstream error")
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[files] host upload - read failed: %v", err)
		return httpx.Error(c, fiber.StatusBadGateway, "upstream error")
	}
	c.Status(resp.StatusCode)
	c.Set(fiber.HeaderContentType, resp.Header.Get(fiber.HeaderContentType))
	return c.Send(responseBody)
}

// ForwardFileDownloadTo streams a file response from the host to the client.
// The ordinary ForwardResponseTo path buffers upstream responses so it can validate
// JSend envelopes; file bodies can be multiple GiB and must remain bounded.
func ForwardFileDownloadTo(c *fiber.Ctx, host models.Host, path string, httpClient *http.Client) error {
	return ForwardFileDownloadToAs(c, host, path, httpClient, utils.UserID(c))
}

func ForwardFileDownloadToAs(c *fiber.Ctx, host models.Host, path string, httpClient *http.Client, userID string) error {
	streamCtx, cancel := requestctx.WithFileTransfer(context.WithoutCancel(c.UserContext()), c.Context().Conn())
	resp, err := hostrpc.Forward(streamCtx, httpClient, host, hostrpc.ForwardRequest{
		Method:         http.MethodGet,
		Path:           path,
		Query:          string(c.Request().URI().QueryString()),
		ContentLength:  -1,
		UserID:         userID,
		WithoutTimeout: true,
	})
	if err != nil {
		cancel()
		log.WithContext(c.UserContext()).Errorf("[files] host download: %v", err)
		return httpx.Error(c, fiber.StatusBadGateway, "upstream error")
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		defer resp.Body.Close()
		defer cancel()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		c.Status(resp.StatusCode)
		c.Set(fiber.HeaderContentType, resp.Header.Get(fiber.HeaderContentType))
		return c.Send(body)
	}

	for key, values := range resp.Header {
		if _, drop := hopByHop[strings.ToLower(key)]; drop {
			continue
		}
		for _, value := range values {
			c.Response().Header.Add(key, value)
		}
	}
	c.Status(resp.StatusCode)
	upstream := resp.Body
	c.Response().SetBodyStreamWriter(fasthttp.StreamWriter(func(w *bufio.Writer) {
		defer cancel()
		defer upstream.Close()
		buf := make([]byte, 64*1024)
		for {
			n, readErr := upstream.Read(buf)
			if n > 0 {
				if _, writeErr := w.Write(buf[:n]); writeErr != nil {
					return
				}
				if flushErr := w.Flush(); flushErr != nil {
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}))
	return nil
}

// ForwardToWithHeaders is the Fiber adapter for hostrpc.Forward. It snapshots
// the inbound request and relays the returned host response into Fiber.
func ForwardToWithHeaders(c *fiber.Ctx, host models.Host, path string, httpClient *http.Client, extraHeaders map[string]string) error {
	method := strings.Clone(c.Method())
	body := c.Body()
	headers := forwardHeaders(c)
	for key, value := range extraHeaders {
		headers.Set(key, value)
	}
	userID := utils.UserID(c)
	if explicit, ok := extraHeaders[utils.HeaderUserID]; ok {
		userID = explicit
	}

	traceCtx, clientTimings := httpx.WithClientTimings(c.UserContext())
	tDo := time.Now()
	resp, err := hostrpc.Forward(traceCtx, httpClient, host, hostrpc.ForwardRequest{
		Method:        method,
		Path:          path,
		Query:         string(c.Request().URI().QueryString()),
		Header:        headers,
		Body:          bytes.NewReader(body),
		ContentLength: int64(len(body)),
		UserID:        userID,
	})
	doMs := float64(time.Since(tDo).Microseconds()) / 1000.0
	httpPhases := clientTimings()
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] upstream error: %v", err)

		return httpx.Error(c, fiber.StatusBadGateway, "upstream error")
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		lc := strings.ToLower(k)
		if _, drop := hopByHop[lc]; drop {
			continue
		}
		for _, v := range vs {
			c.Response().Header.Add(k, v)
		}
	}

	tRead := time.Now()
	buf, err := hostrpc.ReadResponseBody(resp, maxBufferedHostResponseBytes)
	readMs := float64(time.Since(tRead).Microseconds()) / 1000.0
	// Internal telemetry — do=httpClient.Do (dial+TLS+write+response-headers),
	// read=body read from host. Grep by sandbox path/URL.
	log.WithContext(c.UserContext()).Infof("[fwd-inner] rid=%s path=%s pool=%.2f dns=%.2f connect=%.2f tls=%.2f ttfb=%.2f reused=%v do=%.2f read=%.2f status=%d bytes=%d",
		httpx.RequestID(c.UserContext()), path, ms(httpPhases.Pool), ms(httpPhases.DNS),
		ms(httpPhases.Connect), ms(httpPhases.TLS), ms(httpPhases.TTFB), httpPhases.Reused,
		doMs, readMs, resp.StatusCode, len(buf))
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] upstream error: %v", err)
		if errors.Is(err, hostrpc.ErrResponseTooLarge) {
			return httpx.Error(c, fiber.StatusBadGateway, "upstream response too large; use streaming for large output")
		}
		return httpx.Error(c, fiber.StatusBadGateway, "upstream error")
	}
	// Sanity check: buffered host handlers emit a response body except for a
	// legitimate 204 No Content (used by managed-process stdin-close, resize,
	// and signal). An empty body on another 2xx shows up when
	// http.Transport hands us a stale keep-alive conn that the host
	// half-closed (e.g. while another long exec on the same sandbox is
	// holding a different conn open). Surface as 502 so the client
	// retries instead of mis-treating the empty body as a real reply.
	if len(buf) == 0 && resp.StatusCode >= 200 && resp.StatusCode < 300 &&
		resp.StatusCode != http.StatusNoContent {
		log.WithContext(c.UserContext()).Warnf("[handler] upstream host=%s path=%s returned empty %d body; treating as 502", host.ID, path, resp.StatusCode)
		// Drop any headers we already buffered so the 502 envelope is clean.
		c.Response().Header.Reset()
		return httpx.Error(c, fiber.StatusBadGateway, "upstream returned empty response")
	}
	c.Status(resp.StatusCode)
	return c.Send(buf)
}

// writeBufferedHostResponse adapts a typed hostrpc response to Fiber while
// preserving the same safe-header and non-empty-success rules as forwarding.
func writeBufferedHostResponse(c *fiber.Ctx, response *http.Response) error {
	for key, values := range response.Header {
		if _, drop := hopByHop[strings.ToLower(key)]; drop {
			continue
		}
		for _, value := range values {
			c.Response().Header.Add(key, value)
		}
	}
	body, err := hostrpc.ReadResponseBody(response, maxBufferedHostResponseBytes)
	if err != nil {
		c.Response().Header.Reset()
		if errors.Is(err, hostrpc.ErrResponseTooLarge) {
			return httpx.Error(c, fiber.StatusBadGateway, "upstream response too large; use streaming for large output")
		}
		return httpx.Error(c, fiber.StatusBadGateway, "upstream error")
	}
	if len(body) == 0 && response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices &&
		response.StatusCode != http.StatusNoContent {
		c.Response().Header.Reset()
		return httpx.Error(c, fiber.StatusBadGateway, "upstream returned empty response")
	}
	c.Status(response.StatusCode)
	return c.Send(body)
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// ForwardStreamTo is the streaming variant of ForwardResponseTo. Instead of
// reading the upstream body to completion, it pipes it through to
// the client one chunk at a time via fasthttp's SetBodyStreamWriter.
// Used for endpoints that emit NDJSON (currently `?stream=true` exec).
//
// Disconnect propagation: when the client closes its half-conn, the
// w.Flush call returns an error → we break the loop → defer closes
// resp.Body → upstream HTTP/1.1 conn is closed → host's
// SetBodyStreamWriter sees the failed write → its defer closes the
// agent TCP conn → agent kills the command.
func ForwardStreamTo(c *fiber.Ctx, host models.Host, path string, httpClient *http.Client) error {
	return ForwardStreamToAs(c, host, path, httpClient, utils.UserID(c))
}

func ForwardStreamToAs(c *fiber.Ctx, host models.Host, path string, httpClient *http.Client, userID string) error {
	// Manual cancel context — NOT c.UserContext(), which Fiber recycles
	// the moment the handler returns. We need cancellation tied to the
	// stream writer's exit instead, so disconnects on the client side
	// propagate up to the host. cancel is invoked by the deferred cleanup
	// inside SetBodyStreamWriter below.
	streamCtx, streamCancel := requestctx.WithDisconnect(context.WithoutCancel(c.UserContext()), c.Context().Conn())
	// The shared control-to-host client has a one-hour safety timeout for
	// ordinary RPCs. Streaming exec and managed-process connections may live
	// for the sandbox's entire lifetime, so reuse its transport but let the
	// stream writer's cancellation own the deadline.
	body := c.Body()
	resp, err := hostrpc.Forward(streamCtx, httpClient, host, hostrpc.ForwardRequest{
		Method:         strings.Clone(c.Method()),
		Path:           path,
		Query:          string(c.Request().URI().QueryString()),
		Header:         forwardHeaders(c),
		Body:           bytes.NewReader(body),
		ContentLength:  int64(len(body)),
		UserID:         userID,
		WithoutTimeout: true,
	})
	if err != nil {
		streamCancel()
		log.WithContext(c.UserContext()).Errorf("[handler] upstream error: %v", err)

		return httpx.Error(c, fiber.StatusBadGateway, "upstream error")
	}
	if resp.StatusCode != http.StatusOK {
		// Non-2xx → consume + relay buffered (the failure body is small
		// and error semantics are easier when fully read up front).
		defer resp.Body.Close()
		streamCancel()
		buf, _ := io.ReadAll(resp.Body)
		c.Status(resp.StatusCode)
		return c.Send(buf)
	}

	for k, vs := range resp.Header {
		lc := strings.ToLower(k)
		if _, drop := hopByHop[lc]; drop {
			continue
		}
		for _, v := range vs {
			c.Response().Header.Add(k, v)
		}
	}
	// Force the same anti-buffering hints we set host-side.
	c.Set(fiber.HeaderCacheControl, "no-cache")
	c.Set("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)

	// Snapshot the upstream body — the callback runs after fiber has
	// recycled the inbound c, so anything we capture from c will panic.
	// The deferred streamCancel() is the load-bearing piece: when the
	// client disconnects (w.Write fails), we cancel the upstream
	// request context, which closes the TCP conn to the host, which
	// makes the host's response stream fail, which makes its agent
	// conn close, which makes the agent kill the command.
	upstream := resp.Body
	c.Response().SetBodyStreamWriter(fasthttp.StreamWriter(func(w *bufio.Writer) {
		defer streamCancel()
		defer upstream.Close()
		buf := make([]byte, 4096)
		for {
			n, rerr := upstream.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				if ferr := w.Flush(); ferr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}))
	return nil
}
