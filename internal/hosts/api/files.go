package api

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/internal/requestctx"
	"github.com/NodeOps-app/createos-sandbox/internal/utils"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

// agentFilePort mirrors internal/agent/files.go. Not imported to keep api
// decoupled from agent (and because agent is build-tag-gated).
const agentFilePort = 1025

// Buffered guest JSON responses are untrusted. This cap does not apply to
// streamed file contents or process output.
const maxGuestResponseBytes = 4 << 20

func readGuestResponse(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxGuestResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxGuestResponseBytes {
		return nil, fmt.Errorf("guest response exceeds %d bytes", maxGuestResponseBytes)
	}
	return body, nil
}

// newFileClient returns an http.Client whose DialContext writes the
// per-VM "AUTH <token>\n" line as the first bytes on every fresh TCP
// connection to the agent. The agent's authListener reads that line on
// Accept(), then surrenders the conn (with the buffered HTTP request
// remainder preserved) to net/http. Keep-Alive connections inherit the
// authentication for subsequent requests on the same socket.
func newFileClient(token string) *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			c, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			// Single small write, no flush needed (TCP small-write
			// nagle is fine here — the next write is the HTTP request
			// line which arrives within microseconds).
			if _, werr := c.Write([]byte(proto.AuthPrefix + token + "\n")); werr != nil {
				c.Close()
				return nil, fmt.Errorf("write auth line: %w", werr)
			}
			return &fileConn{Conn: c}, nil
		},
		// Disable Keep-Alive: this client is constructed per request,
		// so connection reuse never kicks in anyway. Explicit DisableKeepAlives
		// avoids the runtime allocating an idle-conn pool that would
		// outlive the client.
		DisableKeepAlives: true,
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("guest file redirects are not permitted")
		},
	}
}

func (s *Server) handleFileUpload(c *fiber.Ctx) error {
	id := c.Params("id")
	path := c.Query("path")
	if err := validateFilePath(path); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, err.Error())
	}
	contentLength := int64(c.Request().Header.ContentLength())
	if contentLength > proto.MaxFileUploadBytes {
		return httpx.Fail(c, fiber.StatusRequestEntityTooLarge, "file exceeds 10 GiB limit")
	}

	target, err := s.Svc.OpenFileTransfer(c.UserContext(), id, utils.UserID(c))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		}
		log.WithContext(c.UserContext()).Errorf("[files.agent] target lookup: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if target.IP == "" {
		target.Cancel()
		return httpx.Error(c, fiber.StatusServiceUnavailable, "sandbox has no ip")
	}
	release, ok := s.acquireFileTransfer(id)
	if !ok {
		target.Cancel()
		c.Set(fiber.HeaderRetryAfter, "1")
		return httpx.Fail(c, fiber.StatusTooManyRequests, "file transfer capacity busy")
	}
	transferCtx, stopTransfer := requestctx.WithFileTransfer(target.Context, c.Context().Conn())
	finish := func() { stopTransfer(); target.Cancel(); release() }
	defer finish()
	u := url.URL{Scheme: "http", Host: net.JoinHostPort(target.IP, strconv.Itoa(agentFilePort)), Path: "/files" + path}
	uploadBody := c.Context().RequestBodyStream()
	if uploadBody == nil {
		uploadBody = bytes.NewReader(c.Body())
	}
	uploadBody = io.LimitReader(uploadBody, proto.MaxFileUploadBytes+1)
	uploadCtx, bodyReader, stopUpload := requestctx.WithFileUpload(transferCtx, uploadBody, c.Context().Conn())
	defer stopUpload()
	req, err := http.NewRequestWithContext(uploadCtx, http.MethodPut, u.String(), bodyReader)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if contentLength >= 0 {
		req.ContentLength = contentLength
	}
	resp, err := newFileClient(target.Token).Do(req)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[files.agent] upstream error: %v", err)

		return httpx.Error(c, fiber.StatusBadGateway, "upstream error")
	}
	defer resp.Body.Close()
	body, err := readGuestResponse(resp.Body)
	if err != nil {
		return httpx.Error(c, fiber.StatusBadGateway, "file agent response failed")
	}
	// Agent already emits JSend-shaped JSON on success.
	c.Status(resp.StatusCode)
	c.Set("Content-Type", resp.Header.Get("Content-Type"))
	return c.Send(body)
}

func (s *Server) handleFileDownload(c *fiber.Ctx) error {
	id := c.Params("id")
	path := c.Query("path")
	if err := validateFilePath(path); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, err.Error())
	}

	target, err := s.Svc.OpenFileTransfer(c.UserContext(), id, utils.UserID(c))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		}
		log.WithContext(c.UserContext()).Errorf("[files.agent] target lookup: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if target.IP == "" {
		target.Cancel()
		return httpx.Error(c, fiber.StatusServiceUnavailable, "sandbox has no ip")
	}
	release, ok := s.acquireFileTransfer(id)
	if !ok {
		target.Cancel()
		c.Set(fiber.HeaderRetryAfter, "1")
		return httpx.Fail(c, fiber.StatusTooManyRequests, "file transfer capacity busy")
	}
	transferCtx, stopTransfer := requestctx.WithFileTransfer(target.Context, c.Context().Conn())
	finish := func() { stopTransfer(); target.Cancel(); release() }
	streaming := false
	defer func() {
		if !streaming {
			finish()
		}
	}()
	u := url.URL{Scheme: "http", Host: net.JoinHostPort(target.IP, strconv.Itoa(agentFilePort)), Path: "/files" + path}
	req, err := http.NewRequestWithContext(transferCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	fileClient := newFileClient(target.Token)
	resp, err := fileClient.Do(req)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[files.agent] upstream error: %v", err)

		return httpx.Error(c, fiber.StatusBadGateway, "upstream error")
	}
	if resp.StatusCode == http.StatusNotFound {
		defer resp.Body.Close()
		return httpx.Fail(c, fiber.StatusNotFound, "file not found")
	}
	if resp.StatusCode >= http.StatusBadRequest {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return httpx.Error(c, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	for key, values := range resp.Header {
		for _, value := range values {
			c.Response().Header.Add(key, value)
		}
	}
	c.Set("Content-Type", "application/octet-stream")
	c.Status(resp.StatusCode)
	upstream := resp.Body
	streaming = true
	c.Response().SetBodyStreamWriter(fasthttp.StreamWriter(func(w *bufio.Writer) {
		defer finish()
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

func validateFilePath(p string) error {
	if p == "" {
		return errors.New("query param 'path' is required")
	}
	if !strings.HasPrefix(p, "/") {
		return errors.New("path must be absolute")
	}
	// Reject URL meta-characters and control bytes. Defense in depth: if
	// the path is concatenated into a URL (or any context that interprets
	// '?' / '#'), these would silently truncate or inject parameters. NUL
	// and other sub-0x20 bytes have no legitimate use in file paths.
	for i := 0; i < len(p); i++ {
		b := p[i]
		if b < 0x20 || b == '?' || b == '#' {
			return errors.New("path contains invalid characters")
		}
	}
	// Require the path to be already-normalised. filepath.Clean
	// collapses `..`, `.`, and `//` runs — any of those mean the
	// caller supplied a non-canonical path that could trick a future
	// path-join into escaping the sandbox dir.
	if filepath.Clean(p) != p {
		return errors.New("path must be canonical (no '..', '.', or '//')")
	}
	return nil
}

// Refresh both directions on progress: uploads may write for longer than the
// idle limit while the response reader is already waiting for guest headers.
type fileConn struct{ net.Conn }

func (c *fileConn) NetConn() net.Conn { return c.Conn }

func (c *fileConn) Read(b []byte) (int, error) {
	_ = c.Conn.SetDeadline(time.Now().Add(time.Minute))
	return c.Conn.Read(b)
}
func (c *fileConn) Write(b []byte) (int, error) {
	_ = c.Conn.SetDeadline(time.Now().Add(time.Minute))
	return c.Conn.Write(b)
}

// Reject excess work rather than queueing more stalled transfers. Limits are
// shared by uploads/downloads and held until the response stream is closed.
func (s *Server) acquireFileTransfer(id string) (func(), bool) {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	if s.fileCount >= 64 || s.fileTransfers[id] >= 8 {
		return nil, false
	}
	if s.fileTransfers == nil {
		s.fileTransfers = make(map[string]int)
	}
	id = strings.Clone(id)
	s.fileCount++
	s.fileTransfers[id]++
	return func() {
		s.fileMu.Lock()
		defer s.fileMu.Unlock()
		s.fileCount--
		s.fileTransfers[id]--
		if s.fileTransfers[id] == 0 {
			delete(s.fileTransfers, id)
		}
	}, true
}
