package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// openTunnel dials the host directly (skipping control) and performs an
// HTTP/1.1 Upgrade handshake to obtain a raw TCP tunnel aimed at
// sandboxID's tcp port. The returned net.Conn is the underlying socket —
// the caller is expected to splice it onto an SSH channel.
//
// Wire protocol:
//
//	POST /v1/internal/tunnel/<sbID>/<port> HTTP/1.1
//	Host: <hostAddr>
//	Connection: Upgrade
//	Upgrade: tcp-tunnel
//	Content-Length: 0
//
// A 101 Switching Protocols response promotes the socket to a raw
// bidirectional byte stream.
//
// Auth is the outbound mTLS client cert (gateway's SPIFFE leaf). The
// host's tunnel route is `HostMustBePeerRoleMTLS("ingress", "gateway",
// "control")` — gateway is accepted directly, no need to round-trip
// through control. The SSH-side owner check (g.authorise) already proved
// this user owns the sandbox at session-open time.
func (g *Gateway) openTunnel(ctx context.Context, hostAddr, sandboxID string, port int) (net.Conn, error) {
	// hostAddr may arrive as "192.0.2.30:9090", "https://192.0.2.30:9090", or
	// bare "192.0.2.30" (host DB stores any of these). Normalise:
	addr := strings.TrimPrefix(strings.TrimPrefix(hostAddr, "https://"), "http://")
	if addr == "" {
		return nil, fmt.Errorf("empty host addr")
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		// No port — assume host's internal mTLS listener default.
		addr = net.JoinHostPort(addr, "9090")
	}
	if g.outboundTLS == nil {
		return nil, fmt.Errorf("gateway mTLS not configured (tls-cert/tls-key/tls-ca required for host dial)")
	}

	d := net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	serverName := addr
	if h, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
		serverName = h
	}
	cfg := g.outboundTLS.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName = serverName
	}
	tlsConn := tls.Client(rawConn, cfg)
	hsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		cancel()
		rawConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	cancel()
	var conn net.Conn = tlsConn
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	}

	// Escape both path components. sandboxID is already filtered to the
	// strict ULID-shaped format by authPublicKey, but the request line is
	// hand-built — keep PathEscape here as defense in depth so any future
	// path lower than the auth filter still can't smuggle CRLF/spaces.
	path := "/v1/internal/tunnel/" + url.PathEscape(sandboxID) + "/" + strconv.Itoa(port)
	req := "POST " + path + " HTTP/1.1\r\n" +
		"Host: " + addr + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: tcp-tunnel\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read status: %w", err)
	}
	statusLine = strings.TrimRight(statusLine, "\r\n")
	// Expect "HTTP/1.1 101 Switching Protocols".
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 || parts[1] != "101" {
		// Drain a few bytes for context, then fail.
		conn.Close()
		return nil, fmt.Errorf("tunnel upgrade failed: %q", statusLine)
	}
	// Consume headers up to the empty line.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("read headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// Clear any deadline now that the handshake is done — caller manages IO.
	_ = conn.SetDeadline(time.Time{})

	return &bufConn{Conn: conn, r: br}, nil
}

// bufConn wraps a net.Conn so reads come from the bufio.Reader used
// during the HTTP Upgrade handshake (preserving any prefetched bytes)
// while writes and close still go straight to the underlying conn.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// CloseWrite forwards to the underlying TCP conn so half-close propagates.
func (b *bufConn) CloseWrite() error {
	if tc, ok := b.Conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	// Fall back to full close.
	return b.Close()
}
