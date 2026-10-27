package ingress

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// tunnelConn pairs the raw net.Conn with the bufio.Reader used to parse
// the HTTP upgrade response, so any bytes buffered after the headers
// are still available to the caller.
type tunnelConn struct {
	net.Conn
	br *bufio.Reader
}

func (t *tunnelConn) Read(p []byte) (int, error) {
	if t.br != nil && t.br.Buffered() > 0 {
		return t.br.Read(p)
	}
	return t.Conn.Read(p)
}

// OpenIngressTunnel opens a raw TCP tunnel through the host that owns
// sandboxID, targeting <port> inside the sandbox. Mirrors
// control.OpenTunnel — single Upgrade hop, then bidirectional bytes.
//
// Auth is the outbound mTLS client cert configured on tlsCfg. The host's
// tunnel route is mTLS-only and its handler bypasses the per-user owner
// check (see Svc.LookupIP), so no JWT or user identity is needed.
func OpenIngressTunnel(ctx context.Context, hostAddr, sandboxID string, port int, tlsCfg *tls.Config) (net.Conn, error) {
	addr := strings.TrimPrefix(strings.TrimPrefix(hostAddr, "http://"), "https://")
	if addr == "" {
		return nil, fmt.Errorf("empty host addr")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial host: %w", err)
	}
	conn := rawConn
	if tlsCfg != nil {
		host := addr
		if h, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
			host = h
		}
		cfg := tlsCfg.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = host
		}
		tlsConn := tls.Client(rawConn, cfg)
		hsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if err := tlsConn.HandshakeContext(hsCtx); err != nil {
			cancel()
			rawConn.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		cancel()
		conn = tlsConn
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	path := fmt.Sprintf("/v1/internal/tunnel/%s/%d", sandboxID, port)
	reqLine := "POST " + path + " HTTP/1.1\r\n" +
		"Host: " + addr + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: tcp-tunnel\r\n" +
		"Content-Length: 0\r\n"
	reqLine += "\r\n"
	if _, err := conn.Write([]byte(reqLine)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write upgrade: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read upgrade: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = resp.Body.Close()
		conn.Close()
		return nil, fmt.Errorf("expected 101, got %d", resp.StatusCode)
	}
	if up := strings.ToLower(resp.Header.Get("Upgrade")); up != "tcp-tunnel" {
		_ = resp.Body.Close()
		conn.Close()
		return nil, fmt.Errorf("expected Upgrade: tcp-tunnel, got %q", up)
	}
	_ = conn.SetDeadline(time.Time{})
	return &tunnelConn{Conn: conn, br: br}, nil
}
