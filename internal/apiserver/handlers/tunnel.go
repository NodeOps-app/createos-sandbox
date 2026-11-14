package handlers

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/ca/crl"
	"github.com/NodeOps-app/createos-sandbox/internal/utils"
)

// pkgHostDialTLS is the *tls.Config control uses when dialing hosts for
// HTTP-upgrade tunnels (shell, tunnel). nil = plain TCP (local dev only).
// Set at startup by SetHostDialTLS.
var pkgHostDialTLS *tls.Config

// SetHostDialTLS configures the TLS bundle control will use for outbound
// upgrade dials. When set, dialHostUpgrade wraps the TCP conn in tls.Client
// and presents the configured client cert.
func SetHostDialTLS(
	certPath, keyPath, caPath string,
	verifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error,
) error {
	if certPath == "" || keyPath == "" || caPath == "" {
		pkgHostDialTLS = nil
		return nil
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("load cert: %w", err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("read CA: %w", err)
	}
	pool, _ := x509.SystemCertPool()
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("CA %q has no PEM certs", caPath)
	}
	pkgHostDialTLS = &tls.Config{
		Certificates:          []tls.Certificate{cert},
		RootCAs:               pool,
		MinVersion:            tls.VersionTLS13,
		VerifyPeerCertificate: verifyPeerCertificate,
		// Resumed sessions skip VerifyPeerCertificate; this runs on both.
		VerifyConnection: crl.VerifyConnectionFunc(verifyPeerCertificate),
	}
	return nil
}

// tunnelConn pairs the raw net.Conn with the bufio.Reader used to parse
// the HTTP upgrade response, so any bytes buffered after the headers are
// still available to the caller.
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

// OpenTunnel opens a raw TCP tunnel to the host that owns sandboxID,
// targeting the given port inside the sandbox.
func (h *Handler) OpenTunnel(ctx context.Context, sandboxID string, port int) (net.Conn, error) {
	return h.OpenTunnelAs(ctx, sandboxID, port, utils.UserIDFromContext(ctx))
}

func (h *Handler) OpenTunnelAs(ctx context.Context, sandboxID string, port int, userID string) (net.Conn, error) {
	return h.dialHostUpgrade(ctx, sandboxID,
		fmt.Sprintf("/v1/internal/tunnel/%s/%d", sandboxID, port), userID)
}

// OpenShell opens a raw byte pipe to the agent's interactive-shell (PTY)
// listener on the host that owns sandboxID.
func (h *Handler) OpenShell(ctx context.Context, sandboxID string) (net.Conn, error) {
	return h.OpenShellAs(ctx, sandboxID, utils.UserIDFromContext(ctx))
}

func (h *Handler) OpenShellAs(ctx context.Context, sandboxID, userID string) (net.Conn, error) {
	return h.dialHostUpgrade(ctx, sandboxID, "/v1/internal/shell/"+sandboxID, userID)
}

// dialHostUpgrade dials the owning host's internal HTTP port, issues a
// POST + Upgrade request for the given path, and — upon a 101 Switching
// Protocols reply — returns the underlying net.Conn for the caller to
// splice. The caller owns the returned conn and must close it.
func (h *Handler) dialHostUpgrade(ctx context.Context, sandboxID, path, userID string) (net.Conn, error) {
	rec, err := h.repo.Get(ctx, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("lookup sandbox: %w", err)
	}
	if rec == nil {
		return nil, fmt.Errorf("sandbox %q not found", sandboxID)
	}
	hostID := ""
	if rec.HostID != nil {
		hostID = *rec.HostID
	}
	host, err := h.repo.GetHost(ctx, hostID)
	if err != nil {
		return nil, fmt.Errorf("lookup host: %w", err)
	}
	if host == nil {
		return nil, fmt.Errorf("host for sandbox %q unavailable", sandboxID)
	}

	addr := strings.TrimPrefix(strings.TrimPrefix(host.Addr, "http://"), "https://")

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	conn, err = dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial host %s: %w", addr, err)
	}
	// When host is mTLS-only, wrap the TCP conn in tls.Client before sending
	// the HTTP-upgrade request. SNI defaults to the host's address; certs
	// minted via the bootstrap CSR cover the host's IP / hostname / SPIFFE URI.
	if pkgHostDialTLS != nil {
		serverName := addr
		if i := strings.LastIndex(serverName, ":"); i >= 0 {
			serverName = serverName[:i]
		}
		tlsCfg := pkgHostDialTLS.Clone()
		tlsCfg.ServerName = serverName
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tls handshake to host %s: %w", addr, err)
		}
		conn = tlsConn
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	reqLine := "POST " + path + " HTTP/1.1\r\n" +
		"Host: " + addr + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: tcp-tunnel\r\n" +
		"Content-Length: 0\r\n"
	// End-user id propagates as a plain header inside the mTLS tunnel —
	// the connection itself is authenticated as "control" by the client cert.
	if userID != "" {
		reqLine += utils.HeaderUserID + ": " + userID + "\r\n"
	}
	reqLine += "\r\n"
	if _, err := conn.Write([]byte(reqLine)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write upgrade request: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read upgrade response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = resp.Body.Close()
		conn.Close()
		return nil, fmt.Errorf("expected 101 Switching Protocols, got %d %s", resp.StatusCode, resp.Status)
	}
	if up := strings.ToLower(resp.Header.Get("Upgrade")); up != "tcp-tunnel" {
		_ = resp.Body.Close()
		conn.Close()
		return nil, fmt.Errorf("expected Upgrade: tcp-tunnel, got %q", up)
	}
	// Clear the dial deadline — caller will manage IO timeouts.
	_ = conn.SetDeadline(time.Time{})

	return &tunnelConn{Conn: conn, br: br}, nil
}
