package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTunnelRejectsRevokedHostCertificate(t *testing.T) {
	for _, customHTTP := range []bool{false, true} {
		t.Run(fmt.Sprintf("custom_http=%t", customHTTP), func(t *testing.T) {
			var revoked atomic.Bool
			var serial string
			control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/internal/crl" {
					http.NotFound(w, r)
					return
				}
				if revoked.Load() {
					fmt.Fprintf(w, `{"revoked":[{"serial":%q}]}`, serial)
				} else {
					io.WriteString(w, `{"revoked":[]}`)
				}
			}))
			defer control.Close()
			host := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, buf, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp-tunnel\r\n\r\npong")
				buf.Flush()
			}))
			host.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert}
			host.StartTLS()
			defer host.Close()
			cert := host.TLS.Certificates[0]
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			serial = hex.EncodeToString(leaf.SerialNumber.Bytes())
			key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := Config{ControlURL: control.URL, TLSCertPath: certPath, TLSKeyPath: keyPath, TLSCAPath: certPath}
			if customHTTP {
				cfg.HTTP = &http.Client{Timeout: time.Second}
			}
			g := New(cfg)
			if g.crlFetcher == nil || g.outboundTLS == nil || g.outboundTLS.VerifyConnection == nil {
				t.Fatal("tunnel revocation checker missing")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := g.crlFetcher.Refresh(ctx); err != nil {
				t.Fatal(err)
			}
			g.outboundTLS.ClientSessionCache = tls.NewLRUClientSessionCache(1)
			verify := g.outboundTLS.VerifyConnection
			resumed := false
			g.outboundTLS.VerifyConnection = func(cs tls.ConnectionState) error { resumed = cs.DidResume; return verify(cs) }
			for i := 0; i < 2; i++ {
				conn, err := g.openTunnel(ctx, host.URL, "sb-test", 8080)
				if err != nil {
					t.Fatalf("valid tunnel: %v", err)
				}
				body := make([]byte, 4)
				_, err = io.ReadFull(conn, body)
				conn.Close()
				if err != nil || string(body) != "pong" {
					t.Fatalf("tunnel data=%q err=%v", body, err)
				}
			}
			if !resumed {
				t.Fatal("second TLS connection did not resume")
			}
			revoked.Store(true)
			if err := g.crlFetcher.Refresh(ctx); err != nil {
				t.Fatal(err)
			}
			conn, err := g.openTunnel(ctx, host.URL, "sb-test", 8080)
			if conn != nil {
				conn.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "revoked cert") {
				t.Fatalf("revoked resumed tunnel: %v", err)
			}
			if !resumed {
				t.Fatal("revocation was not exercised on a resumed TLS session")
			}
			g.outboundTLS.ClientSessionCache = nil
			conn, err = g.openTunnel(ctx, host.URL, "sb-test", 8080)
			if conn != nil {
				conn.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "revoked cert") {
				t.Fatalf("revoked full handshake: %v", err)
			}
			g.crlFetcher.HTTPClient.CloseIdleConnections()
			g.cfg.HTTP.CloseIdleConnections()
		})
	}
}
