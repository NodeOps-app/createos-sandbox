package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"

	"github.com/NodeOps-app/createos-sandbox/internal/ca/crl"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/logging"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
)

// buildHostTLSConfig assembles a TLS 1.3 server config wired for required
// client-cert verification — the only auth gate on the host's internal RPCs.
//
// Server cert is loaded via GetCertificate with a 60s in-memory cache so
// the in-process Renewer (see internal/ca/renew) can rewrite tls.crt /
// tls.key on disk and have new handshakes pick up the rotated cert
// within a minute — no serve restart needed. The CA bundle stays
// pinned at startup because rotating the root means redistributing the
// trust anchor to every verifier (operator action, not auto).
//
// verify is the extra peer-cert callback — usually the CRL fetcher's
// VerifyPeerCertificate so revoked clients are rejected at handshake.
func buildHostTLSConfig(certPath, keyPath, caPath string, verify func([][]byte, [][]*x509.Certificate) error) (*tls.Config, error) {
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certs parsed from CA bundle %s", caPath)
	}

	reloader := &certReloader{certPath: certPath, keyPath: keyPath, refresh: 60 * time.Second}
	if _, err := reloader.load(); err != nil {
		return nil, fmt.Errorf("initial cert load: %w", err)
	}
	return &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return reloader.current()
		},
		ClientCAs:             pool,
		ClientAuth:            tls.RequireAndVerifyClientCert,
		MinVersion:            tls.VersionTLS13,
		VerifyPeerCertificate: verify,
		// Also runs on RESUMED handshakes, where VerifyPeerCertificate
		// is skipped — otherwise a revoked client cert keeps working
		// for the session-ticket lifetime.
		VerifyConnection: crl.VerifyConnectionFunc(verify),
	}, nil
}

// certReloader keeps the latest server keypair in memory and reloads
// from disk at most once per `refresh` interval. Concurrent calls to
// current() return the same cached cert when the file mtime hasn't
// changed since the last load.
type certReloader struct {
	certPath, keyPath string
	refresh           time.Duration

	mu        sync.RWMutex
	cur       *tls.Certificate
	loadedAt  time.Time
	loadedMod time.Time
}

func (r *certReloader) current() (*tls.Certificate, error) {
	r.mu.RLock()
	if r.cur != nil && time.Since(r.loadedAt) < r.refresh {
		c := r.cur
		r.mu.RUnlock()
		return c, nil
	}
	r.mu.RUnlock()
	return r.load()
}

func (r *certReloader) load() (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur != nil && time.Since(r.loadedAt) < r.refresh {
		return r.cur, nil
	}
	st, err := os.Stat(r.certPath)
	if err == nil && r.cur != nil && !st.ModTime().After(r.loadedMod) {
		// File unchanged since last load — just bump the freshness timer.
		r.loadedAt = time.Now()
		return r.cur, nil
	}
	c, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return nil, err
	}
	r.cur = &c
	r.loadedAt = time.Now()
	if err == nil && st != nil {
		r.loadedMod = st.ModTime()
	}
	return r.cur, nil
}

// suppliedSandboxIDKey is the context key control uses to pass a
// pre-generated sandbox id to the host (set in handleCreate from
// X-Sandbox-ID, read by the service layer). Internal — never exposed
// to user-supplied request bodies.
type suppliedSandboxIDKey struct{}

// SuppliedSandboxIDFromContext returns the id stashed by handleCreate, or
// "" if the request didn't carry the X-Sandbox-ID header.
func SuppliedSandboxIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(suppliedSandboxIDKey{}).(string); ok {
		return v
	}
	return ""
}

// Server is the HTTP API server for sandbox lifecycle management.
// It depends on the Service interface so handlers stay decoupled from
// the concrete VM manager implementation.
type Server struct {
	Svc  Service
	Addr string

	// TLS / mTLS. When all three paths are set, Run wraps the listener in
	// TLS 1.3 with required client-cert verification — the only authentication
	// gate on the host's internal RPCs after the JWT path was removed.
	TLSCertPath string
	TLSKeyPath  string
	TLSCAPath   string

	// VerifyPeerCertificate is an extra peer-cert callback installed on
	// the mTLS listener — typically the CRL fetcher's verifier. nil =
	// no extra check (only the standard chain validation runs).
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// cordoned mirrors the host's status from the durable record. Updated
	// out-of-band (typically by main_server.go's poll loop) and consulted
	// by handleCreate as a defense-in-depth check: even if the scheduler
	// erroneously picks a draining host, the host itself rejects creates.
	cordoned atomic.Bool

	// Computer screenshots are CPU-heavy and may each carry up to 32 MiB.
	// Bound them independently from lifecycle RPCs so one tenant cannot make
	// the shared host service buffer an unbounded number concurrently.
	computerOnce        sync.Once
	computerMu          sync.Mutex
	computerScreenshots map[string]struct{}
	computerSlots       chan struct{}

	fileMu        sync.Mutex
	fileTransfers map[string]int
	fileCount     int

	processMu       sync.Mutex
	processRequests map[string]int
	processCount    int
}

// SetCordoned updates the cordoned flag from the host's poll loop.
// Safe to call from any goroutine.
func (s *Server) SetCordoned(v bool) { s.cordoned.Store(v) }

// IsCordoned reports the cached cordoned state.
func (s *Server) IsCordoned() bool { return s.cordoned.Load() }

// Run starts the Fiber server and blocks until it shuts down, either via
// SIGINT/SIGTERM or cancellation of the passed context.
func (s *Server) Run(ctx context.Context) error {
	app := fiber.New(fiber.Config{
		AppName:               "createos",
		DisableStartupMessage: true,
		// Ownership IDs are retained in sandbox state and stream callbacks.
		// They must not alias request buffers recycled by fasthttp.
		Immutable: true,
		// Control retires its idle host connections after nine minutes. Keep
		// the server side open slightly longer so a burst never races a host-side
		// idle close and pays TCP+mTLS setup in the exec critical path.
		IdleTimeout: 10 * time.Minute,
		// Match control's 256 KiB JSON cap so larger file bodies stream.
		BodyLimit:         256 * 1024,
		StreamRequestBody: true,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			status := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				status = e.Code
			}
			// 4xx messages are user-actionable (e.g. fiber.NewError(400, "bad json")).
			// 5xx messages may carry internal detail — log + return generic.
			if status >= http.StatusInternalServerError {
				remoteAddr, peerIdentity := httpx.RequestPeer(c)
				log.WithContext(ctx).WithFields(log.Fields{
					"connection_id":   c.Context().ConnID(),
					"response_status": fiber.StatusInternalServerError,
					"status":          status,
					"method":          c.Method(),
					"path":            c.Path(),
					"request_id":      c.Locals("requestid"),
					"remote_addr":     remoteAddr,
					"mtls_peer":       peerIdentity,
				}).Errorf("[http-error] request failed: %v", err)

				return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
			}
			return httpx.Error(c, status, err.Error())
		},
	})

	logHostConnectionErrors(app)

	app.Use(recover.New())
	app.Use(requestid.New())
	app.Use(httpx.FiberRequestIDIntoContext)
	app.Use(httpx.EnforceStreamingBodyLimits(256*1024, 256*1024, proto.MaxFileUploadBytes))
	app.Use(httpx.LogServerErrors("host"))
	app.Use(logger.New(logger.Config{
		Format:     logging.AccessLogFormat(),
		CustomTags: logging.AccessLogCustomTags(),
		TimeFormat: "15:04:05.000",
		Next: func(c *fiber.Ctx) bool {
			return c.Path() == "/v1/internal/connection-warm"
		},
	}))

	// Health endpoints
	app.Get("/healthz", func(c *fiber.Ctx) error {
		return httpx.Success(c, proto.HealthzResp{Up: true})
	})
	app.Get("/readyz", func(c *fiber.Ctx) error {
		// TODO: real readiness checks (pool warm, snapshot built, etc).
		return httpx.Success(c, proto.ReadyzResp{Ready: true})
	})

	// Sandbox routes (v1) require a verified control-role mTLS peer.
	// Control forwards the authenticated end-user ID in a header; the
	// host's role gate stamps it into the request context for ownership checks.
	// Count and time every /v1/internal/* request, including auth failures.
	// Instrumentation wraps the auth gates and records the final status.
	app.Use("/v1/internal", InstrumentInternalRPC("host"))

	// mTLS-only gate for control→host calls. JWT path retired for internal.
	//
	// CRITICAL: do NOT pass mtlsControl as a `app.Group("/v1", mtlsControl)`
	// middleware. Fiber's Group registers the handlers via `app.Use(prefix,
	// handlers...)` which means the gate runs on EVERY route under /v1 —
	// including /v1/internal/tunnel/:id/:port (registered on `app` below)
	// whose own gate is broader (ingress/gateway/control). The result is
	// every ingress + gateway tunnel returning 403 "role not allowed".
	// Attach the gate per-route on the user-facing v1 routes instead so the
	// /v1/internal routes only run their own role gate.
	mtlsControl := s.HostMustBePeerRoleMTLS("control")
	v1 := app.Group("/v1")
	v1.Get("/rootfs", mtlsControl, s.handleListRootfs)
	v1.Post("/sandboxes", mtlsControl, s.handleCreate)
	v1.Put("/sandboxes/:id/egress", mtlsControl, s.handleSetEgress)
	v1.Delete("/sandboxes/:id", mtlsControl, s.handleDestroy)
	v1.Post("/sandboxes/:id/exec", mtlsControl, s.handleExec)
	v1.Post("/sandboxes/:id/checkpoints", mtlsControl, s.handleCheckpointProxy)
	v1.Get("/sandboxes/:id/checkpoints", mtlsControl, s.handleCheckpointProxy)
	v1.Delete("/sandboxes/:id/checkpoints/:"+proto.CheckpointIDParam, mtlsControl, s.handleCheckpointProxy)
	v1.Post("/sandboxes/:id/checkpoints/:"+proto.CheckpointIDParam+"/restore", mtlsControl, s.handleCheckpointProxy)
	v1.Post("/sandboxes/:id/processes", mtlsControl, s.handleProcessProxy)
	v1.Get("/sandboxes/:id/processes", mtlsControl, s.handleProcessProxy)
	v1.Get("/sandboxes/:id/processes/:process", mtlsControl, s.handleProcessProxy)
	v1.Get("/sandboxes/:id/processes/:process/connect", mtlsControl, s.handleProcessConnect)
	v1.Post("/sandboxes/:id/processes/:process/input", mtlsControl, s.handleProcessProxy)
	v1.Post("/sandboxes/:id/processes/:process/stdin/close", mtlsControl, s.handleProcessProxy)
	v1.Post("/sandboxes/:id/processes/:process/resize", mtlsControl, s.handleProcessProxy)
	v1.Post("/sandboxes/:id/processes/:process/signal", mtlsControl, s.handleProcessProxy)
	v1.Get("/sandboxes/:id/processes/:process/wait", mtlsControl, s.handleProcessProxy)
	v1.Delete("/sandboxes/:id/processes/:process", mtlsControl, s.handleProcessProxy)
	for _, path := range []string{"screenshot", "screen", "cursor", "windows", "windows/current"} {
		v1.Get("/sandboxes/:id/computer/"+path, mtlsControl, s.handleComputerProxy)
	}
	v1.Get("/sandboxes/:id/computer/windows/:window", mtlsControl, s.handleComputerProxy)
	v1.Delete("/sandboxes/:id/computer/windows/:window", mtlsControl, s.handleComputerProxy)
	v1.Post("/sandboxes/:id/computer/windows/:window/focus", mtlsControl, s.handleComputerProxy)
	v1.Get("/sandboxes/:id/computer/windows/:window/geometry", mtlsControl, s.handleComputerProxy)
	for _, action := range []string{"move", "resize", "maximize", "minimize", "restore"} {
		v1.Post("/sandboxes/:id/computer/windows/:window/"+action, mtlsControl, s.handleComputerProxy)
	}
	v1.Get("/sandboxes/:id/computer/screens", mtlsControl, s.handleComputerProxy)
	v1.Post("/sandboxes/:id/computer/screens", mtlsControl, s.handleComputerProxy)
	v1.Get("/sandboxes/:id/computer/screens/:screen", mtlsControl, s.handleComputerProxy)
	v1.Get("/sandboxes/:id/computer/screens/:screen/connect", mtlsControl, s.handleComputerProxy)
	v1.Post("/sandboxes/:id/computer/screens/:screen/resize", mtlsControl, s.handleComputerProxy)
	v1.Delete("/sandboxes/:id/computer/screens/:screen", mtlsControl, s.handleComputerProxy)
	for _, path := range []string{
		"mouse/move", "mouse/click", "mouse/scroll", "mouse/drag", "mouse/down", "mouse/up",
		"keyboard/type", "keyboard/press", "keyboard/down", "keyboard/up", "open", "launch",
	} {
		v1.Post("/sandboxes/:id/computer/"+path, mtlsControl, s.handleComputerProxy)
	}
	v1.Get("/sandboxes/:id/computer/clipboard", mtlsControl, s.handleComputerProxy)
	v1.Put("/sandboxes/:id/computer/clipboard", mtlsControl, s.handleComputerProxy)
	v1.Put("/sandboxes/:id/files", mtlsControl, s.handleFileUpload)
	v1.Get("/sandboxes/:id/files", mtlsControl, s.handleFileDownload)
	v1.Get("/sandboxes/:id/metrics", mtlsControl, s.handleSandboxMetrics)
	v1.Get("/sandboxes/:id/metrics/timeseries", mtlsControl, s.handleSandboxMetricsTimeseries)
	v1.Post("/sandboxes/:id/bandwidth/recharge", mtlsControl, s.handleRecharge)
	v1.Post("/sandboxes/:id/pause", mtlsControl, s.handlePause)
	v1.Post("/sandboxes/:id/resume", mtlsControl, s.handleResume)
	v1.Post("/sandboxes/:id/disks", mtlsControl, s.handleDiskAttach)
	v1.Delete("/sandboxes/:id/disks/:disk", mtlsControl, s.handleDiskDetach)

	// Internal RPCs — mTLS-only after the JWT removal.
	app.Post("/v1/internal/tunnel/:id/:port", s.HostMustBePeerRoleMTLS("ingress", "gateway", "control"), s.handleTunnel)
	app.Post("/v1/internal/shell/:id", s.HostMustBePeerRoleMTLS("control"), s.handleShell)
	// Hold concurrent warmer calls long enough that net/http must occupy one
	// HTTP/1.1 socket per request. This keeps the full control-to-host idle pool
	// alive; an immediate /healthz response can be served serially by only a few
	// sockets even when the caller launches twenty goroutines.
	app.Get("/v1/internal/connection-warm", s.HostMustBePeerRoleMTLS("control"), func(c *fiber.Ctx) error {
		time.Sleep(25 * time.Millisecond)
		return httpx.Success(c, proto.HealthzResp{Up: true})
	})
	app.Delete("/v1/internal/sandboxes/:id", s.HostMustBePeerRoleMTLS("control"), s.handleInternalDestroy)
	app.Post("/v1/internal/sandboxes/:id/resume", s.HostMustBePeerRoleMTLS("control"), s.handleResume)
	app.Post("/v1/internal/net-reconcile-kick", s.HostMustBePeerRoleMTLS("control"), s.handleNetReconcileKick)
	app.Post("/v1/internal/sandboxes/:id/pool-claim-kick", s.HostMustBePeerRoleMTLS("control"), s.handlePoolClaimKick)

	mtlsActive := s.TLSCertPath != "" && s.TLSKeyPath != "" && s.TLSCAPath != ""
	log.WithContext(ctx).Infof("[server] listening on %s (mtls=%v)", s.Addr, mtlsActive)

	// Graceful shutdown: trigger on SIGINT/SIGTERM OR parent ctx cancel.
	shutdownErr := make(chan error, 1)
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-sigCh:
			log.WithContext(ctx).Info("[server] shutdown signal received")
		case <-ctx.Done():
			log.WithContext(ctx).Info("[server] context cancelled, shutting down")
		}
		sdCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shutdownErr <- app.ShutdownWithContext(sdCtx)
	}()

	if mtlsActive {
		tlsCfg, err := buildHostTLSConfig(s.TLSCertPath, s.TLSKeyPath, s.TLSCAPath, s.VerifyPeerCertificate)
		if err != nil {
			return fmt.Errorf("build mTLS config: %w", err)
		}
		rawLn, err := net.Listen("tcp", s.Addr)
		if err != nil {
			return err
		}
		tlsLn := tls.NewListener(rawLn, tlsCfg)
		log.WithContext(ctx).Infof("[host] mTLS listener enabled cert=%s", s.TLSCertPath)
		if err := app.Listener(tlsLn); err != nil {
			return err
		}
	} else {
		if err := app.Listen(s.Addr); err != nil {
			return err
		}
	}
	if err := <-shutdownErr; err != nil {
		return err
	}
	return nil
}

// Fiber replaces transport errors with generic HTTP errors. Capture diagnostics
// before that conversion; an unread request can otherwise look like GET /.
func logHostConnectionErrors(app *fiber.App) {
	server := app.Server()
	previous := server.ErrorHandler
	server.ErrorHandler = func(c *fasthttp.RequestCtx, err error) {
		fields := log.Fields{
			"component": "host", "phase": "receive_request",
			"remote_addr": c.RemoteAddr().String(), "local_addr": c.LocalAddr().String(),
			"connection_id": c.ConnID(), "connection_request": c.ConnRequestNum(),
			"error_type":               fmt.Sprintf("%T", err),
			"request_headers_received": len(c.Request.Header.RawHeaders()) != 0,
		}
		// Do not log err.Error(): parser errors can contain raw request bytes,
		// including credentials. Types and known OS errors retain the cause safely.
		var netErr net.Error
		if errors.As(err, &netErr) {
			fields["timeout"] = netErr.Timeout()
		}
		var opErr *net.OpError
		if errors.As(err, &opErr) {
			fields["network_operation"] = opErr.Op
			fields["network_error_type"] = fmt.Sprintf("%T", opErr.Err)
		}
		var errno syscall.Errno
		if errors.As(err, &errno) {
			fields["os_error"] = errno.Error()
		}
		fields["eof"] = errors.Is(err, io.EOF)
		fields["unexpected_eof"] = errors.Is(err, io.ErrUnexpectedEOF)
		if state := c.TLSConnectionState(); state != nil {
			fields["tls_handshake_complete"] = state.HandshakeComplete
			fields["tls_version"] = state.Version
			fields["tls_peer_verified"] = len(state.VerifiedChains) != 0
		}
		log.WithFields(fields).Warn("[http-connection-error] receiving request failed")
		previous(c, err)
	}
}
