package scheduler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"

	"github.com/NodeOps-app/sandbox/internal/httpx"
	schedapi "github.com/NodeOps-app/sandbox/internal/scheduler/api"
	"github.com/NodeOps-app/sandbox/internal/scheduler/framework"
	"github.com/NodeOps-app/sandbox/internal/scheduler/plugins"
	"github.com/NodeOps-app/sandbox/models"
)

// ServerConfig holds the HTTP-level config. Reservation TTL is owned by
// the Instance (so the sweeper and the published ExpiresAtMs can't drift);
// don't duplicate it here.
type ServerConfig struct {
	Addr          string
	ShutdownGrace time.Duration // default 10s

	// TLS server config — listener wraps in TLS 1.3 + RequireAndVerifyClientCert
	// when all three paths are set; empty paths leave it plain (dev only).
	TLSCertPath string
	TLSKeyPath  string
	TLSCAPath   string
}

// HTTPServer is the Fiber app that exposes the scheduler over HTTP.
type HTTPServer struct {
	cfg      ServerConfig
	instance *Instance
	logger   *slog.Logger
}

// NewHTTPServer wires an Instance into a Fiber app.
func NewHTTPServer(inst *Instance, cfg ServerConfig) *HTTPServer {
	if cfg.ShutdownGrace == 0 {
		cfg.ShutdownGrace = 10 * time.Second
	}
	return &HTTPServer{cfg: cfg, instance: inst, logger: inst.logger}
}

// Run starts the Fiber app and blocks until ctx is cancelled. Returns the
// shutdown error if any.
func (s *HTTPServer) Run(ctx context.Context) error {
	app := fiber.New(fiber.Config{
		AppName:               "createos-scheduler",
		DisableStartupMessage: true,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			status := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				status = e.Code
			}
			// 4xx messages are user-actionable (e.g. fiber.NewError(400, "bad json")).
			// 5xx messages may carry internal detail — log + return generic.
			if status >= http.StatusInternalServerError {
				log.WithContext(ctx).WithFields(log.Fields{
					"status":     status,
					"method":     c.Method(),
					"path":       c.Path(),
					"request_id": c.Locals("requestid"),
				}).Errorf("[http-error] request failed: %v", err)

				return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
			}
			return httpx.Error(c, status, err.Error())
		},
	})
	app.Use(recover.New())
	app.Use(requestid.New())
	app.Use(httpx.FiberRequestIDIntoContext)

	app.Get("/healthz", s.handleHealthz)
	app.Get("/readyz", s.handleReadyz)

	v1 := app.Group("/v1")
	// Scheduler is not exposed outside the cluster — the k8s Service
	// is ClusterIP-only and the listener binds inside the createos
	// namespace. Inbound auth is intentionally absent: every caller
	// inside the mesh is trusted to submit placement requests. If you
	// ever expose this port externally, restore an auth gate here
	// (mTLS-role=control matches the rest of the system; see
	// internal/apiserver/routes/main.go for the pattern).
	v1.Post("/schedule", s.handleSchedule)
	// /v1/capacity — read-only per-host commit-vs-limit snapshot for
	// all 4 admission dimensions. Behind the same MustBeControl gate
	// as /schedule because the data is operationally sensitive (host
	// utilization can be used to time attacks at peak load). Operators
	// reach it via `kubectl exec deploy/createos-control -- curl
	// http://createos-scheduler:9100/v1/capacity -H 'Authorization:
	// Bearer <internal-jwt>'` or via a future control-plane proxy.
	v1.Get("/capacity", s.handleCapacity)
	// Note: there is no /release endpoint, by design. The scheduler learns
	// about completed/failed/destroyed sandboxes via the 1s hydrate tick
	// reading the durable sandboxes table. No ack, no callback, no
	// coordination — host crashes, control crashes, and lost messages
	// all converge correctly within the hydrate interval.

	tlsActive := s.cfg.TLSCertPath != "" && s.cfg.TLSKeyPath != "" && s.cfg.TLSCAPath != ""
	s.logger.Info("listening",
		slog.String("addr", s.cfg.Addr),
		slog.Bool("mtls_active", tlsActive))

	shutdownErr := make(chan error, 1)
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-sigCh:
		case <-ctx.Done():
		}
		sdCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownGrace)
		defer cancel()
		shutdownErr <- app.ShutdownWithContext(sdCtx)
	}()

	if tlsActive {
		tlsCfg, err := buildSchedulerTLSConfig(s.cfg.TLSCertPath, s.cfg.TLSKeyPath, s.cfg.TLSCAPath)
		if err != nil {
			return fmt.Errorf("build tls config: %w", err)
		}
		rawLn, err := net.Listen("tcp", s.cfg.Addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", s.cfg.Addr, err)
		}
		tlsLn := tls.NewListener(rawLn, tlsCfg)
		log.WithContext(ctx).Infof("[scheduler] mTLS listener enabled cert=%s", s.cfg.TLSCertPath)
		if err := app.Listener(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return <-shutdownErr
	}

	if err := app.Listen(s.cfg.Addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return <-shutdownErr
}

// buildSchedulerTLSConfig assembles a TLS 1.3 config with required
// client-cert verification — the mTLS gate on internal RPCs.
func buildSchedulerTLSConfig(certPath, keyPath, caPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("ca bundle contained no usable certificates")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ─── handlers ──────────────────────────────────────────────────────────────

func (s *HTTPServer) handleHealthz(c *fiber.Ctx) error {
	return httpx.Success(c, schedapi.HealthzResponse{Up: true})
}

// handleCapacity returns the operator-visible per-host capacity snapshot.
// Read-only: serves the scheduler's current hostCache view. Numbers
// reflect live SUMs as of the last hydrate (≤ ReservationGracePeriod
// stale); pending reservations are NOT included.
func (s *HTTPServer) handleCapacity(c *fiber.Ctx) error {
	hosts := s.instance.HostsSnapshot()
	resp := schedapi.CapacityResponse{Hosts: make([]schedapi.HostCapacity, 0, len(hosts))}
	for _, h := range hosts {
		resp.Hosts = append(resp.Hosts, schedapi.HostCapacity{
			ID: h.ID, Addr: h.Addr, Status: h.Status, Region: h.Region,
			CPU:  dimUsage(int64(h.VCPUInUse), int64(h.CPUCount), h.CPUOvercommitX10, plugins.DefaultCPUOvercommitX10),
			Mem:  dimUsage(int64(h.InUseMib), int64(h.MemCapacityMib), h.MemOvercommitX10, plugins.DefaultMemOvercommitX10),
			Disk: diskDimUsage(h),
			IPs:  dimUsage(int64(h.VMCount), int64(h.MaxVMs), 10, 10),
		})
	}
	return httpx.Success(c, resp)
}

func diskDimUsage(h models.Host) schedapi.DimensionUsage {
	factor := h.DiskOvercommitX10
	if factor <= 0 {
		factor = plugins.DefaultDiskOvercommitX10
	}
	limit := plugins.DiskCommitLimitMiB(&h)
	util := 0.0
	if limit > 0 {
		util = float64(h.DiskInUseMib) / float64(limit)
	}
	return schedapi.DimensionUsage{
		Committed: h.DiskInUseMib,
		Physical:  h.DiskTotalMib,
		Limit:     limit,
		Util:      util,
		OverX10:   factor,
	}
}

// dimUsage builds one DimensionUsage row. factor=0 falls back to dflt.
func dimUsage(committed, physical int64, factor, dflt int) schedapi.DimensionUsage {
	if factor <= 0 {
		factor = dflt
	}
	limit := physical * int64(factor) / 10
	util := 0.0
	if limit > 0 {
		util = float64(committed) / float64(limit)
	}
	return schedapi.DimensionUsage{
		Committed: committed,
		Physical:  physical,
		Limit:     limit,
		Util:      util,
		OverX10:   factor,
	}
}

func (s *HTTPServer) handleReadyz(c *fiber.Ctx) error {
	state := s.instance.State()
	resp := schedapi.ReadyzResponse{
		State:    state.String(),
		Epoch:    s.instance.Epoch(),
		Leader:   s.instance.LeaderID(),
		UptimeMs: s.instance.UptimeMs(),
	}
	if state == StateLeaderActive {
		resp.Ready = true
		return httpx.Success(c, resp)
	}
	resp.Reason = "not in leader_active state"
	return httpx.Fail(c, fiber.StatusServiceUnavailable, resp)
}

func (s *HTTPServer) handleSchedule(c *fiber.Ctx) error {
	started := time.Now()
	parseStarted := time.Now()
	var req schedapi.ScheduleRequest
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, schedapi.ErrorResponse{Error: "invalid json body", Code: fiber.StatusBadRequest})
	}
	if req.SandboxID == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, schedapi.ErrorResponse{Error: "sandbox_id is required", Code: fiber.StatusBadRequest})
	}
	if req.MemMiB <= 0 {
		return httpx.Fail(c, fiber.StatusBadRequest, schedapi.ErrorResponse{Error: "mem_mib is required", Code: fiber.StatusBadRequest})
	}
	parseDur := time.Since(parseStarted)
	scheduleStarted := time.Now()
	d, h, err := s.instance.Schedule(c.UserContext(), req.SandboxID, &framework.Request{
		Shape:            req.Shape,
		Rootfs:           req.Rootfs,
		MemMiB:           req.MemMiB,
		VCPU:             req.VCPU,
		DiskMiB:          req.DiskMiB,
		HostID:           req.HostID,
		Region:           req.Region,
		Labels:           req.Labels,
		PreferredHostIDs: req.PreferredHostIDs,
		CachedHostID:     req.CachedHostID,
		ExcludeHosts:     req.ExcludeHosts,
		SourceCPUVendor:  req.SourceCPUVendor,
	})
	scheduleDur := time.Since(scheduleStarted)
	defer func() {
		hostID := ""
		if d != nil {
			hostID = d.HostID
		}
		log.WithContext(c.UserContext()).Infof("[scheduler-trace] rid=%s sb=%s parse=%.2fms schedule=%.2fms total=%.2fms host=%s status=%d",
			httpx.RequestID(c.UserContext()), req.SandboxID,
			float64(parseDur.Microseconds())/1000, float64(scheduleDur.Microseconds())/1000,
			float64(time.Since(started).Microseconds())/1000, hostID, c.Response().StatusCode())
	}()
	if errors.Is(err, ErrNotReady) {
		log.WithContext(c.UserContext()).Errorf("[handler] service unavailable: %v", err)

		return httpx.Error(c, fiber.StatusServiceUnavailable, "service unavailable")
	}
	if errors.Is(err, ErrInvalidRegion) || errors.Is(err, ErrRegionDisabled) {
		return httpx.Fail(c, fiber.StatusBadRequest, schedapi.ErrorResponse{Error: err.Error(), Code: fiber.StatusBadRequest})
	}
	if errors.Is(err, framework.ErrNoCapacity) {
		return httpx.Fail(c, fiber.StatusServiceUnavailable, schedapi.ErrorResponse{Error: err.Error(), Code: fiber.StatusServiceUnavailable, Reason: schedapi.ReasonNoCapacity})
	}
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	resp := schedapi.ScheduleResponse{
		HostID: d.HostID,
		Epoch:  s.instance.Epoch(),
	}
	if h != nil {
		resp.HostAddr = h.Addr
	}
	return httpx.Success(c, resp)
}
