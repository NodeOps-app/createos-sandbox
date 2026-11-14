package api

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"

	"github.com/NodeOps-app/createos-sandbox/internal/hosts/metrics"
	"github.com/NodeOps-app/createos-sandbox/internal/httpx"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/internal/requestctx"
	"github.com/NodeOps-app/createos-sandbox/internal/trace"
	"github.com/NodeOps-app/createos-sandbox/internal/utils"
	"github.com/NodeOps-app/createos-sandbox/models"
)

func (s *Server) handleCreate(c *fiber.Ctx) error {
	t := trace.Start("api.create").WithObserver(func(name string, d time.Duration) {
		metrics.HostCreatePhaseSeconds.WithLabelValues(name).Observe(d.Seconds())
	})
	t.Attr("rid", httpx.RequestID(c.UserContext()))
	defer t.End()

	// Defense-in-depth: the scheduler is supposed to skip cordoned hosts,
	// but if a stale cache or misrouted request lands here, refuse it
	// so a draining host never accepts new VMs.
	if s.IsCordoned() {
		return httpx.Error(c, fiber.StatusServiceUnavailable, "host is cordoned (draining)")
	}

	stopParse := t.Phase("parse")
	var req CreateReq
	if err := c.BodyParser(&req); err != nil {
		stopParse()
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	stopParse()

	// X-Sandbox-ID is set by the control plane after it has reserved
	// capacity at the scheduler. The manager uses this id verbatim so the
	// durable row, scheduler delta, and live VM all key on the same value.
	//
	// IMPORTANT: c.Get returns an unsafe view into Fiber's pooled fasthttp
	// header buffer that gets overwritten on the next request. We must
	// strings.Clone the value before persisting it anywhere — context,
	// map keys, struct fields — or two concurrent creates will collide
	// (the second request mutates the bytes the first request handed off).
	ctx := c.UserContext()
	if raw := c.Get(proto.HeaderSandboxID); raw != "" {
		id := strings.Clone(raw)
		ctx = context.WithValue(ctx, suppliedSandboxIDKey{}, id)
		ctx = requestctx.WithSandboxID(ctx, id)
		c.Locals("sandbox_id", id)
		c.SetUserContext(ctx)
	}

	stopSvc := t.Phase("svc")
	resp, err := s.Svc.Create(ctx, utils.UserID(c), req)
	stopSvc()
	if err != nil {
		if errors.Is(err, ErrInvalidRequest) {
			return httpx.Fail(c, fiber.StatusBadRequest, err.Error())
		}
		if errors.Is(err, ErrAtCapacity) {
			log.WithContext(c.UserContext()).Errorf("[handler] service unavailable: %v", err)

			return httpx.Error(c, fiber.StatusServiceUnavailable, "service unavailable")
		}
		if errors.Is(err, ErrInfrastructure) {
			log.WithContext(c.UserContext()).Errorf("[handler] infrastructure unavailable: %v", err)

			return httpx.Error(c, fiber.StatusServiceUnavailable, "service unavailable")
		}
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}

	stopResp := t.Phase("resp")
	err = httpx.Success(c, resp)
	stopResp()
	return err
}

func (s *Server) handleExec(c *fiber.Ctx) error {
	id := c.Params("id")

	var req proto.ExecRequest
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if req.Cmd == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "required")
	}

	// Streaming branch: the client opted in via ?stream=true (or by
	// sending stream:true in the body). Wire format is NDJSON over
	// HTTP/1.1 chunked transfer; we hand the response writer to the
	// service which copies the agent's events through, flushing per
	// line. Disconnect at any layer kills the cmd via the chained
	// conn closes (host→agent and client→host).
	if req.Stream || c.QueryBool("stream") {
		return s.handleExecStream(c, id, req)
	}

	ctx, stop := requestctx.WithDisconnect(c.UserContext(), c.Context().Conn())
	defer stop()
	c.SetUserContext(ctx)
	resp, err := s.Svc.Exec(ctx, id, utils.UserID(c), req)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		}
		if errors.Is(err, ErrInvalidRequest) {
			return httpx.Fail(c, fiber.StatusBadRequest, err.Error())
		}
		fingerprintInput, _ := json.Marshal(struct {
			Cmd  string   `json:"cmd"`
			Args []string `json:"args"`
		}{Cmd: req.Cmd, Args: req.Args})
		fingerprint := sha256.Sum256(fingerprintInput)
		_, liveErr := s.Svc.Get(c.UserContext(), id, utils.UserID(c))
		stillLive := liveErr == nil
		log.WithContext(c.UserContext()).WithFields(log.Fields{
			"sandbox_id":       id,
			"request_id":       c.Locals("requestid"),
			"command":          filepath.Base(req.Cmd),
			"argument_count":   len(req.Args),
			"environment_keys": len(req.Env),
			"stdin_bytes":      len(req.Stdin),
			"stream":           false,
			"command_sha256":   fmt.Sprintf("%x", fingerprint[:]),
			"sandbox_live":     stillLive,
			"error_type":       classifyExecError(err),
		}).Errorf("[exec-5xx] request failed: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, resp)
}

func classifyExecError(err error) string {
	if errors.Is(err, context.Canceled) {
		return "client_cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline_exceeded"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "dial agent"):
		return "agent_dial"
	case strings.Contains(msg, "write:"):
		return "agent_write"
	case strings.Contains(msg, "read:") && strings.Contains(msg, "timed out"):
		return "agent_read_timeout"
	case strings.Contains(msg, "read:"):
		return "agent_read"
	default:
		return "exec_internal"
	}
}

// handleExecStream is the streaming variant of handleExec. It uses
// fasthttp's SetBodyStreamWriter so the response body becomes a
// chunked NDJSON stream — one ExecStreamEvent per line.
//
// Key gotcha: fasthttp recycles the *fiber.Ctx as soon as the handler
// returns, even though SetBodyStreamWriter's callback runs *after* the
// return. So we MUST snapshot every value we need (ctx, id, req) into
// local variables before SetBodyStreamWriter — touching `c` from inside
// the callback panics.
func (s *Server) handleExecStream(c *fiber.Ctx, id string, req proto.ExecRequest) error {
	// Pre-flight: confirm the sandbox exists before committing to a
	// chunked response. After SetBodyStreamWriter we can't change the
	// status code anymore.
	parentCtx := c.UserContext()
	if _, err := s.Svc.Get(parentCtx, id, utils.UserID(c)); err != nil {
		if errors.Is(err, ErrNotFound) {
			return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		}
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}

	c.Set(fiber.HeaderContentType, "application/x-ndjson")
	c.Set(fiber.HeaderCacheControl, "no-cache")
	c.Set("X-Accel-Buffering", "no")
	c.Status(fiber.StatusOK)

	// Snapshot — the callback fires on a separate goroutine that may
	// outlive the request handler. Anything captured from `c` directly
	// is a panic waiting to happen.
	capID := strings.Clone(id)
	capReq := req
	svc := s.Svc
	// Capture the authenticated user_id NOW (from c.Locals stamped by
	// the mTLS role middleware) so we can re-stamp it onto the detached
	// context below. Without this, the StreamWriter's
	// context.Background() carries no uid → svc.ExecStream's
	// loadOwned → requireOwner sees an empty caller and returns
	// ErrNotFound, surfacing to the client as the misleading
	// "sandbox not found" NDJSON error. The buffered Exec path
	// inherits c.UserContext() and never hit this.
	capUserID := strings.Clone(utils.UserID(c))

	// Detach from cancellation here: parentCtx is tied to the inbound
	// request and gets cancelled the moment Fiber recycles c. Long-running
	// streaming would die immediately. Observe the client socket separately
	// so silent streams cancel without waiting for broken-pipe writes.
	// WithoutCancel keeps the request id for log correlation.
	detached := context.WithoutCancel(c.UserContext())
	clientConn := c.Context().Conn()
	c.Response().SetBodyStreamWriter(fasthttp.StreamWriter(func(w *bufio.Writer) {
		ctx, cancel := requestctx.WithDisconnect(utils.WithUserID(detached, capUserID), clientConn)
		defer cancel()
		flush := func() { _ = w.Flush() }
		if err := svc.ExecStream(ctx, capID, capUserID, capReq, w, flush); err != nil {
			exit := -1
			ev := proto.ExecStreamEvent{Error: err.Error(), ExitCode: &exit}
			if data, mErr := json.Marshal(ev); mErr == nil {
				_, _ = w.Write(append(data, '\n'))
				_ = w.Flush()
			}
		}
	}))
	return nil
}

func (s *Server) handleSetEgress(c *fiber.Ctx) error {
	id := c.Params("id")
	var req SetEgressReq
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	view, err := s.Svc.SetEgress(c.UserContext(), id, utils.UserID(c), req.Egress)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		}
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.EgressView{ID: view.ID, Egress: view.Egress})
}

// handleTunnel proxies raw TCP between the control plane (HTTP-Upgrade caller)
// and <sandbox.IP>:<port>. The request is hijacked after a 101 Switching
// Protocols response; then two io.Copy goroutines splice the two sockets
// until either side closes.
//
// Protocol contract:
//
//	POST /v1/internal/tunnel/:id/:port
//	  → 101 Switching Protocols
//	    Connection: Upgrade
//	    Upgrade: tcp-tunnel
//	  After the status line + headers, the connection carries raw bytes
//	  bidirectionally until EOF on either side.
func (s *Server) handleTunnel(c *fiber.Ctx) error {
	id := c.Params("id")
	portStr := c.Params("port")
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid")
	}
	// Agent ports are infrastructure-only. Reject them before sandbox lookup
	// or connection hijack so public ingress and user tunnels cannot use the
	// host-injected VM token to reach guest control services. The guest tunnel
	// enforces the same range as defense in depth.
	if port >= 1023 && port <= 1029 {
		return httpx.Fail(c, fiber.StatusForbidden, "port is not available")
	}

	// Need the sandbox's IP to dial. Use the unscoped LookupIP — this
	// handler is gated by mTLS role={ingress,gateway,control} and those
	// callers don't carry an end-user id, so Svc.Get's owner check would
	// always 404. Authorisation for "may this caller open a tunnel into
	// this sandbox?" already happened upstream (ingress validates the
	// public ULID + ingress_enabled, gateway validates ssh_pubkeys,
	// control's HandleUserTunnel checks ownerOK for the createos-cli tunnel path).
	vmIP, err := s.Svc.LookupIP(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		}
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}

	// Pull the per-VM shared secret so we can inject "AUTH <token>\n"
	// on the inner dial. The outer caller (browser via ingress, ssh
	// client via gateway, createos-cli tunnel) never sees the token.
	token, err := s.Svc.SecretToken(c.UserContext(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		}
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}

	// Dial the agent's tunnel port (1026) rather than VM_IP:port directly.
	// The agent, running inside the VM's netns, dials 127.0.0.1:port on our
	// behalf — which makes loopback-bound services reachable. Old-style
	// direct dial can't reach 127.0.0.1 binds because packets arrive on
	// eth0 and the kernel filters loopback sockets by arrival interface.
	agentTarget := fmt.Sprintf("%s:1026", vmIP)
	directTarget := fmt.Sprintf("%s:%d", vmIP, port)

	// Hijack the connection. Fiber exposes the underlying *fasthttp.RequestCtx
	// via c.Context(); use its Hijack method. The callback runs AFTER the
	// response headers written below have been flushed.
	logCtx := c.UserContext()
	c.Context().Hijack(func(netConn net.Conn) {
		defer netConn.Close()
		upstream, via, derr := dialTunnelUpstream(agentTarget, directTarget, port, token)
		if derr != nil {
			log.WithContext(logCtx).Warnf("[tunnel] dial %s (via=%s) failed: %v", directTarget, via, derr)
			return
		}
		defer upstream.Close()
		log.WithContext(logCtx).Infof("[tunnel] sb=%s %s <-> remote (via=%s)", id, directTarget, via)

		// Splice: two goroutines, io.Copy each direction.
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(upstream, netConn); done <- struct{}{} }()
		go func() { _, _ = io.Copy(netConn, upstream); done <- struct{}{} }()
		<-done
	})

	// Return 101 Switching Protocols BEFORE hijack actually takes effect.
	// fasthttp sends the status code + headers before calling the hijack
	// callback.
	c.Status(fiber.StatusSwitchingProtocols)
	c.Set("Connection", "Upgrade")
	c.Set("Upgrade", "tcp-tunnel")
	return nil
}

// handleShell proxies raw bytes between the control plane (HTTP-Upgrade
// caller) and the agent's PTY listener (:1027). Same hijack/splice shape
// as handleTunnel, but the agent side gets only the "AUTH <token>\n"
// line — the PTY listener reads framed shell traffic after that, no port
// header. The interactive-shell framing (data/resize) is end-to-end
// between createos-cli and the agent; the host just splices bytes.
func (s *Server) handleShell(c *fiber.Ctx) error {
	id := c.Params("id")

	view, err := s.Svc.Get(c.UserContext(), id, utils.UserID(c))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		}
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if view.IP == nil || *view.IP == "" {
		return httpx.Error(c, fiber.StatusServiceUnavailable, "sandbox has no IP")
	}
	token, err := s.Svc.SecretToken(c.UserContext(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		}
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}

	agentTarget := net.JoinHostPort(*view.IP, strconv.Itoa(1027))

	logCtx := c.UserContext()
	c.Context().Hijack(func(netConn net.Conn) {
		defer netConn.Close()
		up, derr := net.DialTimeout("tcp", agentTarget, 3*time.Second)
		if derr != nil {
			log.WithContext(logCtx).Warnf("[shell] sb=%s dial %s failed: %v", id, agentTarget, derr)
			return
		}
		defer up.Close()
		if _, werr := fmt.Fprintf(up, "%s%s\n", proto.AuthPrefix, token); werr != nil {
			log.WithContext(logCtx).Warnf("[shell] sb=%s auth write failed: %v", id, werr)
			return
		}
		log.WithContext(logCtx).Infof("[shell] sb=%s <-> pty", id)
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(up, netConn); done <- struct{}{} }()
		go func() { _, _ = io.Copy(netConn, up); done <- struct{}{} }()
		<-done
	})

	c.Status(fiber.StatusSwitchingProtocols)
	c.Set("Connection", "Upgrade")
	c.Set("Upgrade", "tcp-tunnel")
	return nil
}

// dialTunnelUpstream prefers the agent-routed path (VM:1026 + AUTH line +
// port header). The "direct" fallback dials VM_IP:<port> straight, used
// only for VMs rehydrated from snapshots predating the agent tunnel
// listener — those don't have an :1026 to talk to. Direct path can't
// authenticate (the user's app on <port> doesn't know the token), and
// can't reach 127.0.0.1-bound services either; it's a compatibility
// stub that stops being meaningful once snapshots are rebuilt with a
// modern agent.
func dialTunnelUpstream(agentAddr, directAddr string, port int, token string) (net.Conn, string, error) {
	up, err := net.DialTimeout("tcp", agentAddr, 3*time.Second)
	if err == nil {
		// AUTH line + port line in a single write so the agent reads
		// both without an extra RTT.
		if _, werr := fmt.Fprintf(up, "%s%s\n%d\n", proto.AuthPrefix, token, port); werr != nil {
			up.Close()
			return nil, "agent", werr
		}
		return up, "agent", nil
	}
	// Only fall back on connection refused / timeout — other errors are real.
	up2, err2 := net.DialTimeout("tcp", directAddr, 3*time.Second)
	if err2 != nil {
		return nil, "direct", err2
	}
	return up2, "direct", nil
}

func (s *Server) handleListRootfs(c *fiber.Ctx) error {
	catalog, def, err := s.Svc.RootfsCatalog(c.UserContext())
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	names := make([]string, 0, len(catalog))
	for k := range catalog {
		names = append(names, k)
	}
	return httpx.Success(c, proto.RootfsView{Rootfs: names, Default: def})
}

// maxRechargePerCallBytes caps a single bandwidth-recharge request at
// 100 GiB. Prevents a typo (1000000000000 instead of 1000000000) from
// silently committing a multi-TB quota the operator never intended to
// debit. Users that legitimately need more can issue multiple calls;
// the cap is per call, not per sandbox or per day.
const maxRechargePerCallBytes int64 = 100 * 1024 * 1024 * 1024

func (s *Server) handleRecharge(c *fiber.Ctx) error {
	id := c.Params("id")
	var req RechargeReq
	if err := c.BodyParser(&req); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if req.AddBytes <= 0 {
		return httpx.Fail(c, fiber.StatusBadRequest, "must be > 0")
	}
	if req.AddBytes > maxRechargePerCallBytes {
		return httpx.Fail(c, fiber.StatusBadRequest,
			"add_bytes exceeds the 100 GiB per-call cap; split into multiple recharge calls")
	}
	view, err := s.Svc.Recharge(c.UserContext(), id, utils.UserID(c), req.AddBytes)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		}
		if errors.Is(err, ErrInvalidRequest) {
			return httpx.Fail(c, fiber.StatusBadRequest, err.Error())
		}
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, view)
}

func (s *Server) handleDestroy(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := s.Svc.Destroy(c.UserContext(), id, utils.UserID(c)); err != nil {
		// NotFound is idempotent-success at this layer: the host doesn't
		// know about this sandbox (e.g. reconciler already reaped it, or
		// control is racing eager + tick destroys). Return ok so callers
		// see a clean 200 from DELETE.
		if errors.Is(err, ErrNotFound) {
			return httpx.Success(c, proto.DestroyResp{ID: id, Status: "destroyed"})
		}
		log.WithContext(c.UserContext()).Errorf("[handler] internal error: %v", err)

		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.DestroyResp{ID: id, Status: "destroyed"})
}

// handleInternalDestroy is the control-role mTLS endpoint for host cleanup.
// It delegates to handleDestroy and keeps the same ownership checks: control
// must forward the sandbox owner's user ID; an empty caller is rejected.
func (s *Server) handleInternalDestroy(c *fiber.Ctx) error {
	return s.handleDestroy(c)
}

// handlePause kicks off the async pause flow on this host. The
// service layer is responsible for CAS-marking the row and spawning
// the pause goroutine.
func (s *Server) handlePause(c *fiber.Ctx) error {
	// Clone the URL param — Svc.Pause kicks off an async goroutine that
	// holds onto `id` past handler return; without the clone the goroutine
	// would race with fasthttp's request-buffer reuse (the same class of
	// bug we hit on /resume under concurrent bursts).
	id := strings.Clone(c.Params("id"))
	view, err := s.Svc.Pause(c.UserContext(), id, utils.UserID(c))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		}
		if errors.Is(err, ErrInvalidRequest) {
			return httpx.Fail(c, fiber.StatusConflict, err.Error())
		}
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	c.Set("X-Poll-After", "2")
	return httpx.SuccessStatus(c, fiber.StatusAccepted, view)
}

// handleDiskAttach lives-attaches a single disk. Body is the ResolvedDisk
// shape control forwards; rd.Credentials is a cryptobox envelope sealed
// to this host's pubkey — open it before decoding into MMDS form.
func (s *Server) handleDiskAttach(c *fiber.Ctx) error {
	id := c.Params("id")
	var rd proto.ResolvedDisk
	if err := c.BodyParser(&rd); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	if rd.DiskID == "" || rd.MountPath == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "disk_id and mount_path required")
	}
	rds := []proto.ResolvedDisk{rd}
	if err := s.Svc.UnsealResolvedDiskCreds(rds); err != nil {
		log.WithContext(c.UserContext()).Errorf("[handler] disk attach unseal %s: %v", id, err)
		return httpx.Error(c, fiber.StatusBadRequest, "disk credentials unreadable")
	}
	rd = rds[0]
	d := proto.MMDSDisk{
		ID:        rd.DiskID,
		Kind:      rd.Kind,
		MountPath: rd.MountPath,
		SubPath:   rd.SubPath,
	}
	_ = proto.DecodeS3Config(rd.Config, &d.Config)
	_ = proto.DecodeS3Creds(rd.Credentials, &d.Credentials)
	if err := s.Svc.AttachDisk(c.UserContext(), id, utils.UserID(c), d); err != nil {
		if errors.Is(err, ErrNotFound) {
			return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		}
		log.WithContext(c.UserContext()).Errorf("[handler] disk attach: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.NewIDResp(id))
}

// handleDiskDetach removes one disk's mount. Idempotent — detaching a
// disk that isn't attached returns 200. mount_path is required so a
// disk mounted at multiple paths can detach exactly one.
func (s *Server) handleDiskDetach(c *fiber.Ctx) error {
	id := c.Params("id")
	diskID := c.Params("disk")
	mountPath := c.Query("mount_path")
	if diskID == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "disk id required")
	}
	if mountPath == "" {
		return httpx.Fail(c, fiber.StatusBadRequest, "mount_path query parameter required")
	}
	if err := s.Svc.DetachDisk(c.UserContext(), id, utils.UserID(c), diskID, mountPath); err != nil {
		if errors.Is(err, ErrNotFound) {
			return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		}
		log.WithContext(c.UserContext()).Errorf("[handler] disk detach: %v", err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	return httpx.Success(c, proto.NewIDResp(id))
}

// handleResume runs on the host that the control plane (with scheduler
// help) has chosen for the resume. The forwarded body carries the full
// models.Sandbox so the host doesn't need a separate DB read.
func (s *Server) handleResume(c *fiber.Ctx) error {
	// c.Params returns a string aliasing into fasthttp's request buffer;
	// the buffer is recycled when this handler returns. Without cloning,
	// the async goroutine downstream sees `id` mutate to whatever the
	// next request's URL happens to be — observed as concurrent resumes
	// cross-binding snapshot paths between sandboxes under burst load.
	id := strings.Clone(c.Params("id"))
	var row models.Sandbox
	if err := c.BodyParser(&row); err != nil {
		return httpx.Fail(c, fiber.StatusBadRequest, "invalid JSON")
	}
	row.ID = id
	view, err := s.Svc.Resume(c.UserContext(), id, row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
		}
		if errors.Is(err, ErrInvalidRequest) {
			return httpx.Fail(c, fiber.StatusConflict, err.Error())
		}
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	c.Set("X-Poll-After", "2")
	return httpx.SuccessStatus(c, fiber.StatusAccepted, view)
}

// handleNetReconcileKick wakes the overlay reconciler. Called by
// control after AttachNetwork so the new membership programs into
// BPF maps without waiting for the next 5s tick. Idempotent — the
// reconciler debounces multiple in-flight kicks.
func (s *Server) handleNetReconcileKick(c *fiber.Ctx) error {
	s.Svc.KickNetReconciler()
	return httpx.Success(c, struct{}{})
}

type poolClaimKickReq struct {
	Owner string `json:"owner"`
}

// handlePoolClaimKick refreshes the guest clock on a pool-claimed
// sandbox so the tenant's SigV4 workloads don't hit RequestTimeTooSkewed,
// and seeds the ownership cache with the new owner from the request body.
// Called by control right after tryClaimFromPool commits.
func (s *Server) handlePoolClaimKick(c *fiber.Ctx) error {
	id := c.Params("id")
	var body poolClaimKickReq
	// Body is optional — legacy callers post an empty body. If parse
	// fails we still run the kick (clock refresh) without the seed.
	_ = c.BodyParser(&body)
	if err := s.Svc.PoolClaimKick(c.UserContext(), id, body.Owner); err != nil {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	return httpx.Success(c, struct{}{})
}
