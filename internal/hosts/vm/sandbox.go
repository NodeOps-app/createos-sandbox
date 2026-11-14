package vm

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/proto"
)

const agentPort = 1024

// Buffered exec emits up to 1 MiB each of stdout/stderr. JSON escaping can
// expand each byte sixfold. Streaming output uses 4 KiB chunks in the agent;
// cap each frame independently so total stream length remains unrestricted.
const (
	maxGuestExecResponseBytes = 16 << 20
	maxGuestExecFrameBytes    = 64 << 10
)

// readGuestLine bounds allocation before assembling an untrusted guest frame.
// A frame includes its newline; incomplete/oversized frames are never forwarded.
func readGuestLine(r *bufio.Reader, maxBytes int) ([]byte, error) {
	var line []byte
	for {
		fragment, err := r.ReadSlice('\n')
		if len(fragment) > maxBytes-len(line) {
			return nil, fmt.Errorf("guest response line exceeds %d bytes", maxBytes)
		}
		line = append(line, fragment...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF && len(line) != 0 {
			return nil, io.ErrUnexpectedEOF
		}
		if err != nil {
			return nil, err
		}
		return line, nil
	}
}

// Sandbox represents a running Firecracker VM.
type Sandbox struct {
	ID string
	// CreatedBy caches the sandbox's owner user_id so the host's exec /
	// bandwidth / get paths can gate on ownership without a per-call
	// DB round-trip to control's proxy (~27ms). Set at Create from the
	// request context, updated in place by pool-claim + resume, and
	// seeded at rehydrate. Empty on a rehydrated row we haven't back-
	// filled yet — treated as a cache miss and the slow path resolves
	// via Repo.Get, then warms this field.
	CreatedBy string
	// Name is the user-facing VM name. Set at Create from CreateRequest.Name
	// and on the resume path from the durable store record. Pushed into the
	// guest via MMDS as `hostname` and consumed by the per-host DNS stub.
	Name        string
	IP          string
	ApiSocket   string // Firecracker API socket
	Machine     *firecracker.Machine
	FCPid       int // firecracker process PID; valid once Machine is started. Captured for restart-survivable teardown when Machine handle is gone after rehydrate.
	Net         *PooledNet
	OverlayPath string

	// VMStateOverlayPath is the overlay path that's actually baked into
	// firecracker's vmstate. Equals OverlayPath at fresh Create time;
	// preserved across pause→resume cycles (resume sets a fresh
	// OverlayPath for the on-disk decompressed file but vmstate still
	// references the original baked path via a symlink). Read by the
	// pause manifest builder so resume code can reproduce the right
	// symlink target on any host.
	VMStateOverlayPath string

	Rootfs   string // catalog name of the base rootfs
	VCPU     int
	MemMib   int
	DiskMib  int64
	Egress   []string // allowlist applied via iptables; empty = allow all
	HostVeth string   // root-netns veth peer name (resolved at create time)
	// egressMu serialises live policy replacements for this sandbox. Without
	// it, two concurrent PUT /egress calls can each derive a transition from
	// the same old policy and interleave iptables transactions.
	egressMu sync.Mutex

	// Bandwidth quota (bytes). 0 = unmetered. Used and Capped are kept in
	// memory by the meter loop and persisted to the store periodically.
	BandwidthQuota  int64
	BandwidthUsed   int64
	BandwidthCapped bool
	// BandwidthIngressBytes is the host→VM cumulative byte counter —
	// observation-only, never enforces a cap. Tracked in memory by the
	// meter loop alongside Used so the bandwidth API can surface
	// inbound traffic without an extra DB round-trip. Persisted via
	// the same MeterPersister callback as the egress counters.
	BandwidthIngressBytes int64
	// BandwidthBaseline is the cumulative byte total from prior host(s)
	// before this resume. The per-host iptables counter starts from zero
	// every time a meter chain is installed, so to keep a true lifetime
	// total across pause/resume the meter loop reports
	// `Used = Baseline + chain_bytes`. Set at fresh Create to 0; set on
	// resume from `row.bandwidth_used_bytes`.
	BandwidthBaseline int64
	// BandwidthIngressBaseline mirrors BandwidthBaseline for the ingress
	// counter — needed because cross-host pause/resume lands on a fresh
	// BPF map per host, so without a baseline the lifetime inbound total
	// would reset on every migration. Same-host restart restores this
	// baseline from the runtime directory alongside the pinned BPF counters.
	BandwidthIngressBaseline int64

	// Envs is the persistent server-side env-var map. Stamped at create
	// time (or read back on rehydrate from the DB) and injected into
	// every /exec call's proto.ExecRequest.Env. Never user-mutable
	// post-create today — see manager.go's CreateRequest.Envs and
	// rehydrate.go's RehydrateSpec.Envs for the two ingress points.
	Envs map[string]string

	// SecretToken is the per-VM shared secret pushed into the guest via
	// MMDS at create time. Every host→agent dial (exec/files/tunnel)
	// prepends "AUTH <token>\n" before the existing payload. Read-only
	// after Create / Rehydrate; never rotated within a VM lifetime.
	SecretToken string

	// Disks is the most recent set of disk attachments pushed into MMDS
	// for this VM. Held in memory only so post-resume + reconcile paths
	// can re-push without re-fetching from control on every retry.
	// Plaintext credentials live here while the VM is alive — host
	// memory only, never serialised to disk.
	Disks []proto.MMDSDisk

	// guestConsole is a bounded, in-memory tail of the serial console used
	// only to classify unexpected guest deaths. Its contents are never logged.
	guestConsole *guestConsoleCapture

	cancel context.CancelFunc

	// File transfers belong to this VM incarnation. Teardown cancels them
	// before its network slot can be reused, including after host rehydration.
	fileOnce   sync.Once
	fileCtx    context.Context
	fileCancel context.CancelFunc

	// UFFD page server, if the VM was restored via UFFD snapshot. nil for
	// cold-boot or file-backed snapshot. Must be closed on sandbox destroy
	// so the listening socket + mmap are released.
	Uffd *UFFDServer

	// VsockUDSPath is the host-side unix socket path firecracker uses for
	// this VM's vsock device. Per-VM unique random path under
	// runtime dir; cleaned up on Destroy. Empty when vsock probing is
	// disabled (transport=tcp). When non-empty, waitForAgent dials
	// this path instead of TCP.
	VsockUDSPath string

	// destroyed is set by Manager.Destroy BEFORE teardown so the per-VM
	// death watcher knows this exit was deliberate and skips cleanup that
	// the Destroy path is already doing. Set-once; never cleared.
	Destroyed atomic.Bool

	// createdByMu protects CreatedBy. Pool claims update the cached owner from
	// the control-plane kick while the tenant's first exec may read it
	// concurrently.
	createdByMu sync.RWMutex

	// Freezing is set by the pause path BEFORE calling firecracker's
	// PauseVM. While set, the agent on :1024 stops answering (the guest
	// vCPU is frozen) — the liveness watcher must ignore probe failures
	// or it will race pause to a Destroy. Set-once; the sandbox is torn
	// down right after pause completes, so there's no need to clear.
	Freezing atomic.Bool
}

func (s *Sandbox) initFileContext() {
	s.fileOnce.Do(func() { s.fileCtx, s.fileCancel = context.WithCancel(context.Background()) })
}

func (s *Sandbox) FileTransferContext(parent context.Context) (context.Context, context.CancelFunc) {
	s.initFileContext()
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(s.fileCtx, cancel)
	if s.fileCtx.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}

func (s *Sandbox) cancelFileTransfers() {
	s.initFileContext()
	s.fileCancel()
}

// CachedOwner returns the owner cached for host-side hot-path authorization.
func (s *Sandbox) CachedOwner() string {
	s.createdByMu.RLock()
	defer s.createdByMu.RUnlock()
	return s.CreatedBy
}

// SetCachedOwner updates the host-side ownership cache.
func (s *Sandbox) SetCachedOwner(owner string) {
	s.createdByMu.Lock()
	s.CreatedBy = owner
	s.createdByMu.Unlock()
}

// Exec sends a command to the guest agent via TCP and returns the response.
func (s *Sandbox) Exec(ctx context.Context, req proto.ExecRequest) (*proto.ExecResponse, error) {
	r, _, err := s.ExecTimed(ctx, req)
	return r, err
}

// ExecTimed is Exec with per-phase timings (dial/write/read in ms).
// Not user-facing — used only for internal exec-trace logging in
// Service.Exec so we can correlate wall vs. server breakdown.
func (s *Sandbox) ExecTimed(ctx context.Context, req proto.ExecRequest) (*proto.ExecResponse, map[string]float64, error) {
	phases := make(map[string]float64, 3)
	addr := fmt.Sprintf("%s:%d", s.IP, agentPort)
	t0 := time.Now()
	conn, err := dialAgent(ctx, addr)
	phases["dial"] = float64(time.Since(t0).Microseconds()) / 1000.0
	if err != nil {
		return nil, phases, fmt.Errorf("dial agent: %w", err)
	}
	defer conn.Close()

	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	body, _ := json.Marshal(req)
	payload := append([]byte(proto.AuthPrefix+s.SecretToken+"\n"), body...)
	payload = append(payload, '\n')
	t1 := time.Now()
	if _, err := conn.Write(payload); err != nil {
		return nil, phases, fmt.Errorf("write: %w", err)
	}
	phases["write"] = float64(time.Since(t1).Microseconds()) / 1000.0

	reader := bufio.NewReader(conn)
	t2 := time.Now()
	line, err := readGuestLine(reader, maxGuestExecResponseBytes)
	phases["read"] = float64(time.Since(t2).Microseconds()) / 1000.0
	if err != nil {
		return nil, phases, fmt.Errorf("read: %w", err)
	}

	var resp proto.ExecResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, phases, fmt.Errorf("json decode: %w", err)
	}
	return &resp, phases, nil
}

// ExecStream runs the command in streaming mode. It opens the agent
// TCP connection, sends an ExecRequest with Stream=true, and copies
// every NDJSON event line emitted by the agent into w. The function
// returns once the agent closes the connection (final {"exit": N}
// event sent) or on any I/O error.
//
// Cancellation contract: if w is a *fiber.Ctx response writer (the
// streaming response that the host's HTTP handler exposes), a write
// failure here propagates down by closing conn — the agent then sees
// EPIPE on its own write and kills the command via SIGTERM/SIGKILL.
func (s *Sandbox) ExecStream(ctx context.Context, req proto.ExecRequest, w io.Writer, flush func()) error {
	req.Stream = true
	addr := fmt.Sprintf("%s:%d", s.IP, agentPort)
	conn, err := dialAgent(ctx, addr)
	if err != nil {
		return fmt.Errorf("dial agent: %w", err)
	}
	defer conn.Close()

	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	// Some kernels ignore SO_KEEPALIVE without explicit interval tuning;
	// 15s here matches the heartbeat cadence so an unresponsive peer is
	// noticed within ~30s even if the application never writes.
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(15 * time.Second)
	}

	body, _ := json.Marshal(req)
	payload := append([]byte(proto.AuthPrefix+s.SecretToken+"\n"), body...)
	payload = append(payload, '\n')
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// Copy NDJSON lines from agent to w, flushing per line so the caller
	// sees output live. Stop on any read or write error — defer'd
	// conn.Close() then signals the agent to kill.
	reader := bufio.NewReaderSize(conn, 8192)
	for {
		line, err := readGuestLine(reader, maxGuestExecFrameBytes)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err == io.EOF {
				return nil
			}
			return err
		}
		if _, err := w.Write(line); err != nil {
			return err
		}
		if flush != nil {
			flush()
		}
	}
}

// dialAgent connects to the guest agent via TCP with retry.
func dialAgent(ctx context.Context, addr string) (net.Conn, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}

	var lastErr error
	for time.Now().Before(deadline) {
		d := net.Dialer{Timeout: 50 * time.Millisecond}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	return nil, fmt.Errorf("agent connect timed out (last err: %v)", lastErr)
}

// waitForPhase1Probe dials the agent's phase-1 probe port (1023) until it
// accepts a connection. Used by createBaseSnapshot to know the template is at
// the snapshot boundary (post-network-config, pre-overlay-mount).
func waitForPhase1Probe(ctx context.Context, ip string) error {
	addr := fmt.Sprintf("%s:1023", ip)
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for phase1 probe")
		default:
			d := net.Dialer{Timeout: 200 * time.Millisecond}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err == nil {
				_ = conn.Close()
				return nil
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// waitForAgentByTransport routes the readiness probe to the configured
// transport. Returns vsock probe when transport=="vsock" AND the sandbox
// has a VsockUDSPath; otherwise falls back to TCP. The TCP fallback
// matters during the rollout window where a host has vsock enabled but
// some VMs were created/rehydrated before the field landed.
func waitForAgentByTransport(ctx context.Context, sb *Sandbox, transport string) error {
	if transport == "vsock" && sb.VsockUDSPath != "" {
		return waitForAgentVsock(ctx, sb)
	}
	return waitForAgent(ctx, sb)
}

// waitForAgentVsock dials the per-VM firecracker vsock unix socket and
// performs the hybrid-vsock CONNECT handshake to port 1024 (the agent's
// probe listener bound pre-snapshot). Returns nil as soon as the agent
// accepts. Used instead of TCP on nested-virt hosts where the virtio-net
// path is the long pole of agent-ready latency.
func waitForAgentVsock(ctx context.Context, sb *Sandbox) error {
	udsPath := sb.VsockUDSPath
	if udsPath == "" {
		return fmt.Errorf("vsock UDS path empty (sandbox %s)", sb.ID)
	}
	attempts := 0
	start := time.Now()
	var firstDialDur, lastErrDur time.Duration
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for agent (vsock) after %d attempts (first dial=%s, last err=%v @ %s): %w",
				attempts, firstDialDur, lastErr, lastErrDur, ctx.Err())
		default:
			attempts++
			dialStart := time.Now()
			d := net.Dialer{Timeout: 50 * time.Millisecond}
			conn, err := d.DialContext(ctx, "unix", udsPath)
			dialDur := time.Since(dialStart)
			if attempts == 1 {
				firstDialDur = dialDur
			}
			if err == nil {
				// firecracker hybrid-vsock handshake.
				_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
				if _, werr := fmt.Fprintf(conn, "CONNECT %d\n", agentPort); werr != nil {
					_ = conn.Close()
					lastErr = werr
					lastErrDur = time.Since(start)
					time.Sleep(2 * time.Millisecond)
					continue
				}
				// Expect "OK <hostside_port>\n" on success.
				buf := make([]byte, 32)
				n, rerr := conn.Read(buf)
				_ = conn.Close()
				if rerr == nil && n >= 2 && string(buf[:2]) == "OK" {
					if attempts > 1 || time.Since(start) > 10*time.Millisecond {
						log.WithContext(ctx).Infof("[agent-trace] %s vsock attempts=%d total=%s firstDial=%s",
							sb.ID, attempts, time.Since(start).Round(time.Millisecond), firstDialDur.Round(time.Millisecond))
					}
					return nil
				}
				lastErr = fmt.Errorf("handshake: read=%q err=%v", string(buf[:n]), rerr)
				lastErrDur = time.Since(start)
				time.Sleep(2 * time.Millisecond)
				continue
			}
			lastErr = err
			lastErrDur = time.Since(start)
			time.Sleep(2 * time.Millisecond)
		}
	}
}

// waitForAgent blocks until the guest agent's listener on :1024 accepts a
// TCP connection. That's a sufficient liveness signal — the listener only
// binds after the agent has mounted the overlay and is ready to serve exec.
// Previously we ran a full `true` exec here, which added a fork+exec+collect
// round-trip in the guest (~30 ms); the pure TCP probe is <1 ms on success.
func waitForAgent(ctx context.Context, sb *Sandbox) error {
	addr := fmt.Sprintf("%s:%d", sb.IP, agentPort)
	attempts := 0
	start := time.Now()
	var firstDialDur, lastErrDur time.Duration
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for agent after %d attempts (first dial=%s, last err=%v @ %s): %w",
				attempts, firstDialDur, lastErr, lastErrDur, ctx.Err())
		default:
			attempts++
			dialStart := time.Now()
			// 30ms timeout: first dial on a freshly-restored VM sometimes
			// drops its first SYN (guest virtio-net not yet seen on the
			// veth, host ARP neigh stale after slot reuse). Rather than
			// block the dialer for 200ms waiting for a SYN-ACK that isn't
			// coming, fail fast and retry — the second dial lands in ~2ms
			// once the guest's applyNetwork primer packet has primed the
			// host's neigh table. Net effect: p50 agent-wait drops from
			// 203ms to ~30ms on slot-reused VMs, with no impact on
			// already-fast first-use slots (they still succeed on
			// attempt 1).
			d := net.Dialer{Timeout: 10 * time.Millisecond}
			conn, err := d.DialContext(ctx, "tcp", addr)
			dialDur := time.Since(dialStart)
			if attempts == 1 {
				firstDialDur = dialDur
			}
			if err == nil {
				_ = conn.Close()
				if attempts > 1 || time.Since(start) > 10*time.Millisecond {
					log.WithContext(ctx).Infof("[agent-trace] %s attempts=%d total=%s firstDial=%s",
						sb.ID, attempts, time.Since(start).Round(time.Millisecond), firstDialDur.Round(time.Millisecond))
				}
				return nil
			}
			lastErr = err
			lastErrDur = time.Since(start)
			time.Sleep(2 * time.Millisecond)
		}
	}
}
