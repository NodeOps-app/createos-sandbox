// Package metrics defines the prometheus metric set exposed by the
// createos host agent at /metrics. Wiring lives here so callers in
// internal/hosts/vm/ can poke counters/gauges without depending on
// the prom client directly.
package metrics

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"time"

	"github.com/arl/statsviz"
	"github.com/felixge/fgprof"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

// Registry is the host-scoped registry. We use a private one (not the
// default) so the Go runtime metrics don't auto-mix with our gauges
// unless we opt them in explicitly via NewGoCollector.
var Registry = prometheus.NewRegistry()

// ── Sandbox lifecycle ────────────────────────────────────────────────

// SandboxOps counts terminal events per lifecycle phase. Use the
// phase-specific Inc helpers below so callers don't have to know the
// label values.
var SandboxOps = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "createos_sandbox_ops_total",
		Help: "Count of sandbox lifecycle events on this host.",
	},
	[]string{"phase"}, // created, destroyed, resumed, paused, failed
)

// SandboxRunning is the in-process running-VM count. Backed by a
// callback so it stays consistent with Manager.Sandboxes without
// requiring manual inc/dec on every state transition.
var SandboxRunning = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "createos_sandbox_running",
	Help: "Live count of running sandboxes on this host.",
})

// SpawnPhaseSeconds breaks down the host-side spawn wall clock into
// the phases reported by the existing [sandbox] log line. Labels let
// us hist-aggregate per shape without proliferating series — keep the
// label set small.
var SpawnPhaseSeconds = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "createos_spawn_phase_seconds",
		Help:    "Per-phase duration of sandbox creation.",
		Buckets: prometheus.ExponentialBuckets(0.005, 2, 12), // 5ms..~20s
	},
	[]string{"phase"}, // pool, boot, agent, net, total
)

// HostCreatePhaseSeconds breaks down the host-side create request into
// phases OUTSIDE Manager.Create — parse, svc (Service.Create wrapper),
// resp, boot.queue, mgr.create. Complements SpawnPhaseSeconds by making
// the gap between "host handler entered" and "phase=total timer started"
// visible. Buckets span 1ms → ~8s.
var HostCreatePhaseSeconds = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "createos_host_create_phase_seconds",
		Help:    "Per-phase wall-clock for POST /v1/sandboxes on the host agent (outside Manager.Create).",
		Buckets: prometheus.ExponentialBuckets(0.001, 2, 14),
	},
	[]string{"phase"},
)

// SnapshotCapturePhaseSeconds uses fixed worker phases, never sandbox IDs.
var SnapshotCapturePhaseSeconds = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "createos_snapshot_capture_phase_seconds",
		Help:    "Snapshot capture and upload phase wall-clock duration, including failed phases.",
		Buckets: prometheus.ExponentialBuckets(0.001, 2, 22),
	},
	[]string{"operation", "phase"},
)

// ── Resource pools ───────────────────────────────────────────────────

// NetPoolDepth tracks the NetPool's free-slot count. Falling near 0
// during a burst signals slot exhaustion → replenish lag → spawn
// latency cliff.
var NetPoolDepth = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "createos_netpool_depth",
	Help: "Free network slots in the NetPool ready channel.",
})

// SnapshotReady is 1 when the per-(shape,rootfs) prewarmed snapshot
// is ready, 0 otherwise. Useful for "host fully ready" alerts.
var SnapshotReady = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "createos_snapshot_ready",
		Help: "Whether the prewarmed snapshot for a (shape,rootfs) is ready (1) or not (0).",
	},
	[]string{"shape", "rootfs"},
)

// FirecrackerConcurrent is the count of /snapshot/load + cold-boot
// firecracker invocations currently in-flight. High values correlate
// with vCPU starvation on nested-virt hosts.
var FirecrackerConcurrent = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "createos_firecracker_concurrent",
	Help: "Count of firecracker create+restore operations currently in-flight.",
})

// ── Memory accounting ────────────────────────────────────────────────

var (
	MemCapacityMiB = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "createos_mem_capacity_mib",
		Help: "Operator-configured memory capacity for VMs on this host (MiB).",
	})
	MemInUseMiB = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "createos_mem_in_use_mib",
		Help: "Memory currently committed to running VMs (MiB).",
	})
)

// ── Internal RPC instrumentation ────────────────────────────────────

// InternalRPC counts every inbound /v1/internal/* request by service +
// method. Authentication is enforced by each route's middleware; this
// counter has no authentication-method label.
var InternalRPC = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "createos_internal_rpc_total",
		Help: "Internal RPC count by service and method.",
	},
	[]string{"service", "method"},
)

// InternalRPCSeconds measures inbound service-to-service RPC wall time.
// Status is a bounded HTTP status class so latency can be separated from
// failure retries without creating unbounded metric cardinality.
var InternalRPCSeconds = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "createos_internal_rpc_seconds",
		Help:    "Wall-clock duration of internal RPCs by service, method, and status class.",
		Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
	},
	[]string{"service", "method", "status_class"},
)

// ── Build info ───────────────────────────────────────────────────────

// BuildInfo is the standard prometheus "info" pattern — value is
// always 1; the labels carry the metadata.
var BuildInfo = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "createos_build_info",
		Help: "Build metadata for the createos binary on this host.",
	},
	[]string{"version", "commit", "go_version"},
)

// ── Per-sandbox resource usage (cgroup-scraped) ──────────────────────

// SandboxMemBytes is the guest workload memory from each VM's cgroup
// memory.stat "anon" line. anon = firecracker's anonymous mmap backing
// the guest's RAM, which is what the tenant sees inside the VM's
// `free`/`top`. Deliberately NOT memory.current — that includes page
// cache and drifts toward the ceiling on any long-running VM, which
// misleads tenant dashboards. For OOM/quota accounting operators still
// look at memory.max on the cgroup directly.
var SandboxMemBytes = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "createos_sandbox_memory_bytes",
		Help: "Per-sandbox guest workload memory in bytes (cgroup memory.stat anon).",
	},
	[]string{"sandbox_id"},
)

// SandboxMemLimitBytes is the per-VM memory cap (cgroup memory.max).
// Paired with SandboxMemBytes so dashboards can compute utilization
// (current / limit) without a second scrape.
var SandboxMemLimitBytes = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "createos_sandbox_memory_limit_bytes",
		Help: "Per-sandbox memory cap in bytes (cgroup memory.max).",
	},
	[]string{"sandbox_id"},
)

// SandboxCPUSecondsTotal is the cumulative CPU seconds the VM has
// consumed (cgroup cpu.stat usage_usec). Counter — use rate() in
// PromQL to derive instantaneous cores used.
var SandboxCPUSecondsTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "createos_sandbox_cpu_seconds_total",
		Help: "Cumulative CPU seconds consumed by sandbox (cgroup cpu.stat usage_usec).",
	},
	[]string{"sandbox_id"},
)

// SandboxNetBytesIn/OutTotal are per-VM cumulative network byte
// counters from the BPF veth meter. Emitting them at scrape time lets
// PromQL do rate() for bytes/sec without shipping a separate
// timeseries. Cumulative, so the ring buffer can recover per-tick
// deltas without racing with rehydrate baselines.
var SandboxNetBytesInTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "createos_sandbox_net_bytes_in_total",
		Help: "Cumulative host→VM bytes over the BPF veth meter.",
	},
	[]string{"sandbox_id"},
)

var SandboxNetBytesOutTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "createos_sandbox_net_bytes_out_total",
		Help: "Cumulative VM→host bytes over the BPF veth meter.",
	},
	[]string{"sandbox_id"},
)

// SandboxMemUsedGuestBytes is the guest's own "used" number, matching
// what `free -m` prints inside the VM. Complements SandboxMemBytes
// (host-side anon) so tenants can see both views.
var SandboxMemUsedGuestBytes = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "createos_sandbox_memory_used_guest_bytes",
		Help: "Per-sandbox memory used as seen inside the guest (matches `free -m used`; total-free-buffers-cached).",
	},
	[]string{"sandbox_id"},
)

// SandboxStorageUsed/LimitBytes are the guest's rootfs occupation and
// its ceiling (disk_mib * 1024^2). Gauges — the tenant's UI reads the
// ratio to draw the "storage" chart in the screenshot.
var SandboxStorageUsedBytes = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "createos_sandbox_storage_used_bytes",
		Help: "Per-sandbox rootfs bytes used (overlay ext4).",
	},
	[]string{"sandbox_id"},
)

var SandboxStorageLimitBytes = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "createos_sandbox_storage_limit_bytes",
		Help: "Per-sandbox rootfs capacity (disk_mib × 1024^2).",
	},
	[]string{"sandbox_id"},
)

func init() {
	Registry.MustRegister(
		SandboxOps,
		SandboxRunning,
		SpawnPhaseSeconds,
		HostCreatePhaseSeconds,
		SnapshotCapturePhaseSeconds,
		NetPoolDepth,
		SnapshotReady,
		FirecrackerConcurrent,
		MemCapacityMiB,
		MemInUseMiB,
		BuildInfo,
		InternalRPC,
		InternalRPCSeconds,
		SandboxMemBytes,
		SandboxMemLimitBytes,
		SandboxCPUSecondsTotal,
		SandboxNetBytesInTotal,
		SandboxNetBytesOutTotal,
		SandboxStorageUsedBytes,
		SandboxStorageLimitBytes,
		SandboxMemUsedGuestBytes,
	)
	// Go runtime + process metrics. The process collector exposes
	// uptime, RSS, FDs etc. — handy for catching FD leaks.
	Registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
}

// ── HTTP server ──────────────────────────────────────────────────────

// ServeConfig is the operator-tunable surface for the host's metrics
// endpoint. Both fields empty = metrics endpoint disabled.
type ServeConfig struct {
	// Addr is the TCP listen address, e.g. ":9091". When empty the
	// endpoint isn't started.
	Addr string
	// TokenFile points at a file containing the static bearer token.
	// Required whenever Addr enables the listener.
	TokenFile string
}

// Serve starts the host's /metrics listener on its own http.Server
// (separate from the API server). Returns nil immediately when
// cfg.Addr is empty so callers can call it unconditionally.
// Blocks the caller's goroutine; intended to be run in `go ...`.
func Serve(ctx context.Context, cfg ServeConfig) error {
	if cfg.Addr == "" {
		return nil
	}
	if cfg.TokenFile == "" {
		return fmt.Errorf("metrics token file is required when metrics listener is enabled")
	}
	var expectedToken string
	raw, err := os.ReadFile(cfg.TokenFile)
	if err != nil {
		return fmt.Errorf("read metrics token file %q: %w", cfg.TokenFile, err)
	}
	expectedToken = strings.TrimSpace(string(raw))
	if expectedToken == "" {
		return fmt.Errorf("metrics token file %q is empty", cfg.TokenFile)
	}

	handler := promhttp.HandlerFor(Registry, promhttp.HandlerOpts{
		ErrorLog:      log.StandardLogger(),
		ErrorHandling: promhttp.ContinueOnError,
	})

	mux := http.NewServeMux()

	// requireToken wraps a handler with the same bearer-token gate as
	// /metrics. Use for any debug surface we don't want public.
	requireToken := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if expectedToken != "" {
				h := r.Header.Get("Authorization")
				if !strings.HasPrefix(h, "Bearer ") || strings.TrimPrefix(h, "Bearer ") != expectedToken {
					w.Header().Set("WWW-Authenticate", `Bearer realm="createos-metrics"`)
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}

	mux.Handle("/metrics", requireToken(handler))

	// /debug/pprof/* exposes runtime diagnostics through the same optional
	// bearer-token gate as /metrics. With an empty token these routes are
	// unauthenticated; deployments must configure the token and restrict access.
	//
	// Common probes:
	//   curl -H "Authorization: Bearer $TOKEN" http://host:9091/debug/pprof/goroutine?debug=1
	//   curl -H "Authorization: Bearer $TOKEN" http://host:9091/debug/pprof/goroutine?debug=2 > stacks.txt
	//   go tool pprof http://host:9091/debug/pprof/profile?seconds=30
	mux.Handle("/debug/pprof/", requireToken(http.HandlerFunc(pprof.Index)))
	mux.Handle("/debug/pprof/cmdline", requireToken(http.HandlerFunc(pprof.Cmdline)))
	mux.Handle("/debug/pprof/profile", requireToken(http.HandlerFunc(pprof.Profile)))
	mux.Handle("/debug/pprof/symbol", requireToken(http.HandlerFunc(pprof.Symbol)))
	mux.Handle("/debug/pprof/trace", requireToken(http.HandlerFunc(pprof.Trace)))

	// /debug/fgprof — wall-clock profile covering BOTH on-CPU and
	// off-CPU (blocked in syscall, chan recv, mutex, sleep) time.
	// pprof.Profile above only samples on-CPU, which is exactly the
	// blind spot in the idle-CPU accumulation bug: a watcher looping
	// without backoff shows as sleep/syscall time, not CPU time.
	//
	//   go tool pprof -http=: 'http://host:9091/debug/fgprof?seconds=30'
	mux.Handle("/debug/fgprof", requireToken(fgprof.Handler()))

	// /debug/statsviz/ — live browser view of GC, heap, goroutine count
	// and scheduler latency. Cheap way to watch a host over hours and
	// catch the goroutine curve climbing before CPU does.
	statsvizSrv, err := statsviz.NewServer(statsviz.Root("/debug/statsviz"))
	if err != nil {
		return fmt.Errorf("statsviz: %w", err)
	}
	mux.Handle("/debug/statsviz/", requireToken(statsvizSrv.Index()))
	mux.Handle("/debug/statsviz/ws", requireToken(http.HandlerFunc(statsvizSrv.Ws())))

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Close on ctx done.
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	log.WithContext(ctx).Infof("[metrics] listening on %s (auth=%v)", cfg.Addr, expectedToken != "")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("metrics serve: %w", err)
	}
	return nil
}
