// Package metrics exposes control-plane Prometheus metrics on its own
// dedicated registry so scrapes here don't drag in the default global
// process metrics that some deployments already surface via a separate
// exporter.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry is the isolated collector set for control. Handler() below
// serves only what we register here.
var Registry = prometheus.NewRegistry()

// CreateSeconds is the wall-clock time the control-plane spent handling
// POST /v1/sandboxes — from handler entry to response send. Captures
// everything server-side: auth, scheduler decision, host RPC forward,
// downstream spawn wait, and response. Does NOT include client network
// RTT (unobservable from the server).
//
// Labels are bounded on purpose: shape from the fixed catalog (~10),
// status_class buckets HTTP status (~3), country is the ISO-3166 code
// from GeoIP (~250 + "unknown"). Worst-case series ≈ 10×3×250 = 7,500.
var CreateSeconds = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "createos_control_create_seconds",
		Help:    "End-to-end wall-clock time the control plane spent handling POST /v1/sandboxes.",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10},
	},
	[]string{"shape", "status_class", "country"},
)

// CreatePhaseSeconds breaks the control-side create wall-clock into named
// phases (preflight, insert, schedule, disks, forward, post). Complements
// CreateSeconds by pinpointing which sub-step dominates the tail —
// e.g. a p99 spike that's entirely in "schedule" points at scheduler
// wait; one entirely in "forward" points at mTLS dial / host queue.
// Buckets span 1ms → ~8s so fast preflights and slow forwards both
// land in usable buckets.
var CreatePhaseSeconds = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "createos_control_create_phase_seconds",
		Help:    "Per-phase wall-clock for POST /v1/sandboxes on the control plane.",
		Buckets: prometheus.ExponentialBuckets(0.001, 2, 14),
	},
	[]string{"phase"},
)

// PoolDepth is the current count of live pool rows for this region and
// spec. Diverging from PoolTarget signals grow-loop underperformance
// (below target) or over-provisioning (above target).
var PoolDepth = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "createos_pool_depth",
		Help: "Live count of pre-warmed pool sandboxes per region+shape.",
	},
	[]string{"region", "shape"},
)

// PoolTarget is the target size for the CURRENT time bucket. Updated by
// the grow loop on every tick. Comparing PoolDepth vs. PoolTarget over
// time tells you whether the buckets are sized right.
var PoolTarget = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "createos_pool_target",
		Help: "Configured pool target for the current time bucket.",
	},
	[]string{"region", "shape", "bucket"},
)

// PoolClaimTotal counts pool-lookup outcomes on user create requests.
// result="hit" — pool row handed over
// result="miss_empty" — request matched spec but pool was empty
// result="miss_ineligible" — request didn't match spec, no pool attempt
var PoolClaimTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "createos_pool_claim_total",
		Help: "Pool-lookup outcomes on POST /v1/sandboxes.",
	},
	[]string{"result"},
)

// PoolClaimSeconds is the wall-clock time the pool-claim CTE took,
// bucketed by outcome. Hits should sit at low-single-digit ms; misses
// are similarly cheap (SELECT returns fast) but tracked separately so
// we can spot regressions.
var PoolClaimSeconds = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "createos_pool_claim_seconds",
		Help:    "Duration of the pool claim tx.",
		Buckets: prometheus.ExponentialBuckets(0.001, 2, 14),
	},
	[]string{"result"},
)

// PoolGrowTotal counts grow-loop create attempts.
// outcome="ok" | "fail" (scheduler unreachable, host at capacity, etc.)
var PoolGrowTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "createos_pool_grow_total",
		Help: "Pool grow-loop create attempts and their outcome.",
	},
	[]string{"outcome"},
)

// PoolShrinkTotal counts pool sandboxes reaped by the shrink loop.
// reason="excess" — over target, oldest first
// reason="aged"   — past max_age
var PoolShrinkTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "createos_pool_shrink_total",
		Help: "Pool shrink-loop destroys and their reason.",
	},
	[]string{"reason"},
)

func init() {
	Registry.MustRegister(CreateSeconds)
	Registry.MustRegister(CreatePhaseSeconds)
	Registry.MustRegister(PoolDepth)
	Registry.MustRegister(PoolTarget)
	Registry.MustRegister(PoolClaimTotal)
	Registry.MustRegister(PoolClaimSeconds)
	Registry.MustRegister(PoolGrowTotal)
	Registry.MustRegister(PoolShrinkTotal)
}

// StatusClass returns "2xx"/"4xx"/"5xx" for a given numeric HTTP status.
// Used as the histogram label so we can slice success vs client-error
// vs server-error latencies separately.
func StatusClass(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 200:
		return "2xx"
	default:
		return "other"
	}
}

// Handler returns the http.Handler that serves the isolated registry
// contents. Mount under an internal, auth-gated route.
func Handler() http.Handler {
	return promhttp.HandlerFor(Registry, promhttp.HandlerOpts{})
}
