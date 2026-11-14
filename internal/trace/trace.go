// Package trace is a logrus-backed, log-line based tracer for the
// control api-server plane's hot paths. Not a replacement for OpenTelemetry
// — intentionally simpler: just time named phases inside a single
// request and dump a one-liner summary at the end.
//
// Example:
//
//	t := trace.Start("create")
//	defer t.End()
//	stop := t.Phase("schedule")
//	resp, err := s.schedulerClient.Schedule(ctx, req)
//	stop()
//	…
//
// Output:
//
//	[trace] create total=263.12ms id=sb-01K… reserve=92.40ms forward=44.70ms set_host=93.00ms
//
// grep + awk is a perfectly good analysis layer for this scale.
package trace

import (
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// Observer is an optional callback invoked with each phase's name and
// duration when the phase's stop() runs. Used to feed the same timing
// data into Prometheus histograms without coupling the trace package
// to any specific metrics registry.
type Observer func(name string, d time.Duration)

// Trace collects phase timings for a single request. Not safe for
// concurrent use across goroutines — use one Trace per goroutine /
// request.
type Trace struct {
	name     string
	start    time.Time
	phases   []phase
	attrs    []attr
	stopped  bool
	observer Observer
}

// WithObserver attaches a per-phase callback. Chainable so callers can
// write: trace.Start("create").WithObserver(fn).
func (t *Trace) WithObserver(o Observer) *Trace {
	t.observer = o
	return t
}

type phase struct {
	name string
	dur  time.Duration
}

type attr struct {
	key, val string
}

// Start begins a trace for a named hot path (e.g. "create", "destroy").
// The returned Trace must have End() called to emit the log line;
// defer t.End() is idiomatic.
func Start(name string) *Trace {
	return &Trace{name: name, start: time.Now()}
}

// Attr adds a key=value pair to the emitted log line. Typical uses:
// id=<sandbox id>, host=<host id>, status=<http code>.
func (t *Trace) Attr(key, val string) *Trace {
	t.attrs = append(t.attrs, attr{key, val})
	return t
}

// Phase returns a Stop func that records elapsed time against `name`
// when called. Defer it, or call synchronously after the phase ends.
func (t *Trace) Phase(name string) (stop func()) {
	start := time.Now()
	return func() {
		d := time.Since(start)
		t.phases = append(t.phases, phase{name: name, dur: d})
		if t.observer != nil {
			t.observer(name, d)
		}
	}
}

// End emits the tracing log line. Safe to call twice; second call no-ops
// so defer + explicit End are compatible.
func (t *Trace) End() {
	if t.stopped {
		return
	}
	t.stopped = true
	total := time.Since(t.start)

	var b strings.Builder
	b.WriteString(t.name)
	fmt.Fprintf(&b, " total=%.2fms", ms(total))
	for _, a := range t.attrs {
		b.WriteString(" ")
		b.WriteString(a.key)
		b.WriteString("=")
		b.WriteString(a.val)
	}
	for _, p := range t.phases {
		fmt.Fprintf(&b, " %s=%.2fms", p.name, ms(p.dur))
	}

	log.Infof("[trace] %s", b.String())
}

func ms(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}
