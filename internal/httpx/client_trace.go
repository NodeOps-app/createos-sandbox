package httpx

import (
	"context"
	"crypto/tls"
	"net/http/httptrace"
	"sync"
	"time"
)

// ClientTimings decomposes an outbound HTTP request without changing its
// transport. Pool measures GetConn to GotConn, including connection setup
// when needed; it overlaps DNS/Connect/TLS rather than being additive.
// Zero durations can mean a phase did not run or has not completed.
type ClientTimings struct {
	mu                                sync.Mutex
	started, dns, connect, tls, wrote time.Time
	DNS, Connect, TLS, Pool, TTFB     time.Duration
	Reused                            bool
}

// WithClientTimings installs net/http trace hooks and returns a snapshot
// function that is safe to call after RoundTrip completes.
func WithClientTimings(ctx context.Context) (context.Context, func() ClientTimings) {
	t := &ClientTimings{started: time.Now()}
	trace := &httptrace.ClientTrace{
		DNSStart:          func(httptrace.DNSStartInfo) { t.mu.Lock(); t.dns = time.Now(); t.mu.Unlock() },
		DNSDone:           func(httptrace.DNSDoneInfo) { t.mu.Lock(); t.DNS = time.Since(t.dns); t.mu.Unlock() },
		ConnectStart:      func(_, _ string) { t.mu.Lock(); t.connect = time.Now(); t.mu.Unlock() },
		ConnectDone:       func(_, _ string, _ error) { t.mu.Lock(); t.Connect = time.Since(t.connect); t.mu.Unlock() },
		TLSHandshakeStart: func() { t.mu.Lock(); t.tls = time.Now(); t.mu.Unlock() },
		TLSHandshakeDone:  func(tls.ConnectionState, error) { t.mu.Lock(); t.TLS = time.Since(t.tls); t.mu.Unlock() },
		GetConn:           func(string) { t.mu.Lock(); t.started = time.Now(); t.mu.Unlock() },
		GotConn: func(info httptrace.GotConnInfo) {
			t.mu.Lock()
			t.Pool = time.Since(t.started)
			t.Reused = info.Reused
			t.mu.Unlock()
		},
		WroteRequest:         func(httptrace.WroteRequestInfo) { t.mu.Lock(); t.wrote = time.Now(); t.mu.Unlock() },
		GotFirstResponseByte: func() { t.mu.Lock(); t.TTFB = time.Since(t.wrote); t.mu.Unlock() },
	}
	return httptrace.WithClientTrace(ctx, trace), func() ClientTimings {
		t.mu.Lock()
		defer t.mu.Unlock()
		return ClientTimings{DNS: t.DNS, Connect: t.Connect, TLS: t.TLS, Pool: t.Pool, TTFB: t.TTFB, Reused: t.Reused}
	}
}
