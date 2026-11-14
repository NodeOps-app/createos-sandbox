package controlclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

// diagnosticTransport preserves transport behavior and records connection phases.
// Only failures are logged, at most once a minute per client. Trace callbacks can
// race with cancellation and Happy Eyeballs dialing, so their state is locked.
// Do not log URLs, headers, bodies or raw errors: they may contain credentials.
type diagnosticTransport struct {
	base           http.RoundTripper
	lastFailureLog atomic.Int64
}

func (t *diagnosticTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	var mu sync.Mutex
	fields := log.Fields{"control_host": req.URL.Hostname(), "method": req.Method}
	var dnsStart, tlsStart, written time.Time
	connects := make(map[string]time.Time)
	update := func(fn func()) { mu.Lock(); defer mu.Unlock(); fn() }
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { update(func() { dnsStart = time.Now(); fields["phase"] = "dns" }) },
		DNSDone: func(i httptrace.DNSDoneInfo) {
			update(func() {
				fields["dns_duration"] = time.Since(dnsStart)
				ips := make([]string, 0, len(i.Addrs))
				for _, a := range i.Addrs {
					ips = append(ips, a.IP.String())
				}
				fields["resolved_ips"] = ips
				if i.Err != nil {
					fields["dns_error_type"] = fmt.Sprintf("%T", i.Err)
				}
			})
		},
		ConnectStart: func(network, addr string) {
			update(func() { connects[network+addr] = time.Now(); fields["phase"] = "tcp"; fields["connect_address"] = addr })
		},
		ConnectDone: func(network, addr string, err error) {
			update(func() {
				if s, ok := connects[network+addr]; ok {
					fields["tcp_duration"] = time.Since(s)
				}
				if err != nil {
					fields["tcp_error_type"] = fmt.Sprintf("%T", err)
				}
			})
		},
		TLSHandshakeStart: func() { update(func() { tlsStart = time.Now(); fields["phase"] = "tls" }) },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			update(func() {
				fields["tls_duration"] = time.Since(tlsStart)
				if err != nil {
					fields["tls_error_type"] = fmt.Sprintf("%T", err)
				}
			})
		},
		GotConn: func(i httptrace.GotConnInfo) {
			update(func() {
				fields["phase"] = "write"
				fields["connection_reused"] = i.Reused
				fields["remote_address"] = i.Conn.RemoteAddr().String()
			})
		},
		WroteRequest: func(i httptrace.WroteRequestInfo) {
			update(func() {
				if i.Err != nil {
					fields["write_error_type"] = fmt.Sprintf("%T", i.Err)
				} else {
					written = time.Now()
					fields["phase"] = "response_headers"
				}
			})
		},
		GotFirstResponseByte: func() {
			update(func() {
				if !written.IsZero() {
					fields["first_byte_duration"] = time.Since(written)
				}
				fields["phase"] = "response_headers_received"
			})
		},
	}
	resp, err := t.base.RoundTrip(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
	if err == nil && resp.StatusCode < 500 {
		return resp, err
	}
	// Caller cancellation is expected during shutdown; a deadline is diagnostic.
	if req.Context().Err() == context.Canceled {
		return resp, err
	}
	now := time.Now()
	last := t.lastFailureLog.Load()
	if (last == 0 || now.UnixNano()-last >= int64(time.Minute)) && t.lastFailureLog.CompareAndSwap(last, now.UnixNano()) {
		update(func() {
			fields["total_duration"] = time.Since(start)
			if !written.IsZero() {
				fields["response_wait_duration"] = time.Since(written)
			}
			if resp != nil {
				fields["status"] = resp.StatusCode
			}
			if err != nil {
				fields["error_type"] = fmt.Sprintf("%T", err)
				fields["error_kind"] = connectionErrorKind(err)
				if deadline, ok := req.Context().Deadline(); ok && !time.Now().Before(deadline) {
					fields["error_kind"] = "timeout"
				}
			}
			log.WithContext(req.Context()).WithFields(fields).Warn("[control-client] request failed")
		})
	}
	return resp, err
}

func (t *diagnosticTransport) CloseIdleConnections() {
	if c, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// Stable, credential-free error categories complement the phase timings.
func connectionErrorKind(err error) string {
	var dns *net.DNSError
	if errors.As(err, &dns) {
		if dns.IsNotFound {
			return "dns_not_found"
		}
		if dns.IsTimeout {
			return "dns_timeout"
		}
		return "dns_error"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection_refused"
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return "network_unreachable"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return "transport_error"
}
