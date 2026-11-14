// Package ingress implements the createos HTTP ingress: a stateless
// reverse proxy that routes <ulid>-<port>.<DomainSuffix> to the
// corresponding sandbox VM. Its inbound listener uses HTTP behind the trusted
// edge proxy; outbound control lookups and host tunnels require mTLS.
package ingress

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"

	"github.com/NodeOps-app/createos-sandbox/internal/ca/crl"
	"github.com/NodeOps-app/createos-sandbox/internal/mtlsclient"
)

const (
	computerVNCFirstPort = 5900
	computerVNCLastPort  = 5907
)

// Config carries everything the server needs at construction time.
type Config struct {
	Addr string
	// Outbound auth to host is mTLS via TLS* below; no JWT path remains.
	DomainSuffix  string
	MaxConcurrent int
	PositiveTTL   time.Duration
	NegativeTTL   time.Duration
	// Required outbound mTLS material for control requests and host tunnels.
	// These paths do not configure TLS on the inbound HTTP listener.
	TLSCertPath string
	TLSKeyPath  string
	TLSCAPath   string
	// ControlURLs maps region → that region's control internal mTLS base
	// URL. Enables wake-on-request: a hit on a paused sandbox's public URL
	// POSTs a wake to the control for the sandbox's own region. At least
	// one nonempty endpoint is required for route lookup at construction.
	ControlURLs map[string]string
}

// Server is the ingress HTTP server.
type Server struct {
	cfg    Config
	routes *controlRouteClient
	cache  *cache
	cap    *concurrencyCap
	hostRE *regexp.Regexp
	// sf collapses concurrent cache-miss control lookups for the same
	// sandbox into one request (cache stampede guard).
	sf singleflight.Group
	// waker fires wake-on-request resumes at control. New always wires it;
	// a nil value is handled defensively by serveWake.
	waker *waker
	// outboundTLS is the client-side mTLS config used when dialing
	// hosts via OpenIngressTunnel. New requires this configuration. Client
	// certificates can reload during handshakes; the CA bundle is loaded once.
	outboundTLS *tls.Config
	// crlFetcher is the control-backed revocation cache; its
	// VerifyPeerCertificate is wired into outboundTLS so dials to a
	// revoked host fail the handshake. nil when mTLS is off.
	crlFetcher *crl.Fetcher
}

// New constructs an ingress server with required control endpoints and mTLS.
// It validates the domain suffix and fetches the initial revocation set before
// returning. Routing is not restricted to the ingress process's own region.
func New(cfg Config) (*Server, error) {
	if strings.TrimSpace(cfg.DomainSuffix) == "" {
		return nil, errors.New("domain-suffix must be set")
	}
	pattern := `^([0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{26})-(\d{1,5})\.` +
		regexp.QuoteMeta(cfg.DomainSuffix) + `$`
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("compile host regex: %w", err)
	}
	if cfg.PositiveTTL <= 0 {
		cfg.PositiveTTL = 30 * time.Second
	}
	if cfg.NegativeTTL <= 0 {
		cfg.NegativeTTL = 5 * time.Second
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 64
	}
	if len(cfg.ControlURLs) == 0 {
		return nil, errors.New("control_urls must contain at least one regional control endpoint")
	}
	s := &Server{
		cfg:    cfg,
		cache:  newCache(cfg.PositiveTTL, cfg.NegativeTTL),
		cap:    newConcurrencyCap(cfg.MaxConcurrent),
		hostRE: re,
	}
	// Require outbound mTLS for control lookups and host tunnels.
	tlsCfg, err := mtlsclient.NewTLSConfig(cfg.TLSCertPath, cfg.TLSKeyPath, cfg.TLSCAPath)
	if err != nil {
		return nil, fmt.Errorf("ingress outbound tls: %w", err)
	}
	if tlsCfg == nil {
		return nil, errors.New("ingress requires tls_cert, tls_key, and tls_ca for control and host mTLS")
	}
	controlBases := sortedControlURLs(cfg.ControlURLs)
	if len(controlBases) == 0 {
		return nil, errors.New("control_urls must contain at least one non-empty endpoint")
	}
	crlTransport := http.DefaultTransport.(*http.Transport).Clone()
	crlTransport.TLSClientConfig = tlsCfg.Clone()
	s.crlFetcher = crl.New(controlBases[0], &http.Client{
		Timeout:   10 * time.Second,
		Transport: crlTransport,
	})
	s.crlFetcher.Logger = log.WithField("component", "crl")
	crlCtx, cancelCRL := context.WithTimeout(context.Background(), 10*time.Second)
	err = s.crlFetcher.Refresh(crlCtx)
	cancelCRL()
	if err != nil {
		return nil, fmt.Errorf("initial control CRL fetch: %w", err)
	}
	tlsCfg.VerifyPeerCertificate = s.crlFetcher.VerifyPeerCertificate
	// Resumed sessions skip VerifyPeerCertificate; this runs on both.
	tlsCfg.VerifyConnection = crl.VerifyConnectionFunc(s.crlFetcher.VerifyPeerCertificate)
	s.outboundTLS = tlsCfg
	controlTransport := http.DefaultTransport.(*http.Transport).Clone()
	controlTransport.TLSClientConfig = tlsCfg.Clone()
	controlClient := &http.Client{Timeout: 10 * time.Second, Transport: controlTransport}
	s.routes = newControlRouteClient(controlBases, controlClient)

	// Reuse the ingress-role mTLS client to wake sandboxes through their
	// owning region's control endpoint.
	s.waker = newWaker(cfg.ControlURLs, controlClient)
	log.Infof("[ingress] control-backed routing and wake enabled for regions %v", regionKeys(cfg.ControlURLs))
	return s, nil
}

func regionKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Run starts the HTTP server and blocks until ctx is done or a signal arrives.
func (s *Server) Run(ctx context.Context) error {
	if s.crlFetcher != nil {
		s.crlFetcher.Interval = 30 * time.Second
		go s.crlFetcher.Run(ctx)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success","data":{"up":true}}`))
	})
	mux.HandleFunc("/", s.handle)

	srv := &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-sigCh:
		case <-ctx.Done():
		}
		sdCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sdCtx)
	}()

	// Ingress is fronted by nginx-ingress (plain HTTP inside the cluster),
	// so the inbound listener stays plain HTTP. The TLS keypair is used
	// only for outbound mTLS to control and host tunnel endpoints.
	log.WithContext(ctx).Infof("[ingress] listening on %s suffix=%s outbound_mtls=%v",
		s.cfg.Addr, s.cfg.DomainSuffix, s.outboundTLS != nil)

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// resolved is the parsed-and-validated routing decision.
type resolved struct {
	sbID  string
	port  int
	route ingressRoute
}

// resolve runs hostname parse → cache → control → validation. Returns an
// HTTP status code on failure. On the success path it has neither
// acquired the concurrency cap nor opened the tunnel — those happen in
// handle() so the failure paths stay cheap.
func (s *Server) resolve(hostHeader string) (*resolved, int, string) {
	host := hostHeader
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil, http.StatusBadRequest, "Missing Host header."
	}
	m := s.hostRE.FindStringSubmatch(host)
	if m == nil {
		return nil, http.StatusBadRequest,
			"That URL shape isn't valid for this service.\n\n" +
				"Expected: <sandbox-ulid>-<port>." + s.cfg.DomainSuffix
	}
	ulid := strings.ToLower(m[1])
	port, err := strconv.Atoi(m[2])
	if err != nil || port < 1 || port > 65535 {
		return nil, http.StatusBadRequest, "Port in the URL must be between 1 and 65535."
	}
	// Public ingress must not expose infrastructure or authentication-bypass
	// ports. SSH belongs behind the key-authenticated gateway; 1023-1029 are
	// guest-agent services; and 5900-5907 are unauthenticated raw x11vnc
	// listeners. Token-protected noVNC remains available on 6080-6087.
	if port == 22 ||
		(port >= 1023 && port <= 1029) ||
		(port >= computerVNCFirstPort && port <= computerVNCLastPort) {
		return nil, http.StatusForbidden, "This port is not available through public ingress."
	}
	sbID := "sb-" + ulid

	// Cache hit?
	if route, ok, hit := s.cache.get(sbID); hit {
		if !ok {
			return nil, http.StatusNotFound, "No sandbox matches this URL."
		}
		if status, msg := s.validate(route); status != 0 {
			return nil, status, msg
		}
		return &resolved{sbID: sbID, port: port, route: route}, 0, ""
	}

	// Cache miss: single-flight the control lookup so a burst of concurrent
	// requests for the same URL (e.g. the waking page's <meta refresh>
	// across tabs) collapses into ONE GetIngressRoute — the leader queries
	// + fills the cache, followers get its result. The 5s timeout rides a
	// background context (not the caller's) so one cancelled request can't
	// abort the shared lookup for everyone.
	v, err, _ := s.sf.Do(sbID, func() (any, error) {
		lookupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		route, err := s.routes.Get(lookupCtx, sbID)
		if err != nil {
			return ingressRoute{}, err
		}
		if route.ID == "" {
			s.cache.putNegative(sbID)
			return route, nil
		}
		// running → full posTTL; transitional (paused/resuming/…) → short
		// negTTL so a wake→running flip is seen within a poll cycle.
		ttl := s.cache.posTTL
		if route.Status != "running" {
			ttl = s.cache.negTTL
		}
		s.cache.putPositive(sbID, route, ttl)
		return route, nil
	})
	if err != nil {
		log.Warnf("[ingress] GetIngressRoute(%s): %v", sbID, err)
		return nil, http.StatusBadGateway,
			"Sandbox lookup is temporarily failing on our side. Please retry."
	}
	route := v.(ingressRoute)
	if route.ID == "" {
		return nil, http.StatusNotFound, "No sandbox matches this URL."
	}
	if status, msg := s.validate(route); status != 0 {
		// Negative-cache disabled ingress and terminal sandbox states.
		if status == http.StatusNotFound {
			s.cache.putNegative(sbID)
		}
		return nil, status, msg
	}
	return &resolved{sbID: sbID, port: port, route: route}, 0, ""
}

// validate maps a route to (HTTP status, user-facing reason). status=0
// means accept. The reason is a short plain-text message the user sees
// in their browser/curl output — generic, no CLI/tool-specific advice.
//
// Region intentionally not checked here. The sandbox's `ingress_enabled`
// flag is the access gate (owner opt-in); region was previously a
// routing optimization back when DNS pinned `*.<region>.<suffix>` to a
// regional ingress. With the WG mesh spanning regions and a single
// `*.<suffix>` wildcard, any ingress can serve any sandbox.
func (s *Server) validate(route ingressRoute) (int, string) {
	if !route.IngressEnabled {
		return http.StatusNotFound, "Public access is disabled for this sandbox."
	}
	switch route.Status {
	case "destroyed", "destroying", "failed":
		return http.StatusNotFound, "This sandbox no longer exists (" + route.Status + ")."
	case "paused", "pausing", "resuming", "creating", "forking":
		// Wakeable / starting. handle() serves the waking page (and, for
		// `paused`, kicks a resume) instead of a bare error. Status 0 lets
		// resolve() carry the route through; the branch is in handle().
		return 0, ""
	case "running":
		if route.BandwidthCapped {
			return http.StatusServiceUnavailable, "This sandbox has exhausted its bandwidth quota."
		}
		if route.HostAddr == "" {
			return http.StatusBadGateway, "This sandbox isn't bound to a host yet. Try again in a moment."
		}
		return 0, ""
	default:
		return http.StatusServiceUnavailable, "This sandbox isn't running (" + route.Status + ")."
	}
}

// upstreamErrorMessage describes common application-level causes of a proxy
// failure. A validated route is cached metadata, not proof of reachability;
// tunnel, host, or network failures can also reach this error path.
func upstreamErrorMessage(port int) string {
	return fmt.Sprintf(
		"Couldn't reach a service on port %d inside the sandbox.\n\n"+
			"Common causes:\n"+
			"  • nothing is listening on port %d\n"+
			"  • the service is bound to 127.0.0.1 only — bind on 0.0.0.0 to receive ingress traffic\n"+
			"  • the service crashed",
		port, port)
}

// handle is the catch-all for every non-/healthz request.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	r2 := r.Clone(r.Context())

	res, status, msg := s.resolve(r.Host)
	if status != 0 {
		writePlain(w, status, msg)
		logTunnelClose(strings.TrimPrefix(r.Host, ""), 0, status, time.Since(start), 0)
		return
	}

	// Wake-on-request: the sandbox exists + is ingress-enabled but isn't
	// running (paused / pausing / resuming / creating / forking). Serve the
	// interstitial and kick a resume if it's paused — don't try to proxy.
	if res.route.Status != "running" {
		s.serveWake(w, r, res, start)
		return
	}

	if !s.cap.Acquire(res.sbID) {
		w.Header().Set("Retry-After", "1")
		writePlain(w, http.StatusTooManyRequests,
			"Too many concurrent requests in flight for this sandbox.\nRetry in a moment.")
		logTunnelClose(res.sbID, res.port, http.StatusTooManyRequests, time.Since(start), 0)
		return
	}
	defer s.cap.Release(res.sbID)

	// Sanitize headers BEFORE handing the request to the proxy.
	sanitizeRequest(r2, res.port)

	// Build a one-shot reverse proxy with a transport that opens our
	// upgrade-tunnel for every dial. The tunnel is point-to-point
	// (request-scoped) so connection reuse across distinct sandboxes
	// is impossible.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return OpenIngressTunnel(ctx, res.route.HostAddr, res.sbID, res.port, s.outboundTLS)
		},
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: 0,
		IdleConnTimeout:     0,
		DisableKeepAlives:   true,
	}

	// Use a counter ResponseWriter to capture body byte count for the log.
	cw := &countingWriter{ResponseWriter: w}
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = "http"
			r.Out.URL.Host = "localhost:" + strconv.Itoa(res.port)
			r.Out.Host = r.Out.URL.Host
			// Rewrite (unlike the deprecated Director) strips X-Forwarded-*
			// off the outbound request before running, so restore the values
			// sanitizeRequest already derived from the trusted Cf-Connecting-Ip.
			// r.SetXForwarded() is unusable here: it would overwrite
			// X-Forwarded-Proto with the plaintext ingress-nginx hop's scheme
			// and X-Forwarded-Host with the raw inbound Host.
			for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host"} {
				if v := r.In.Header.Get(h); v != "" {
					r.Out.Header.Set(h, v)
				}
			}
			// Director's implicit append of the immediate peer, preserved.
			if peerIP, _, err := net.SplitHostPort(r.In.RemoteAddr); err == nil {
				if prior := r.Out.Header.Get("X-Forwarded-For"); prior != "" {
					peerIP = prior + ", " + peerIP
				}
				r.Out.Header.Set("X-Forwarded-For", peerIP)
			}
		},
		Transport:      transport,
		ModifyResponse: sanitizeResponse,
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			log.Warnf("[ingress] proxy error sb=%s port=%d: %v", res.sbID, res.port, err)
			writePlain(rw, http.StatusBadGateway, upstreamErrorMessage(res.port))
		},
	}
	rp.ServeHTTP(cw, r2)

	st := cw.status
	if st == 0 {
		st = http.StatusOK
	}
	logTunnelClose(res.sbID, res.port, st, time.Since(start), cw.bytes)
}

// sanitizeResponse keeps sandbox cookies scoped to the exact public ingress
// hostname that issued them. All sandbox hostnames share DomainSuffix, so a
// guest-controlled `Domain=<suffix>` attribute would otherwise cause the
// browser to send that cookie to sibling sandboxes. Preserve the cookie and
// all of its other attributes; removing Domain converts it to a host-only
// cookie. Other response headers belong to the sandbox application and remain
// untouched.
func sanitizeResponse(resp *http.Response) error {
	values := resp.Header.Values("Set-Cookie")
	if len(values) == 0 {
		return nil
	}

	resp.Header.Del("Set-Cookie")
	for _, value := range values {
		parts := strings.Split(value, ";")
		kept := parts[:1]
		for _, part := range parts[1:] {
			name := strings.TrimSpace(part)
			if i := strings.IndexByte(name, '='); i >= 0 {
				name = strings.TrimSpace(name[:i])
			}
			if strings.EqualFold(name, "domain") {
				continue
			}
			kept = append(kept, part)
		}
		resp.Header.Add("Set-Cookie", strings.Join(kept, ";"))
	}
	return nil
}

// sanitizeRequest applies the request-side header policy. Called BEFORE
// proxy.Rewrite so the cleaning lands on the cloned request the proxy
// transports — never on the original client request.
// IMPORTANT: Cf-Connecting-Ip is taken at face value. control ingress
// MUST be deployed behind Cloudflare (or another trusted L7 LB) such
// that direct access to its socket is blocked at the network layer.
// If anyone can reach this listener bypassing CF, they spoof
// X-Forwarded-For for upstream logs / audit trails. The standard
// deployment uses a ClusterIP Service + Ingress with CF in front; do
// not expose the ingress pod on a public LoadBalancer.
func sanitizeRequest(req *http.Request, port int) {
	xff := strings.TrimSpace(req.Header.Get("Cf-Connecting-Ip"))

	// Read what we need from Cf-* / forwarded-host BEFORE dropping them.
	origHost := req.Host

	// Strip caller-supplied tokens, internal headers, and every header
	// commonly used by load balancers / proxies to convey "the real client
	// IP" — a sandbox app that trusts X-Real-Ip / True-Client-Ip / RFC 7239
	// Forwarded for IP-based access control could otherwise be tricked into
	// believing a request originated from localhost or some internal range.
	// Only X-Forwarded-For is rewritten below from the trusted Cf-Connecting-
	// Ip; everything else gets dropped wholesale.
	for h := range req.Header {
		hl := strings.ToLower(h)
		if strings.HasPrefix(hl, "cf-") ||
			strings.HasPrefix(hl, "x-createos-") ||
			strings.HasPrefix(hl, "x-internal-") ||
			// ingress-nginx renames the user's X-Forwarded-For into
			// X-Original-Forwarded-For and adds its own. Without this
			// strip, an attacker injecting X-Forwarded-For: 10.0.0.1
			// at the edge ends up with that exact value visible to
			// the backend under x-original-forwarded-for — defeating
			// the whole point of rewriting X-Forwarded-For.
			strings.HasPrefix(hl, "x-original-") ||
			hl == "x-admin-token" ||
			hl == "x-forwarded-for" ||
			hl == "x-real-ip" ||
			hl == "true-client-ip" ||
			hl == "forwarded" ||
			// Proxy-Authorization is hop-by-hop per RFC 7235 and must
			// not propagate to the in-VM service — strip unconditionally.
			hl == "proxy-authorization" {
			req.Header.Del(h)
		}
		// Preserve application Authorization headers (Basic/Bearer). Tunnel
		// authentication uses the ingress client certificate, separately from
		// the HTTP request delivered to the sandbox application.
	}

	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	if origHost != "" {
		req.Header.Set("X-Forwarded-Host", origHost)
	}
}

// countingWriter intercepts WriteHeader / Write so the log line can
// surface the upstream status + body byte count.
type countingWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (c *countingWriter) WriteHeader(s int) {
	if c.status == 0 {
		c.status = s
	}
	c.ResponseWriter.WriteHeader(s)
}

func (c *countingWriter) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	n, err := c.ResponseWriter.Write(b)
	c.bytes += int64(n)
	return n, err
}

// writePlain emits a short plaintext error. Never echoes upstream
// internals (no host_addr, no error chain, no headers).
func writePlain(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg + "\n"))
}

// Hijack exposes the underlying connection for WebSocket upgrades.
// Without this, httputil.ReverseProxy can't switch protocols.
func (c *countingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := c.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("upstream ResponseWriter does not implement http.Hijacker")
}

// Flush supports streaming responses (SSE, chunked transfer).
func (c *countingWriter) Flush() {
	if fl, ok := c.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

// Compile-time assertion that countingWriter still implements the
// minimal interface required by ReverseProxy.
var _ http.ResponseWriter = (*countingWriter)(nil)
