package ingress

import (
	"context"
	_ "embed"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// wakingPage is the self-contained interstitial served while a paused
// sandbox resumes. It carries a <meta refresh> so the browser reloads the
// same URL every few seconds — once the sandbox flips to running, that
// reload proxies straight through to the app.
//
//go:embed waking.html
var wakingPage []byte

// serveWakingPage writes the interstitial with no-store so browsers and
// intermediaries never cache it in place of the real app.
func serveWakingPage(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	h.Set("Retry-After", "3")
	// 200, not 503: some browsers won't honor <meta refresh> on error
	// responses, which would strand the user on the waking page forever.
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(wakingPage)
}

// serveWake handles a hit on a sandbox that exists + is ingress-enabled but
// isn't running. It kicks a resume when paused, then serves the waking page
// to browser navigations (503 + Retry-After to everything else).
func (s *Server) serveWake(w http.ResponseWriter, r *http.Request, res *resolved, start time.Time) {
	// Feature off (no control wiring) — preserve the old plain 503.
	if s.waker == nil {
		writePlain(w, http.StatusServiceUnavailable, startingMessage(res.route.Status))
		logTunnelClose(res.sbID, res.port, http.StatusServiceUnavailable, time.Since(start), 0)
		return
	}
	// Only `paused` needs a kick; other states are already transitioning.
	// Route the wake to the control that owns the sandbox's region.
	if res.route.Status == "paused" {
		s.waker.trigger(res.sbID, res.route.Region)
	}
	if wantsHTML(r) {
		serveWakingPage(w)
		logTunnelClose(res.sbID, res.port, http.StatusOK, time.Since(start), int64(len(wakingPage)))
		return
	}
	w.Header().Set("Retry-After", "3")
	writePlain(w, http.StatusServiceUnavailable, "Sandbox is waking up. Retry in a moment.")
	logTunnelClose(res.sbID, res.port, http.StatusServiceUnavailable, time.Since(start), 0)
}

func startingMessage(status string) string {
	if status == "paused" || status == "pausing" {
		return "This sandbox is paused."
	}
	return "This sandbox is still starting (" + status + ")."
}

// wantsHTML reports whether this is a browser navigation that should get the
// waking page. Assets/XHR/API calls (or any non-GET) get a 503 + Retry-After
// instead — serving them HTML would corrupt the response.
func wantsHTML(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// waker fires wake-on-request resumes at control, coalescing bursts so N
// concurrent hits on a paused URL trigger at most one request per debounce
// window (control's resume CAS is the backstop; this just spares control
// the redundant calls).
type waker struct {
	urls     map[string]string // region → control internal base URL
	client   *http.Client
	interval time.Duration

	mu   sync.Mutex
	last map[string]time.Time
}

func newWaker(controlURLs map[string]string, client *http.Client) *waker {
	urls := make(map[string]string, len(controlURLs))
	for r, u := range controlURLs {
		urls[r] = strings.TrimRight(u, "/")
	}
	return &waker{
		urls:     urls,
		client:   client,
		interval: 8 * time.Second,
		last:     make(map[string]time.Time),
	}
}

// trigger fires a wake for id at the control that owns the sandbox's region,
// unless one fired within the debounce window. Fire-and-forget: it never
// blocks the request serving the waking page.
func (wk *waker) trigger(id, region string) {
	base, ok := wk.urls[region]
	if !ok {
		log.Warnf("[ingress-wake] %s: no control URL for region %q — skipping wake", id, region)
		return
	}
	now := time.Now()
	wk.mu.Lock()
	if t, ok := wk.last[id]; ok && now.Sub(t) < wk.interval {
		wk.mu.Unlock()
		return
	}
	wk.last[id] = now
	// Remove expired debounce entries opportunistically. Entries from the
	// current window may still exceed this threshold; it is not a hard cap.
	if len(wk.last) > 4096 {
		for k, t := range wk.last {
			if now.Sub(t) > wk.interval {
				delete(wk.last, k)
			}
		}
	}
	wk.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// PathEscape the id: base comes from operator config, but id is
		// parsed off the request hostname — escaping keeps a malformed id
		// from reshaping the path it lands on.
		url := base + "/v1/internal/sandboxes/" + neturl.PathEscape(id) + "/wake"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
		if err != nil {
			log.Warnf("[ingress-wake] %s build req: %v", id, err)
			return
		}
		resp, err := wk.client.Do(req)
		if err != nil {
			log.Warnf("[ingress-wake] %s POST wake: %v", id, err)
			return
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 {
			log.Warnf("[ingress-wake] %s wake returned %d", id, resp.StatusCode)
			return
		}
		log.Infof("[ingress-wake] %s wake triggered", id)
	}()
}
