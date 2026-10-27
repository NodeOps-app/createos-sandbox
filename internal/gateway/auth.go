package gateway

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"

	"github.com/NodeOps-app/sandbox/internal/httpx"
)

// validSandboxIDRe matches the gateway's view of a sandbox id: `sb-` prefix
// followed by a 26-char Crockford-base32 ULID (case-insensitive — Crockford
// excludes I, L, O, U). An attacker-controlled SSH username is checked
// against this BEFORE any URL is constructed; anything outside this shape
// is rejected to keep CRLF / slashes / dotdot / control bytes out of the
// HTTP request line built by openTunnel and the URL in fetchSandbox.
var validSandboxIDRe = regexp.MustCompile(`^sb-[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{26}$`)

// sandboxPeek is what we unmarshal out of the control-plane JSend
// response. Field tags match the raw store.Record (capitalized Go field
// names, no json tags) that the internal DB proxy returns. Callers that
// used the public api.SandboxView shape would fail to populate these.
type sandboxPeek struct {
	ID         string   `json:"id"`
	IP         string   `json:"ip"`
	HostID     string   `json:"host_id"`
	SSHPubkeys []string `json:"ssh_pubkeys"`
	// CreatedBy is the user_id of the sandbox owner. Threaded through
	// to the tunnel JWT's uid claim so the host's requireOwner check
	// passes (fails closed on empty uid since the security pass).
	CreatedBy string `json:"created_by"`
	// Status is checked at auth time so a destroyed/destroying/failed
	// sandbox can't have its lingering ssh_pubkeys honoured. Without
	// this gate, calling DELETE on a sandbox leaves SSH access open
	// until the row is fully reaped — owner-level lifecycle bug.
	Status string `json:"status"`
}

type jsendEnvelope struct {
	Status  string          `json:"status"`
	Data    json.RawMessage `json:"data"`
	Message string          `json:"message"`
}

// authPublicKey is the ssh.ServerConfig PublicKeyCallback. Every auth
// attempt is logged with its outcome.
func (g *Gateway) authPublicKey(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	remote := meta.RemoteAddr().String()
	user := meta.User()
	fp := ssh.FingerprintSHA256(key)

	// Strict format check BEFORE any URL/HTTP construction. SSH usernames
	// are attacker-controlled; without this an entry containing CRLF,
	// slashes, or `..` would land in fetchSandbox's URL and (on success)
	// flow into openTunnel's hand-built HTTP request line.
	// One opaque error string for every failure mode below. Different
	// strings (invalid format, unknown sandbox, key mismatch) let an
	// attacker enumerate valid sandbox IDs by watching the client-side
	// auth-error text. Operator-visible reasons stay in the log lines.
	const opaqueAuthErr = "authentication failed"

	// Per-source-IP rate limit BEFORE any lookup. Closes the timing
	// channel between "real sandbox" (1 DB read) and "invalid format"
	// (O(µs) regex reject) once the bucket is drained.
	if g.authLimiter != nil {
		key := remote
		if tcpAddr, ok := meta.RemoteAddr().(*net.TCPAddr); ok && tcpAddr != nil {
			key = tcpAddr.IP.String()
		}
		if !g.authLimiter.Allow(key) {
			log.Infof("[gateway] auth remote=%s user=%q fp=%s outcome=reject reason=rate limited",
				remote, user, fp)
			return nil, errors.New(opaqueAuthErr)
		}
	}

	if !validSandboxIDRe.MatchString(user) {
		log.Infof("[gateway] auth remote=%s user=%q fp=%s outcome=reject reason=invalid sandbox id format",
			remote, user, fp)
		// Dummy compare so the format-reject path doesn't return
		// noticeably faster than the post-lookup paths.
		incoming := normalizeKey(key)
		_ = subtle.ConstantTimeCompare([]byte(incoming), []byte(incoming))
		return nil, errors.New(opaqueAuthErr)
	}

	sb, err := g.fetchSandbox(context.Background(), user)
	incoming := normalizeKey(key)
	if err != nil {
		log.Infof("[gateway] auth remote=%s user=%s fp=%s outcome=reject reason=%v",
			remote, user, fp, err)
		// Burn a constant-time compare against the caller's own key on
		// the not-found path so timing doesn't trivially separate
		// "sandbox unknown" from "sandbox known, key not in list".
		_ = subtle.ConstantTimeCompare([]byte(incoming), []byte(incoming))
		return nil, errors.New(opaqueAuthErr)
	}

	// Only running sandboxes are SSH-reachable. The DB proxy returns
	// rows for destroyed/destroying/paused/failed sandboxes too —
	// their ssh_pubkeys array is preserved, so without this gate the
	// owner (or anyone holding their key) keeps SSH-tunnelling into a
	// sandbox the API says is gone. Same constant-time dummy compare
	// as the not-found path so timing doesn't separate "wrong status"
	// from "no such sandbox".
	if sb.Status != "running" {
		log.Infof("[gateway] auth remote=%s user=%s fp=%s sandbox=%s outcome=reject reason=status=%q",
			remote, user, fp, sb.ID, sb.Status)
		_ = subtle.ConstantTimeCompare([]byte(incoming), []byte(incoming))
		return nil, errors.New(opaqueAuthErr)
	}

	for _, raw := range sb.SSHPubkeys {
		if allowed := parseAuthorizedKey(raw); allowed != "" && len(allowed) == len(incoming) && subtle.ConstantTimeCompare([]byte(allowed), []byte(incoming)) == 1 {
			// Resolve host_addr now so tunnel-open later can dial the host
			// directly without a second round trip. Failure here = reject
			// the SSH session: without host_addr the tunnel will fail
			// anyway, better to surface it at auth time.
			hostAddr, herr := g.fetchHostAddr(context.Background(), sb.HostID)
			if herr != nil {
				log.Warnf("[gateway] auth remote=%s user=%s fp=%s sandbox=%s outcome=reject reason=%q",
					remote, user, fp, sb.ID, "host lookup failed: "+herr.Error())
				return nil, errors.New(opaqueAuthErr)
			}
			log.Infof("[gateway] auth remote=%s user=%s fp=%s outcome=allow sandbox=%s ip=%s host=%s",
				remote, user, fp, sb.ID, sb.IP, hostAddr)
			return &ssh.Permissions{
				Extensions: map[string]string{
					"sandbox_id":   sb.ID,
					"sandbox_ip":   sb.IP,
					"sandbox_host": sb.HostID,
					"host_addr":    hostAddr,
				},
			}, nil
		}
	}

	log.Infof("[gateway] auth remote=%s user=%s fp=%s outcome=reject reason=%q",
		remote, user, fp, "pubkey not authorized")
	return nil, errors.New(opaqueAuthErr)
}

// fetchSandbox calls the control plane and returns the sandbox record
// (with its authorized pubkeys). Returns an error suitable for surfacing
// to the SSH client — the fingerprint-tagged log line above has the
// detail for operators.
func (g *Gateway) fetchSandbox(ctx context.Context, id string) (*sandboxPeek, error) {
	if id == "" {
		return nil, errors.New("unknown sandbox")
	}
	// Hit the cluster-internal read endpoint — bypasses the per-user
	// scoping on the public API (which would make the gateway see only
	// the sandboxes owned by whatever API key it happened to carry).
	// PathEscape as defense in depth — authPublicKey already validates
	// the sandbox-id format, but fetchSandbox shouldn't depend on the
	// caller having done that.
	reqURL := strings.TrimRight(g.cfg.ControlURL, "/") + "/v1/internal/db/sandboxes/" + url.PathEscape(id)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	httpx.SetRequestIDHeader(ctx, req)
	// Auth is the outbound mTLS client cert (gateway SPIFFE leaf).
	// Control's DB-proxy read route is `MustBePeerRoleMTLS("host",
	// "host-proxy", "gateway")` — JWT path retired.
	resp, err := g.cfg.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("control plane unreachable: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("unknown sandbox")
	}
	if resp.StatusCode >= http.StatusInternalServerError {
		return nil, fmt.Errorf("control plane error %d", resp.StatusCode)
	}

	var env jsendEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("bad control-plane response: %w", err)
	}
	if env.Status != "success" {
		return nil, errors.New("unknown sandbox")
	}
	var peek sandboxPeek
	if err := json.Unmarshal(env.Data, &peek); err != nil {
		return nil, fmt.Errorf("bad sandbox view: %w", err)
	}
	if peek.ID == "" {
		peek.ID = id
	}
	return &peek, nil
}

// fetchHostAddr resolves a host_id to the host's outbound addr via control's
// DB-proxy. Used at SSH auth time so direct-tcpip channels can dial the host
// directly without an extra control round trip.
func (g *Gateway) fetchHostAddr(ctx context.Context, hostID string) (string, error) {
	if hostID == "" {
		return "", errors.New("missing host_id")
	}
	reqURL := strings.TrimRight(g.cfg.ControlURL, "/") + "/v1/internal/db/hosts/" + url.PathEscape(hostID)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	httpx.SetRequestIDHeader(ctx, req)
	resp, err := g.cfg.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("control unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", errors.New("unknown host")
	}
	if resp.StatusCode >= http.StatusInternalServerError {
		return "", fmt.Errorf("control plane error %d", resp.StatusCode)
	}
	var env jsendEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return "", fmt.Errorf("bad host response: %w", err)
	}
	if env.Status != "success" {
		return "", errors.New("unknown host")
	}
	var h struct {
		Addr string `json:"addr"`
	}
	if err := json.Unmarshal(env.Data, &h); err != nil {
		return "", fmt.Errorf("bad host view: %w", err)
	}
	if h.Addr == "" {
		return "", errors.New("host has no addr")
	}
	return h.Addr, nil
}

// normalizeKey returns an ssh.PublicKey in canonical "type base64" form,
// dropping any trailing comment/whitespace. This is the form we compare
// against DB-stored keys after normalizing them too.
func normalizeKey(k ssh.PublicKey) string {
	line := ssh.MarshalAuthorizedKey(k)
	return trimKey(string(line))
}

// parseAuthorizedKey parses a stored authorized_keys entry and returns
// it in canonical "type base64" form. Returns "" on parse failure.
func parseAuthorizedKey(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		return ""
	}
	return trimKey(string(ssh.MarshalAuthorizedKey(k)))
}

// trimKey strips whitespace and any trailing comment to leave only
// "algorithm base64blob".
func trimKey(s string) string {
	s = strings.TrimSpace(s)
	// MarshalAuthorizedKey yields "algo b64\n", no comment — but be safe.
	parts := strings.Fields(s)
	if len(parts) >= 2 {
		return parts[0] + " " + parts[1]
	}
	return s
}
