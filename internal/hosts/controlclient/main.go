package controlclient

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/NodeOps-app/sandbox/internal/httpx"
	"github.com/NodeOps-app/sandbox/internal/httpx/types"
	"github.com/NodeOps-app/sandbox/internal/mtlsclient"
	"github.com/NodeOps-app/sandbox/internal/proto"
	"github.com/NodeOps-app/sandbox/internal/utils"
	"github.com/NodeOps-app/sandbox/models"
)

const queryHostID = "host_id"

// Client proxies every persistence method to the control plane's
// /v1/internal/db/* endpoints. Hosts get one of these instead of opening
// their own DB session, so they need no DB credentials or network access
// to Postgres. Control's /v1/internal/db/* routes are mTLS-only — the
// caller's client cert authenticates each request.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient constructs a remote repo. baseURL is the control plane URL
// (without trailing slash). For mTLS-enabled deployments use
// NewClientWithTLS instead.
func NewClient(baseURL string) *Client {
	// Custom Transport instead of http.DefaultTransport — Go's default
	// caps MaxIdleConnsPerHost at 2, so under any concurrent burst the
	// 3rd+ in-flight call opens a fresh TCP+TLS handshake (several round
	// trips each). The host hits this path on every create/exec/destroy
	// via control's /v1/internal/db/* RPCs,
	// so the cost shows up directly as `db.insert` time on the host.
	//
	// Tuning: 100 idle conns/host comfortably exceeds peak per-VM call
	// fan-out (3-4 RPCs per VM × tens of concurrent VMs), keeping the
	// pool warm.
	//
	// HTTP/2 disabled deliberately. The earlier `ForceAttemptHTTP2: true`
	// tickled a Go stdlib bug under concurrent burst:
	//   panic: id (267) <= evictCount (675)
	//   golang.org/x/net/http2/hpack.(*headerFieldTable).idToIndex
	// (golang/go#56020, #55357). Many goroutines piling concurrent
	// requests onto the single shared HTTP/2 connection drives the
	// HPACK dynamic-table state inconsistent, the assertion fires,
	// the host process exits, and burst traffic targeting that host
	// observes `connection refused` until systemd restarts serve.
	//
	// HTTP/1.1 with the keep-alive pool above achieves nearly the
	// same perf (multiple TCP conns instead of mux, but steady-state
	// per-request latency is identical) and is panic-free under our
	// burst rates.
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 30 * time.Second, Transport: transport},
	}
}

// NewClientWithTLS is identical to NewClient but additionally installs a
// TLS client config built from the supplied paths. When any TLS path is
// empty, falls back to plain HTTP — the returned client is byte-equivalent
// to NewClient(baseURL).
//
// When TLS is active and baseURL still carries an http:// scheme, the
// scheme is rewritten to https:// so the resulting HTTP requests
// actually go through the TLS handshake.
func NewClientWithTLS(baseURL, tlsCertPath, tlsKeyPath, tlsCAPath string) (*Client, error) {
	return NewClientWithTLSAndVerify(baseURL, tlsCertPath, tlsKeyPath, tlsCAPath, nil)
}

// NewClientWithTLSAndVerify is NewClientWithTLS plus an extra peer-cert
// callback — typically the CRL fetcher's VerifyPeerCertificate — so
// connections to a revoked control fail the handshake.
func NewClientWithTLSAndVerify(
	baseURL, tlsCertPath, tlsKeyPath, tlsCAPath string,
	verify func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error,
) (*Client, error) {
	base := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
	}

	useTLS := tlsCertPath != "" && tlsKeyPath != "" && tlsCAPath != ""

	var transport *http.Transport
	if useTLS {
		tr, err := mtlsclient.NewTransportWithVerify(tlsCertPath, tlsKeyPath, tlsCAPath, base, verify)
		if err != nil {
			return nil, err
		}
		transport = tr
	} else {
		transport = base
	}

	url := strings.TrimRight(baseURL, "/")
	if useTLS && strings.HasPrefix(url, "http://") {
		url = "https://" + strings.TrimPrefix(url, "http://")
	}

	return &Client{
		baseURL: url,
		http:    &http.Client{Timeout: 30 * time.Second, Transport: transport},
	}, nil
}

// HTTP returns the underlying *http.Client so callers that need to make
// ad-hoc requests (with mTLS already wired) can reuse the same transport
// without spinning up a second TLS handshake pool.
func (r *Client) HTTP() *http.Client { return r.http }

// BaseURL returns the resolved base URL (with http→https flip applied
// when mTLS is enabled), so ad-hoc callers can build absolute URLs.
func (r *Client) BaseURL() string { return r.baseURL }

func (r *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.baseURL+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	httpx.SetRequestIDHeader(ctx, req)
	// End-user id (set by the inbound control→host call) rides through to
	// control's DB proxy as a plain header. Under mTLS the connection is
	// already authenticated as "host" by the client cert.
	if uid := utils.UserIDFromContext(ctx); uid != "" {
		utils.SetUserIDHeader(req, uid)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if resp.StatusCode == http.StatusNotFound {
		return errNotFound
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("control %s %s: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}
	if out == nil {
		return nil
	}
	// Unwrap the JSend envelope: {"status":"success","data": <out>}
	var env struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(bodyBytes, &env); err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	if env.Status != "success" {
		return fmt.Errorf("control %s %s: non-success: %s", method, path, string(bodyBytes))
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return nil
	}
	return json.Unmarshal(env.Data, out)
}

// errNotFound is the sentinel returned by remote 404s. Repository contract
// for Get/GetByIP is "(nil, nil) on miss"; remote handlers map miss → 404,
// so we have to translate back here.
var errNotFound = fmt.Errorf("not found")

// ── Repository implementation ──────────────────────────────────────────────

func (r *Client) Bootstrap(ctx context.Context) error {
	return r.do(ctx, http.MethodPost, "/v1/internal/db/bootstrap", nil, nil)
}

// RelayState fetches the per-tick reconcile state for one relay
// (sessions + BPF policy pairs). The relay polls this every 5s instead
// of holding a direct Postgres DSN. Authz at control: caller's SPIFFE
// host_id MUST equal `hostID` AND `hostID`'s row must be role='relay'.
func (r *Client) RelayState(ctx context.Context, hostID string) (*proto.RelayStateResp, error) {
	var out proto.RelayStateResp
	if err := r.do(ctx, http.MethodGet,
		"/v1/internal/relay-state?"+queryHostID+"="+url.QueryEscape(hostID),
		nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *Client) Insert(ctx context.Context, rec models.Sandbox) error {
	return r.do(ctx, http.MethodPost, "/v1/internal/db/sandboxes", rec, nil)
}

func (r *Client) Get(ctx context.Context, id string) (*models.Sandbox, error) {
	var rec models.Sandbox
	if err := r.do(ctx, http.MethodGet, "/v1/internal/db/sandboxes/"+id, nil, &rec); err != nil {
		if err == errNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &rec, nil
}

func (r *Client) GetByIP(ctx context.Context, ip string) (*models.Sandbox, error) {
	var rec models.Sandbox
	if err := r.do(ctx, http.MethodGet, "/v1/internal/db/sandboxes/by-ip/"+ip, nil, &rec); err != nil {
		if err == errNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &rec, nil
}

func (r *Client) List(ctx context.Context, host, userID, status string, limit int) ([]models.Sandbox, error) {
	q := "?limit=" + strconv.Itoa(limit)
	if host != "" {
		q += "&host=" + host
	}
	if userID != "" {
		q += "&user_id=" + userID
	}
	if status != "" {
		q += "&status=" + status
	}
	var recs []models.Sandbox
	if err := r.do(ctx, http.MethodGet, "/v1/internal/db/sandboxes"+q, nil, &recs); err != nil {
		return nil, err
	}
	return recs, nil
}

func (r *Client) MarkDestroyed(ctx context.Context, id string, at time.Time, note *string) error {
	return r.do(ctx, http.MethodPatch, "/v1/internal/db/sandboxes/"+id+"/destroyed",
		proto.ControlMarkDestroyedReq{At: at, Note: note}, nil)
}

func (r *Client) MarkFailed(ctx context.Context, id string, errText *string, at time.Time) error {
	return r.do(ctx, http.MethodPatch, "/v1/internal/db/sandboxes/"+id+"/failed",
		proto.ControlMarkFailedReq{ErrText: errText, At: at}, nil)
}

// MarkFailedFromCreatingCAS asks control to atomically flip a row from
// 'creating' → 'failed', conditional on host_id matching. Returns
// (true, nil) when the CAS hit, (false, nil) when status had already
// moved (e.g. our reconcile raced a stale handler that completed
// before SIGTERM). Callers MUST gate any local cleanup side-effects
// on flipped=true so we don't tear down a slot still in use.
func (r *Client) MarkFailedFromCreatingCAS(ctx context.Context, id, hostID string, errText *string, at time.Time) (bool, error) {
	var resp proto.ControlMarkFailedFromCreatingCASResp
	if err := r.do(ctx, http.MethodPatch, "/v1/internal/db/sandboxes/"+id+"/failed-from-creating",
		proto.ControlMarkFailedFromCreatingCASReq{HostID: hostID, ErrText: errText, At: at}, &resp); err != nil {
		return false, err
	}
	return resp.Flipped, nil
}

func (r *Client) ListRunningIDs(ctx context.Context, host string) ([]string, error) {
	var resp struct {
		IDs []string `json:"ids"`
	}
	path := "/v1/internal/db/sandboxes/running-ids?host=" + url.QueryEscape(host)
	if err := r.do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return resp.IDs, nil
}

func (r *Client) ListLiveIDs(ctx context.Context, host string) ([]string, error) {
	var resp struct {
		IDs []string `json:"ids"`
	}
	path := "/v1/internal/db/sandboxes/live-ids?host=" + url.QueryEscape(host)
	if err := r.do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return resp.IDs, nil
}

func (r *Client) SetSandboxHost(ctx context.Context, id string, hostID *string) error {
	return r.do(ctx, http.MethodPatch, "/v1/internal/db/sandboxes/"+id+"/host",
		proto.ControlSetSandboxHostReq{HostID: hostID}, nil)
}

func (r *Client) SetSSHPubkeys(ctx context.Context, id string, keys []string) error {
	return r.do(ctx, http.MethodPatch, "/v1/internal/db/sandboxes/"+id+"/ssh-pubkeys",
		proto.ControlSetSSHPubkeysReq{Keys: keys}, nil)
}

func (r *Client) SetEgress(ctx context.Context, id string, rules []string) error {
	return r.do(ctx, http.MethodPatch, "/v1/internal/db/sandboxes/"+id+"/egress",
		proto.ControlSetEgressReq{Rules: rules}, nil)
}

func (r *Client) SetEnvs(ctx context.Context, id string, envs map[string]string) error {
	return r.do(ctx, http.MethodPatch, "/v1/internal/db/sandboxes/"+id+"/envs", map[string]any{"envs": envs}, nil)
}

func (r *Client) SetDiskMib(ctx context.Context, id string, diskMib int64) error {
	return r.do(ctx, http.MethodPatch, "/v1/internal/db/sandboxes/"+id+"/disk",
		proto.ControlSetDiskMibReq{DiskMib: diskMib}, nil)
}

func (r *Client) SetRuntime(ctx context.Context, id string, apiSock, containerID, overlayPath *string, fcPid int) error {
	return r.do(ctx, http.MethodPatch, "/v1/internal/db/sandboxes/"+id+"/runtime",
		proto.ControlSetRuntimeReq{APISock: apiSock, ContainerID: containerID, FCPid: fcPid, OverlayPath: overlayPath}, nil)
}

func (r *Client) SetBandwidthQuota(ctx context.Context, id string, quota int64) error {
	return r.do(ctx, http.MethodPatch, "/v1/internal/db/sandboxes/"+id+"/bandwidth/quota",
		proto.ControlBandwidthValueReq{Value: quota}, nil)
}

// ResetSandboxDiskStatus flips every attachment for a sandbox back to
// 'pending' — called from the pause path so the surfaced status doesn't
// lie about disks that are about to be unmounted.
func (r *Client) ResetSandboxDiskStatus(ctx context.Context, id string) error {
	return r.do(ctx, http.MethodPost,
		"/v1/internal/db/sandboxes/"+id+"/disks/reset", nil, nil)
}

// SetSandboxDiskStatus PATCHes the per-attachment mount_status (+ error)
// for a single disk attachment. Driven by the host's disk status poller.
func (r *Client) SetSandboxDiskStatus(ctx context.Context, id, diskID, mountPath, status, errMsg string) error {
	return r.do(ctx, http.MethodPatch,
		"/v1/internal/db/sandboxes/"+id+"/disks/"+diskID+"/status",
		proto.ControlSetDiskStatusReq{MountPath: mountPath, Status: status, Error: errMsg}, nil)
}

// ResolveSandboxDisks fetches the decrypted disk bundle for a sandbox
// the calling host owns. Used by rehydrate paths to repopulate MMDS
// after a serve restart. Returns the agent-bound MMDS shape directly.
func (r *Client) ResolveSandboxDisks(ctx context.Context, id string) ([]proto.MMDSDisk, error) {
	var resp struct {
		Disks []proto.MMDSDisk `json:"disks"`
	}
	if err := r.do(ctx, http.MethodGet,
		"/v1/internal/db/sandboxes/"+id+"/disks/resolved", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Disks, nil
}

func (r *Client) SetBandwidthUsed(ctx context.Context, id string, used int64) error {
	return r.do(ctx, http.MethodPatch, "/v1/internal/db/sandboxes/"+id+"/bandwidth/used",
		proto.ControlBandwidthValueReq{Value: used}, nil)
}

func (r *Client) SetBandwidthCapped(ctx context.Context, id string, capped bool) error {
	return r.do(ctx, http.MethodPatch, "/v1/internal/db/sandboxes/"+id+"/bandwidth/capped",
		proto.ControlBandwidthCappedReq{Value: capped}, nil)
}

func (r *Client) SetIngressEnabled(ctx context.Context, id string, enabled bool) error {
	return r.do(ctx, http.MethodPatch, "/v1/internal/db/sandboxes/"+id+"/ingress",
		proto.ControlSetIngressEnabledReq{Enabled: enabled}, nil)
}

func (r *Client) GetIngressRoute(ctx context.Context, id string) (models.IngressRoute, error) {
	var resp proto.ControlIngressRouteResp
	if err := r.do(ctx, http.MethodGet, "/v1/internal/db/sandboxes/"+id+"/ingress-route", nil, &resp); err != nil {
		if err == errNotFound {
			return models.IngressRoute{}, nil
		}
		return models.IngressRoute{}, err
	}
	return models.IngressRoute{
		ID:              resp.ID,
		HostAddr:        resp.HostAddr,
		Status:          resp.Status,
		IngressEnabled:  resp.IngressEnabled,
		Region:          resp.Region,
		BandwidthCapped: resp.BandwidthCapped,
	}, nil
}

func (r *Client) UpdateBandwidthIngress(ctx context.Context, id string, bytes int64) error {
	return r.do(ctx, http.MethodPatch, "/v1/internal/db/sandboxes/"+id+"/bandwidth/ingress",
		proto.ControlBandwidthValueReq{Value: bytes}, nil)
}

func (r *Client) UpsertHost(ctx context.Context, h models.Host) error {
	return r.do(ctx, http.MethodPost, "/v1/internal/db/hosts", h, nil)
}

func (r *Client) HeartbeatHost(ctx context.Context, id string, inUse, vmCount int, status string, diskUsedMib int64, at time.Time) error {
	return r.do(ctx, http.MethodPatch, "/v1/internal/db/hosts/"+id+"/heartbeat",
		proto.ControlHeartbeatHostReq{InUseMib: inUse, VMCount: vmCount, Status: status, DiskUsedMib: diskUsedMib, At: at}, nil)
}

func (r *Client) ListHosts(ctx context.Context) ([]models.Host, error) {
	var hs []models.Host
	if err := r.do(ctx, http.MethodGet, "/v1/internal/db/hosts", nil, &hs); err != nil {
		return nil, err
	}
	return hs, nil
}

func (r *Client) GetHost(ctx context.Context, id string) (*models.Host, error) {
	var h models.Host
	if err := r.do(ctx, http.MethodGet, "/v1/internal/db/hosts/"+id, nil, &h); err != nil {
		if err == errNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &h, nil
}

// Rootfs catalog metadata is only read by control today (host/ingress/proxy
// don't need it). We stub them through to control via the same
// /v1/internal/db proxy in case a future caller needs them. If the
// routes aren't mounted there yet
// these will return a 404; that's fine — nothing on the host side calls them.
func (r *Client) GetRootfsMetadata(ctx context.Context, name string) (*models.RootfsCatalog, error) {
	var rec models.RootfsCatalog
	if err := r.do(ctx, http.MethodGet, "/v1/internal/db/rootfs-catalog/"+name, nil, &rec); err != nil {
		if err == errNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &rec, nil
}

func (r *Client) ListRootfsMetadata(ctx context.Context) ([]models.RootfsCatalog, error) {
	var recs []models.RootfsCatalog
	if err := r.do(ctx, http.MethodGet, "/v1/internal/db/rootfs-catalog", nil, &recs); err != nil {
		return nil, err
	}
	return recs, nil
}

// ── pause / resume / fork ─────────────────────────────────────────────
//
// Each method posts a small JSON body to control's /v1/internal/db/pause/*
// endpoint. Control routes call into the underlying pgRepo. Bodies are
// kept minimal — we never re-encode the full models.Sandbox.

func (r *Client) MarkPausing(ctx context.Context, id string, at time.Time) (string, error) {
	var resp proto.CASStatusResp
	if err := r.do(ctx, http.MethodPost, "/v1/internal/db/pause/mark-pausing",
		proto.ControlMarkPausingReq{ID: id, At: at}, &resp); err != nil {
		return "", err
	}
	return resp.Status, nil
}

func (r *Client) MarkPaused(ctx context.Context, id string, manifest json.RawMessage,
	uri, cachedHostID *string, cachedUntil, pausedAt time.Time) (string, error) {
	var resp proto.CASStatusResp
	if err := r.do(ctx, http.MethodPost, "/v1/internal/db/pause/mark-paused",
		proto.ControlMarkPausedReq{ID: id, PausedAt: pausedAt, URI: uri, Manifest: manifest,
			CachedHostID: cachedHostID, CachedUntil: cachedUntil}, &resp); err != nil {
		return "", err
	}
	return resp.Status, nil
}

func (r *Client) MarkPauseRolledBack(ctx context.Context, id string, errMsg *string, at time.Time) (string, error) {
	var resp proto.CASStatusResp
	if err := r.do(ctx, http.MethodPost, "/v1/internal/db/pause/mark-rolled-back",
		proto.ControlMarkPauseRolledBackReq{ID: id, Err: errMsg, At: at}, &resp); err != nil {
		return "", err
	}
	return resp.Status, nil
}

func (r *Client) MarkResumed(ctx context.Context, id string, ip, mac, apiSock, containerID, overlayPath *string,
	fcPid int, runningAt time.Time, host string) (string, error) {
	var resp proto.CASStatusResp
	if err := r.do(ctx, http.MethodPost, "/v1/internal/db/pause/mark-resumed",
		proto.ControlMarkResumedReq{ID: id, IP: ip, MAC: mac, APISock: apiSock, ContainerID: containerID,
			OverlayPath: overlayPath, FCPid: fcPid, RunningAt: runningAt, Host: host}, &resp); err != nil {
		return "", err
	}
	return resp.Status, nil
}

func (r *Client) MarkResumeFailed(ctx context.Context, id, host string, errMsg *string, at time.Time) (string, error) {
	var resp proto.CASStatusResp
	if err := r.do(ctx, http.MethodPost, "/v1/internal/db/pause/mark-resume-failed",
		proto.ControlMarkResumeFailedReq{ID: id, Host: host, Err: errMsg, At: at}, &resp); err != nil {
		return "", err
	}
	return resp.Status, nil
}

func (r *Client) MarkDestroying(ctx context.Context, id string) (string, error) {
	var resp proto.CASStatusResp
	if err := r.do(ctx, http.MethodPost, "/v1/internal/db/pause/mark-destroying",
		proto.ControlIDReq{ID: id}, &resp); err != nil {
		return "", err
	}
	return resp.Status, nil
}

func (r *Client) ClearLocalCache(ctx context.Context, id, host string) error {
	return r.do(ctx, http.MethodPost, "/v1/internal/db/pause/clear-local-cache",
		proto.ControlClearLocalCacheReq{ID: id, Host: host}, nil)
}

func (r *Client) ListPausing(ctx context.Context, host string) ([]string, error) {
	var ids []string
	if err := r.do(ctx, http.MethodGet,
		"/v1/internal/db/pause/list-pausing?host="+url.QueryEscape(host), nil, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

func (r *Client) ListPaused(ctx context.Context, cachedHost string) ([]string, error) {
	var ids []string
	if err := r.do(ctx, http.MethodGet,
		"/v1/internal/db/pause/list-paused?cached_host="+url.QueryEscape(cachedHost), nil, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

func (r *Client) ListStuckResuming(ctx context.Context, cutoff time.Time, region string) ([]models.Sandbox, error) {
	var recs []models.Sandbox
	if err := r.do(ctx, http.MethodGet,
		"/v1/internal/db/pause/list-stuck-resuming?cutoff="+url.QueryEscape(cutoff.Format(time.RFC3339Nano))+
			"&region="+url.QueryEscape(region),
		nil, &recs); err != nil {
		return nil, err
	}
	return recs, nil
}

func (r *Client) LocalCacheCandidates(ctx context.Context, host string) ([]models.LocalCacheCandidate, error) {
	var recs []models.LocalCacheCandidate
	if err := r.do(ctx, http.MethodGet,
		"/v1/internal/db/pause/local-cache-candidates?host="+url.QueryEscape(host),
		nil, &recs); err != nil {
		return nil, err
	}
	return recs, nil
}

func (r *Client) KeepLocalCache(ctx context.Context, id string) (bool, error) {
	var resp proto.ControlLocalCacheStateResp
	if err := r.do(ctx, http.MethodGet,
		"/v1/internal/db/pause/local-cache-state/"+url.PathEscape(id), nil, &resp); err != nil {
		return false, err
	}
	return resp.Keep, nil
}

func (r *Client) Close() {} // no resources to release

// ─── Templates feature ──────────────────────────────────────────────
//
// Most template ops are control-plane-local (admin endpoints, builder
// service) and not proxied. Hosts only need the host_cached_templates
// upserts/deletes (both go through dedicated /v1/internal/db/* paths)
// plus GetTemplate so they can read the row's sha256 to verify the
// downloaded ext4.

func (r *Client) GetTemplate(ctx context.Context, id string) (*models.Template, error) {
	var rec models.Template
	if err := r.do(ctx, http.MethodGet,
		"/v1/internal/db/templates/"+url.PathEscape(id), nil, &rec); err != nil {
		if errors.Is(err, errNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &rec, nil
}

func (r *Client) UpsertHostCachedTemplate(ctx context.Context, hostID, tplID string, cachedUntil time.Time) error {
	return r.do(ctx, http.MethodPost, "/v1/internal/db/host-cached-templates/upsert",
		proto.ControlUpsertHostCachedTemplateReq{HostID: hostID, TplID: tplID, CachedUntil: cachedUntil}, nil)
}

func (r *Client) DeleteHostCachedTemplate(ctx context.Context, hostID, tplID string) error {
	return r.do(ctx, http.MethodDelete,
		"/v1/internal/db/host-cached-templates/"+url.PathEscape(hostID)+"/"+url.PathEscape(tplID),
		nil, nil)
}

func (r *Client) ListHostCachedTemplates(ctx context.Context, hostID string) ([]models.HostCachedTemplate, error) {
	var recs []models.HostCachedTemplate
	if err := r.do(ctx, http.MethodGet,
		"/v1/internal/db/host-cached-templates?host="+url.QueryEscape(hostID),
		nil, &recs); err != nil {
		return nil, err
	}
	return recs, nil
}

func (r *Client) HostCachedTemplateHasActiveSandbox(ctx context.Context, hostID, tplID string) (int, error) {
	var resp struct {
		Count int `json:"count"`
	}
	q := "/v1/internal/db/host-cached-templates/" + url.PathEscape(hostID) + "/" + url.PathEscape(tplID) + "/active-count"
	if err := r.do(ctx, http.MethodGet, q, nil, &resp); err != nil {
		return 0, err
	}
	return resp.Count, nil
}

// ─── host registration + heartbeat ────────────────────────────────────
//
// Register always carries the bootstrap token. When this Client has TLS
// configured it also presents the host leaf: control requires that matching
// mTLS identity when an existing host row is re-registered. First enrollment
// may still run without a client cert because no host identity exists yet.
// Heartbeat is mTLS like every other RPC but lives on Client so we have one
// HTTP transport for all control traffic.

// Register sends the initial registration to control. Returns the
// HostRegisterResp (subnet CIDR + underlay IP, when overlay networking
// is on). bootstrapToken gates this single endpoint.
func (r *Client) Register(ctx context.Context, req proto.ControlHostRegisterReq, bootstrapToken string) (proto.HostRegisterResp, error) {
	var out proto.HostRegisterResp
	buf, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		r.baseURL+types.PathHostRegister, bytes.NewReader(buf))
	if err != nil {
		return out, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if bootstrapToken != "" {
		httpReq.Header.Set(proto.HeaderBootstrapToken, bootstrapToken)
	}
	httpx.SetRequestIDHeader(ctx, httpReq)
	resp, err := r.http.Do(httpReq)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return out, fmt.Errorf("register: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var env struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return out, fmt.Errorf("decode register response: %w", err)
	}
	if env.Status != "success" {
		return out, fmt.Errorf("register: non-success: %s", string(body))
	}
	if len(env.Data) > 0 && string(env.Data) != "null" {
		_ = json.Unmarshal(env.Data, &out)
	}
	return out, nil
}

// Heartbeat sends one heartbeat tick over the mTLS-authenticated transport.
// The response carries the resolved shape catalog so callers can detect
// operator-driven changes and re-prewarm. The OKResp shape that this
// endpoint used to return is still wire-compatible — fields the host
// doesn't understand are silently dropped, and the {"ok":true} envelope
// the legacy decoder expected is gone (the wrapped JSend envelope is the
// stable contract). When called against a legacy control plane that
// returns no shapes, resp.Shapes is nil and the caller leaves its
// catalog untouched.
func (r *Client) Heartbeat(ctx context.Context, req proto.ControlHostHeartbeatReq) (proto.HostHeartbeatResp, error) {
	var out proto.HostHeartbeatResp
	if err := r.do(ctx, http.MethodPost, types.PathHostHeartbeat, req, &out); err != nil {
		return out, err
	}
	return out, nil
}
