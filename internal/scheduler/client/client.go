package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/NodeOps-app/sandbox/internal/httpx"
	schedapi "github.com/NodeOps-app/sandbox/internal/scheduler/api"
)

// Config configures the HTTP client to the scheduler.
type Config struct {
	BaseURL      string        // e.g. http://scheduler:9100
	HTTP         *http.Client  // nil -> sane default
	ProbePeriod  time.Duration // default 1s
	ProbeFailMax int32         // default 3 — consecutive failures before unhealthy
}

// Client is a typed HTTP client to the control scheduler service.
// Wraps schedule plus a background liveness probe whose result is
// readable atomically by the create handler so the circuit breaker doesn't
// pay retry latency when the scheduler is known-down.
type Client struct {
	cfg    Config
	http   *http.Client
	logger Logger

	healthy atomic.Bool
	epoch   atomic.Int64
	fails   atomic.Int32
	lastOK  atomic.Int64 // unix ms
	lastErr atomic.Pointer[string]
}

// Logger is a tiny adapter so we don't pull in slog here — the
// rest of the control plane uses sirupsen/logrus, but the only thing we
// log is debug-level probe state, so it's just a callable.
type Logger func(format string, args ...any)

// New constructs a client. Run() must be called separately
// to start the probe loop.
func New(cfg Config, log Logger) *Client {
	if cfg.ProbePeriod == 0 {
		cfg.ProbePeriod = time.Second
	}
	if cfg.ProbeFailMax == 0 {
		cfg.ProbeFailMax = 3
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 2 * time.Second}
	}
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Client{cfg: cfg, http: cfg.HTTP, logger: log}
}

// ProbeSync runs one probe synchronously and returns whether the
// scheduler is healthy. Used by short-lived processes (sweep CronJob)
// that can't afford to wait for the background ticker before the first
// Schedule() call. Long-running processes use Run() instead.
func (c *Client) ProbeSync(ctx context.Context) bool {
	c.probe(ctx)
	return c.healthy.Load()
}

// Run blocks until ctx is cancelled, ticking the probe every ProbePeriod.
func (c *Client) Run(ctx context.Context) {
	t := time.NewTicker(c.cfg.ProbePeriod)
	defer t.Stop()
	c.probe(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.probe(ctx)
		}
	}
}

// Healthy reports the cached probe state.
func (c *Client) Healthy() bool { return c.healthy.Load() }

// Epoch returns the most recently observed scheduler epoch.
func (c *Client) Epoch() int64 { return c.epoch.Load() }

// LastOK is the unix-ms timestamp of the most recent successful probe.
func (c *Client) LastOK() int64 { return c.lastOK.Load() }

// HealthSnapshot returns the operator-visible view.
func (c *Client) HealthSnapshot() HealthSnapshot {
	last := c.lastOK.Load()
	out := HealthSnapshot{
		Reachable:           c.healthy.Load(),
		Epoch:               c.epoch.Load(),
		ConsecutiveFailures: c.fails.Load(),
		LastOkMsAgo:         time.Now().UnixMilli() - last,
	}
	if last == 0 {
		out.LastOkMsAgo = -1
	}
	if e := c.lastErr.Load(); e != nil {
		out.LastError = *e
	}
	return out
}

// HealthSnapshot is what the operator endpoint returns.
type HealthSnapshot struct {
	Reachable           bool   `json:"reachable"`
	Epoch               int64  `json:"epoch"`
	ConsecutiveFailures int32  `json:"consecutive_failures"`
	LastOkMsAgo         int64  `json:"last_ok_ms_ago"`
	LastError           string `json:"last_error,omitempty"`
}

// probe hits /readyz and updates atomics.
func (c *Client) probe(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, 500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+"/readyz", nil)
	if err != nil {
		c.markFail(err.Error())
		return
	}
	httpx.SetRequestIDHeader(ctx, req)
	// Scheduler runs unauthenticated on its cluster-internal port — see
	// scheduler/http.go for the rationale.
	resp, err := c.http.Do(req)
	if err != nil {
		c.markFail(err.Error())
		return
	}
	defer resp.Body.Close()
	// /readyz returns JSend: 200 + {"status":"success","data":{ready:true,...}} when ready,
	// 503 + {"status":"fail","data":{ready:false,...}} when not. Either shape carries
	// the typed body in `data` — decode that path.
	envelope := struct {
		Status string                  `json:"status"`
		Data   schedapi.ReadyzResponse `json:"data"`
	}{}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		c.markFail("decode readyz: " + err.Error())
		return
	}
	if resp.StatusCode != http.StatusOK || envelope.Status != "success" || !envelope.Data.Ready {
		c.markFail(fmt.Sprintf("readyz status=%d state=%s", resp.StatusCode, envelope.Data.State))
		return
	}
	body := envelope.Data
	if e := body.Epoch; e < c.epoch.Load() {
		// epoch went backward — reject this probe; will recover on next tick
		// if the scheduler stabilises on a higher epoch.
		c.markFail(fmt.Sprintf("epoch regression %d -> %d", c.epoch.Load(), e))
		return
	}
	c.epoch.Store(body.Epoch)
	c.fails.Store(0)
	c.lastOK.Store(time.Now().UnixMilli())
	c.healthy.Store(true)
	c.lastErr.Store(nil)
}

func (c *Client) markFail(reason string) {
	n := c.fails.Add(1)
	c.lastErr.Store(&reason)
	// Always log the first ~5 consecutive failures from startup so a never-healthy
	// breaker is diagnosable; afterwards only log the healthy→unhealthy transition.
	if n <= 5 {
		c.logger("[scheduler-client] probe fail #%d: %s", n, reason)
	}
	if n >= c.cfg.ProbeFailMax {
		if c.healthy.Swap(false) {
			c.logger("[scheduler-client] unhealthy: %s (after %d failures)", reason, n)
		}
	}
}

// ─── public RPCs ───────────────────────────────────────────────────────────

// ErrSchedulerUnavailable is returned when the circuit breaker is open.
var ErrSchedulerUnavailable = errors.New("scheduler unavailable")

// ErrNoCapacity is a definitive scheduling rejection, not an uncertain RPC failure.
var ErrNoCapacity = errors.New("scheduler has no capacity")

// Schedule calls POST /v1/schedule with retry+jitter on 5xx/network errors.
func (c *Client) Schedule(ctx context.Context, req schedapi.ScheduleRequest) (*schedapi.ScheduleResponse, error) {
	if !c.healthy.Load() {
		return nil, ErrSchedulerUnavailable
	}
	const maxAttempts = 5
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		resp, retry, err := c.schedule(ctx, req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !retry {
			return nil, err
		}
		// Exponential backoff with full jitter: 1..(2^attempt * 50)ms, cap 1500.
		base := 50 << attempt
		if base > 1500 {
			base = 1500
		}
		sleep := time.Duration(rand.IntN(base)+1) * time.Millisecond
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(sleep):
		}
	}
	return nil, fmt.Errorf("schedule: %d attempts: %w", maxAttempts, lastErr)
}

// schedule does one attempt. Returns (resp, retryable, err).
func (c *Client) schedule(ctx context.Context, req schedapi.ScheduleRequest) (*schedapi.ScheduleResponse, bool, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, false, fmt.Errorf("marshal: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/v1/schedule", bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpx.SetRequestIDHeader(ctx, httpReq)
	// Scheduler runs unauthenticated — see scheduler/http.go.
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, true, err
	}
	defer resp.Body.Close()
	// Decode the envelope twice so we can pull either the typed Data on
	// success or the ErrorResponse-shaped Data on JSend "fail".
	buf, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		env := struct {
			Status string                    `json:"status"`
			Data   schedapi.ScheduleResponse `json:"data"`
		}{}
		if err := json.Unmarshal(buf, &env); err != nil {
			return nil, false, fmt.Errorf("decode: %w (body=%s)", err, string(buf))
		}
		if env.Status != "success" {
			return nil, false, fmt.Errorf("unexpected envelope status=%q (body=%s)", env.Status, string(buf))
		}
		return &env.Data, false, nil
	}
	failEnv := struct {
		Status  string                 `json:"status"`
		Data    schedapi.ErrorResponse `json:"data"`
		Message string                 `json:"message"`
	}{}
	_ = json.Unmarshal(buf, &failEnv)
	msg := failEnv.Message
	if msg == "" {
		msg = failEnv.Data.Error
	}
	if msg == "" {
		msg = string(buf)
	}
	if resp.StatusCode == http.StatusServiceUnavailable && failEnv.Status == "fail" && failEnv.Data.Reason == schedapi.ReasonNoCapacity {
		return nil, false, ErrNoCapacity
	}
	retry := resp.StatusCode == http.StatusServiceUnavailable ||
		resp.StatusCode == http.StatusBadGateway ||
		resp.StatusCode == http.StatusGatewayTimeout
	return nil, retry, fmt.Errorf("status=%d msg=%s", resp.StatusCode, msg)
}

// Note: there is no Release or UpsertHost on this client, by design.
// The scheduler does not accept any callbacks or acks from the control
// plane or hosts — it learns about state changes by polling the
// sandboxes table every 1s.
