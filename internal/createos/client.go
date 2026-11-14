// Package createos talks to the external createos credit/plan API. It
// shares its signing format with the billing webhook client — both sign
// HTTP bodies with the same HMAC-SHA256 over "<unix-ts>.<raw-body>"
// and use the X-CreateOS-Timestamp / X-CreateOS-Signature header pair.
//
// Today the two endpoints we call:
//
//	POST /v1/sandboxes/current-plan              {user_id}        → plan + credit amount
//	POST /v1/sandboxes/egress-bandwidth-recharge {user_id, sandbox_id, gib} → deduct credits, return debited amount
package createos

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/hmacsign"
)

// Client is the createos HTTP client. One per process; safe for
// concurrent use (http.Client is goroutine-safe). Zero BaseURL disables
// the integration — every call returns ErrDisabled and the auto-top-up
// trigger is expected to short-circuit.
type Client struct {
	BaseURL string
	Secret  []byte
	HTTP    *http.Client
}

// New constructs a Client with sensible defaults. Empty url returns a
// Client whose calls all error with ErrDisabled — callers short-circuit
// on len(BaseURL)==0 rather than dispatching.
func New(baseURL, secret string) *Client {
	return &Client{
		BaseURL: baseURL,
		Secret:  []byte(secret),
		HTTP: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:    16,
				IdleConnTimeout: 30 * time.Second,
			},
		},
	}
}

// ErrDisabled is returned when BaseURL is empty (createos integration
// not configured). Callers should treat this as "feature off" and skip.
var ErrDisabled = fmt.Errorf("createos client disabled (no base url)")

// CurrentPlanRequest is the body of POST /v1/sandboxes/current-plan.
type CurrentPlanRequest struct {
	UserID string `json:"user_id"`
}

// PlanLimit and Plan match createos's response shape. We only need
// a subset for the auto-top-up trigger (the credit amount) but keep
// the full structure so callers can surface the plan to the user.
type PlanLimit struct {
	MaxProjects             int  `json:"maxProjects"`
	MaxActiveDeployments    int  `json:"maxActiveDeployments"`
	MaxActiveEnvironments   int  `json:"maxActiveEnvironments"`
	MinDeploymentResources  *Res `json:"minDeploymentResources,omitempty"`
	MaxDeploymentResources  *Res `json:"maxDeploymentResources,omitempty"`
	MinEnvironmentResources *Res `json:"minEnvironmentResources,omitempty"`
	MaxEnvironmentResources *Res `json:"maxEnvironmentResources,omitempty"`
	MaxEnvironmentReplicas  int  `json:"maxEnvironmentReplicas"`
	MinEnvironmentReplicas  int  `json:"minEnvironmentReplicas"`
	MaxBuildTimeInMinutes   int  `json:"maxBuildTimeInMinutes"`
	MinBuildResources       *Res `json:"minBuildResources,omitempty"`
	MaxBuildResources       *Res `json:"maxBuildResources,omitempty"`
	MaxParallelBuilds       int  `json:"maxParallelBuilds"`
	MaxDomains              int  `json:"maxDomains"`
	MaxApis                 int  `json:"maxApis"`

	MaxSandboxes              *int     `json:"maxSandboxes,omitempty"`
	MaxSandboxesPerDay        *int     `json:"maxSandboxesPerDay,omitempty"`
	MaxSandboxNetworks        *int     `json:"maxSandboxNetworks,omitempty"`
	MaxSandboxNetworksPerDay  *int     `json:"maxSandboxNetworksPerDay,omitempty"`
	MaxSandboxDisks           *int     `json:"maxSandboxDisks,omitempty"`
	MaxSandboxDisksPerDay     *int     `json:"maxSandboxDisksPerDay,omitempty"`
	MaxSandboxTemplates       *int     `json:"maxSandboxTemplates,omitempty"`
	MaxSandboxTemplatesPerDay *int     `json:"maxSandboxTemplatesPerDay,omitempty"`
	SandboxSizes              []string `json:"sandboxSizes,omitempty"`
	MaxDiskSizeAllowedInGib   *int     `json:"maxDiskSizeAllowedInGib,omitempty"`
	MaxDevices                *int     `json:"maxDevices,omitempty"`
}

// Res is the {memoryMib, cpuMillicores} pair createos uses for every
// min/max resource bound on a plan.
type Res struct {
	MemoryMib     int `json:"memoryMib"`
	CPUMillicores int `json:"cpuMillicores"`
}

type Plan struct {
	Plan                 string    `json:"plan"`
	PlanName             string    `json:"planName"`
	SubscriptionID       string    `json:"subscriptionId"`
	Amount               float64   `json:"amount"`
	LifetimeCreditAmount float64   `json:"lifetimeCreditAmount"`
	LifetimeDebitAmount  float64   `json:"lifetimeDebitAmount"`
	LifetimeTopupAmount  float64   `json:"lifetimeTopupAmount"`
	CreditMultiplier     float64   `json:"creditMultiplier"`
	Limit                PlanLimit `json:"limit"`
}

// CurrentPlanResponse mirrors createos's JSend-shaped success body.
// Amount is the remaining credit balance — the key field the
// auto-top-up trigger gates on (> 0 means we can deduct).
type CurrentPlanResponse struct {
	User         *PlanUser   `json:"user,omitempty"`
	Amount       float64     `json:"amount"`
	Plan         Plan        `json:"plan"`
	Subscription interface{} `json:"subscription"`
}

// PlanUser is the profile returned by the signed user-ID plan lookup.
type PlanUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// RechargeRequest is the body of POST /v1/sandboxes/egress-bandwidth-recharge.
// Gib is fractional (e.g. 1.5 = 1.5 GiB worth of egress). SandboxID is
// required by createos so the debit can be reconciled against the specific
// VM it grew quota for.
type RechargeRequest struct {
	UserID    string  `json:"user_id"`
	SandboxID string  `json:"sandbox_id"`
	Gib       float64 `json:"gib"`
}

// RechargeResponse is what createos returns on a successful deduction.
// Amount is the credits debited (already deducted from the user's
// balance); Gib echoes back the requested allowance.
type RechargeResponse struct {
	Amount      float64 `json:"amount"`
	Description string  `json:"description"`
	Gib         float64 `json:"gib"`
}

// GetCurrentPlan fetches the user's active plan + remaining credit.
// Returns ErrDisabled if the client wasn't configured with a BaseURL.
func (c *Client) GetCurrentPlan(ctx context.Context, userID string) (*CurrentPlanResponse, error) {
	var out CurrentPlanResponse
	if err := c.post(ctx, "/v1/sandboxes/current-plan",
		CurrentPlanRequest{UserID: userID}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RechargeEgressBandwidth deducts credits from the user's balance in
// exchange for `gib` GiB of egress bandwidth allowance for the given
// sandbox. Caller is expected to then bump the sandbox's
// bandwidth_quota_bytes locally so the new allowance takes effect.
func (c *Client) RechargeEgressBandwidth(ctx context.Context, userID, sandboxID string, gib float64) (*RechargeResponse, error) {
	var out RechargeResponse
	if err := c.post(ctx, "/v1/sandboxes/egress-bandwidth-recharge",
		RechargeRequest{UserID: userID, SandboxID: sandboxID, Gib: gib}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// post is the signed-POST helper used by every endpoint. Marshals
// `in` to JSON, signs the body + timestamp, dispatches, decodes the
// JSend envelope's `data` into `out`.
func (c *Client) post(ctx context.Context, path string, in, out interface{}) error {
	if c.BaseURL == "" {
		return ErrDisabled
	}
	body, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	now := time.Now().UTC()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CreateOS-Timestamp", strconv.FormatInt(now.Unix(), 10))
	req.Header.Set("X-CreateOS-Signature", hmacsign.Sign(c.Secret, body, now))

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("post %s: %w", path, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %d: %s", path, resp.StatusCode, truncate(respBody, 256))
	}

	var env struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(respBody, &env); err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	if env.Status != "success" {
		return fmt.Errorf("createos returned status=%q: %s", env.Status, truncate(respBody, 256))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("decode data: %w", err)
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
