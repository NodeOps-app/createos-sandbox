package userapikey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ExternalValidator validates a user-supplied token by calling an
// upstream auth service. On 200 it returns the resolved user identity;
// on 401/403/404 it returns ErrExternalKeyInvalid (token is unknown or
// revoked upstream). Any other status / network error returns a wrapped
// error so the caller can decide whether to fail-closed or retry.
//
// authType tells the validator which header the user sent under, so the
// outbound call to upstream can forward the same header verbatim — the
// upstream auth service treats the four token types (api_key /
// access_token / auth_token) as separate populations.
type ExternalValidator interface {
	Validate(ctx context.Context, authType, token string, extraHeaders map[string]string) (*ExternalKey, error)
}

// ExternalKey is the projection of the upstream response we care about.
// Mirrors the upstream auth service's /v1/users/me payload — extras tolerated.
type ExternalKey struct {
	UserID    string
	Name      string
	ExpiresAt *time.Time // upstream's expiredAt; honored as upper-bound on cache TTL
}

// ErrExternalKeyInvalid is returned for HTTP 401 / 403 / 404 (token
// unknown / expired / revoked). Distinct from network errors so the
// resolver can treat it as "definitely-not-a-user" and DELETE any stale
// cached row, instead of "fail-closed transiently".
var ErrExternalKeyInvalid = errors.New("external auth: token not found, expired, or revoked")

// HTTPExternalValidator hits the upstream auth endpoint:
//
//	GET <BaseURL>/v1/users/me
//	<forwarded auth header>: <user-supplied token>
//
// authType ↔ header mapping:
//
//	api_key       → X-Api-Key
//	access_token  → X-Access-Token   (also used for Authorization: Bearer)
//	auth_token    → X-Auth-Token
//	mpp_agent     → X-Agent-Token    (+ X-Agent-Shared-Key, both forwarded from request)
//
// Expected 200 body shape (extras ignored):
//
//	{"status":"success","data":{"id":..,"username":..,"email":..,"suspendedAt":..}}
//
// 401/403/404 → ErrExternalKeyInvalid. Any other status → wrapped error.
type HTTPExternalValidator struct {
	BaseURL string       // e.g. https://auth.example.com
	Client  *http.Client // nil → 5s timeout default
}

// NewHTTPExternalValidator constructs a validator with a sane default
// client (5s timeout). BaseURL is required; empty disables the
// validator (caller must short-circuit).
func NewHTTPExternalValidator(baseURL string) *HTTPExternalValidator {
	return &HTTPExternalValidator{
		BaseURL: baseURL,
		Client:  &http.Client{Timeout: 5 * time.Second},
	}
}

// HeaderFor returns the upstream header name corresponding to authType.
// Panics on unknown types — authType is set by our own code from the
// AuthType* constants, so a miss here is a programmer error, not a
// runtime input. Failing loud beats silently forwarding as X-Api-Key
// and having the backend accept for the wrong reason.
func HeaderFor(authType string) string {
	switch authType {
	case AuthTypeAPIKey:
		return "X-Api-Key"
	case AuthTypeAccessToken:
		return "X-Access-Token"
	case AuthTypeAuthToken:
		return "X-Auth-Token"
	case AuthTypeMPPAgent:
		return "X-Agent-Token"
	default:
		panic("userapikey: HeaderFor called with unknown authType: " + authType)
	}
}

// extEnvelope mirrors the upstream /v1/users/me response.
type extEnvelope struct {
	Status string  `json:"status"`
	Data   userRow `json:"data"`
}

type userRow struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	Username    *string    `json:"username"`
	DisplayName *string    `json:"displayName"`
	SuspendedAt *time.Time `json:"suspendedAt"`
}

func (v *HTTPExternalValidator) Validate(ctx context.Context, authType, token string, extraHeaders map[string]string) (*ExternalKey, error) {
	if v.BaseURL == "" {
		return nil, fmt.Errorf("external validator: BaseURL not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.BaseURL+"/v1/users/me", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(HeaderFor(authType), token)
	for k, val := range extraHeaders {
		req.Header.Set(k, val)
	}
	req.Header.Set("Accept", "application/json")

	c := v.Client
	if c == nil {
		c = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("external validator: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// fall through
	case http.StatusNotFound, http.StatusUnauthorized, http.StatusForbidden:
		return nil, ErrExternalKeyInvalid
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("external validator: status=%d body=%q", resp.StatusCode, string(body))
	}

	var env extEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, fmt.Errorf("external validator: decode: %w", err)
	}
	if env.Status != "success" || env.Data.ID == "" {
		return nil, ErrExternalKeyInvalid
	}
	if env.Data.SuspendedAt != nil {
		return nil, ErrExternalKeyInvalid
	}
	// Synthesise a display label so the api_keys.name column has
	// something human-readable. Email > username > displayName > empty.
	name := env.Data.Email
	if name == "" && env.Data.Username != nil {
		name = *env.Data.Username
	}
	if name == "" && env.Data.DisplayName != nil {
		name = *env.Data.DisplayName
	}
	return &ExternalKey{
		UserID:    env.Data.ID,
		Name:      name,
		ExpiresAt: nil, // /v1/users/me has no per-token TTL; rely on our externalTTL config
	}, nil
}
