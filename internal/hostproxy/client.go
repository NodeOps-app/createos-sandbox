package hostproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NodeOps-app/sandbox/internal/httpx"
)

// APIClient speaks to createos's HTTP API to resolve a source IP into
// a sandbox and its egress allowlist. The HTTP client should be built
// with the host's mTLS cert/key/ca so control's by-ip route accepts
// it as role=host. NewAPIClient takes a pre-built *http.Client so the
// caller controls the TLS bundle.
type APIClient struct {
	BaseURL string
	HTTP    *http.Client
}

// NewAPIClient builds a client. baseURL is control's internal mTLS
// address (e.g. https://control:8443). httpClient must carry the
// proxy's client cert when control's by-ip route is mTLS-gated.
func NewAPIClient(baseURL string, httpClient *http.Client) *APIClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 3 * time.Second}
	}
	return &APIClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    httpClient,
	}
}

// jsendResp is the decoded shape of a JSend response from createos.
type jsendResp struct {
	Status  string          `json:"status"`
	Data    json.RawMessage `json:"data"`
	Message string          `json:"message"`
}

type egressData struct {
	ID     string   `json:"id"`
	Egress []string `json:"egress"`
}

// FetchEgress calls control's internal DB lookup for the sandbox at ip. On
// JSend "success" it returns an *Entry with parsed rules. On "fail" (unknown
// IP) it returns (nil, nil). On "error" or transport errors it returns an error.
func (c *APIClient) FetchEgress(ctx context.Context, ip string) (*Entry, error) {
	u := fmt.Sprintf("%s/v1/internal/db/sandboxes/by-ip/%s", c.BaseURL, url.PathEscape(ip))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	httpx.SetRequestIDHeader(ctx, req)
	// Authentication rides on the mTLS handshake — c.HTTP carries the
	// proxy's client cert, control's by-ip route verifies the SPIFFE
	// URI from the cert. No bearer token needed.
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jr jsendResp
	if err := json.NewDecoder(resp.Body).Decode(&jr); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	switch jr.Status {
	case "success":
		var d egressData
		if len(jr.Data) > 0 {
			if err := json.Unmarshal(jr.Data, &d); err != nil {
				return nil, fmt.Errorf("decode data: %w", err)
			}
		}
		rules, err := ParseList(d.Egress)
		if err != nil {
			return nil, fmt.Errorf("parse rules: %w", err)
		}
		return &Entry{SandboxID: d.ID, Rules: rules}, nil
	case "fail":
		return nil, nil
	case "error":
		return nil, fmt.Errorf("api error: %s", jr.Message)
	default:
		return nil, fmt.Errorf("unexpected status %q (http %d)", jr.Status, resp.StatusCode)
	}
}
