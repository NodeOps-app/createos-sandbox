package hostrpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/NodeOps-app/sandbox/internal/httpx"
	"github.com/NodeOps-app/sandbox/internal/proto"
	"github.com/NodeOps-app/sandbox/internal/utils"
	"github.com/NodeOps-app/sandbox/models"
)

var ErrResponseTooLarge = errors.New("host response exceeds buffered limit")

// ForwardRequest describes an HTTP request that control proxies to a machine
// host. Body may be streaming; callers retain responsibility for closing it.
type ForwardRequest struct {
	Method         string
	Path           string
	Query          string
	Header         http.Header
	Body           io.Reader
	ContentLength  int64
	UserID         string
	WithoutTimeout bool
}

var proxyHopByHop = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

// Forward sends a client-shaped request to a host while stripping credentials
// and hop-by-hop headers. The returned response body belongs to the caller.
func Forward(ctx context.Context, httpClient *http.Client, host models.Host, in ForwardRequest) (*http.Response, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("hostrpc requires an HTTP client")
	}
	url := hostURL(host, in.Path)
	if in.Query != "" {
		url += "?" + in.Query
	}
	req, err := http.NewRequestWithContext(ctx, in.Method, url, in.Body)
	if err != nil {
		return nil, err
	}
	if in.ContentLength >= 0 {
		req.ContentLength = in.ContentLength
	}
	httpx.SetRequestIDHeader(ctx, req)
	for key, values := range in.Header {
		lower := strings.ToLower(key)
		if _, drop := proxyHopByHop[lower]; drop || lower == "host" || lower == "content-length" || lower == "authorization" {
			continue
		}
		// Hosts authenticate control through mTLS and receive the resolved user
		// identity below. User credentials must stay at the control boundary.
		switch lower {
		case strings.ToLower(proto.HeaderAPIKey), "x-auth-token", "x-access-token", "x-agent-token",
			"x-agent-shared-key", "x-admin-token", strings.ToLower(proto.HeaderBootstrapToken), "cookie":
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if in.UserID != "" {
		utils.SetUserIDHeader(req, in.UserID)
	}
	client := httpClient
	if in.WithoutTimeout {
		clone := *httpClient
		clone.Timeout = 0
		client = &clone
	}
	return client.Do(req)
}

// ReadResponseBody reads a response intended for buffered relay while keeping
// control-plane memory bounded. Streaming callers must consume Body directly.
func ReadResponseBody(response *http.Response, maxBytes int64) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("hostrpc response body is missing")
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("buffered response limit must be positive")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, ErrResponseTooLarge
	}
	return body, nil
}
