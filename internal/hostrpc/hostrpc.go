// Package hostrpc owns control-to-machine HTTP communication: typed lifecycle
// commands and sanitized proxy requests. Host selection remains the
// scheduler's responsibility.
package hostrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/NodeOps-app/sandbox/internal/proto"
	"github.com/NodeOps-app/sandbox/models"
)

var hostScheme = "http"

func SetHostScheme(scheme string) {
	if scheme != "" {
		hostScheme = scheme
	}
}

func hostURL(host models.Host, path string) string {
	addr := host.Addr
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		addr = hostScheme + "://" + addr
	}
	return strings.TrimRight(addr, "/") + "/" + strings.TrimLeft(path, "/")
}

func do(
	ctx context.Context,
	httpClient *http.Client,
	host models.Host,
	method, path, userID string,
	body []byte,
	extraHeaders map[string]string,
) (*http.Response, error) {
	headers := make(http.Header)
	if len(body) > 0 {
		headers.Set("Content-Type", "application/json")
	}
	for key, value := range extraHeaders {
		headers.Set(key, value)
	}
	return Forward(ctx, httpClient, host, ForwardRequest{
		Method:        method,
		Path:          path,
		Header:        headers,
		Body:          bytes.NewReader(body),
		ContentLength: int64(len(body)),
		UserID:        userID,
	})
}

func Pause(ctx context.Context, httpClient *http.Client, host models.Host, sandboxID, userID string) (*http.Response, error) {
	return do(ctx, httpClient, host, http.MethodPost, "/v1/sandboxes/"+sandboxID+"/pause", userID, nil, nil)
}

// Create sends the control-enriched create command to the scheduler-selected
// host. The sandbox ID is minted by control and carried separately so the host
// uses that exact ID when it creates the VM.
func Create(
	ctx context.Context,
	httpClient *http.Client,
	host models.Host,
	sandboxID, userID string,
	request *proto.CreateReq,
) (*http.Response, error) {
	if request == nil {
		return nil, fmt.Errorf("create request is required")
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encode create request: %w", err)
	}
	return do(ctx, httpClient, host, http.MethodPost, "/v1/sandboxes", userID, body, map[string]string{
		proto.HeaderSandboxID: sandboxID,
	})
}

func Destroy(ctx context.Context, httpClient *http.Client, host models.Host, sandboxID, userID string) (*http.Response, error) {
	return do(ctx, httpClient, host, http.MethodDelete, "/v1/internal/sandboxes/"+sandboxID, userID, nil, nil)
}

// Resume resolves the scheduler-selected host ID and sends that host the full
// sandbox row needed for restoration. It never selects or schedules a host.
func Resume(
	ctx context.Context,
	repo *models.Repo,
	httpClient *http.Client,
	hostID string,
	sandbox *models.Sandbox,
) (*http.Response, error) {
	if repo == nil {
		return nil, fmt.Errorf("hostrpc resume requires a repository")
	}
	if sandbox == nil {
		return nil, fmt.Errorf("sandbox is required")
	}
	host, err := repo.GetHost(ctx, hostID)
	if err != nil {
		return nil, fmt.Errorf("resolve host %s: %w", hostID, err)
	}
	if host == nil {
		return nil, fmt.Errorf("host %s not found", hostID)
	}
	body, err := json.Marshal(sandbox)
	if err != nil {
		return nil, fmt.Errorf("encode sandbox: %w", err)
	}
	return do(ctx, httpClient, *host, http.MethodPost,
		"/v1/internal/sandboxes/"+sandbox.ID+"/resume", sandbox.CreatedBy, body, nil)
}

func PauseAccepted(response *http.Response) bool {
	if response == nil {
		return false
	}
	return response.StatusCode == http.StatusConflict || response.StatusCode == http.StatusNotFound ||
		(response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices)
}

func DestroyAccepted(response *http.Response) bool {
	if response == nil {
		return false
	}
	return response.StatusCode == http.StatusNotFound ||
		(response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices)
}
