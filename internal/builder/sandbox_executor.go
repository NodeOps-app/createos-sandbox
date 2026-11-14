package builder

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/internal/proto"
)

//go:embed sandbox_runner.sh
var sandboxRunner []byte

const (
	buildLabelSystem     = "createos.system"
	buildLabelTemplateID = "createos.template_id"
	buildLabelProcessID  = "createos.process_id"
	buildLabelSystemName = "template-builder"
)

type SandboxExecutorConfig struct {
	APIURL  string
	APIKey  string
	Rootfs  string
	Shape   string
	DiskMiB int64
	Region  string
}

// SandboxExecutor builds templates inside ordinary CreateOS sandboxes.
// The API key is used only by this client and is never placed in the guest.
type SandboxExecutor struct {
	cfg    SandboxExecutorConfig
	client *http.Client
}

func NewSandboxExecutor(cfg SandboxExecutorConfig, client *http.Client) *SandboxExecutor {
	if client == nil {
		client = &http.Client{}
	}
	return &SandboxExecutor{cfg: cfg, client: client}
}

type jsendEnvelope struct {
	Status  string          `json:"status"`
	Data    json.RawMessage `json:"data"`
	Message string          `json:"message"`
}

type runnerConfig struct {
	TemplateID string `json:"template_id"`
	ControlURL string `json:"control_url"`
	JWT        string `json:"jwt"`
	RootfsURL  string `json:"rootfs_put_url"`
	SizeCapMiB int64  `json:"size_cap_mib"`
}

func (e *SandboxExecutor) Run(ctx context.Context, spec BuildSpec) error {
	id, err := e.create(ctx, spec.TplID)
	if err != nil {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		var err error
		for attempt := 1; attempt <= 3; attempt++ {
			if err = e.destroy(cleanupCtx, id); err == nil {
				return
			}
			if attempt < 3 {
				select {
				case <-cleanupCtx.Done():
					break
				case <-time.After(time.Duration(attempt) * time.Second):
				}
			}
		}
		log.WithContext(ctx).Errorf("[builder] cleanup sandbox %s: %v", id, err)
	}()

	configJSON, err := json.Marshal(runnerConfig{
		TemplateID: spec.TplID,
		ControlURL: strings.TrimRight(spec.ControlURL, "/") + "/v1/internal/templates",
		JWT:        spec.Grants.JWT,
		RootfsURL:  spec.Grants.RootfsPutURL,
		SizeCapMiB: spec.SizeCapMiB,
	})
	if err != nil {
		return fmt.Errorf("encode runner config: %w", err)
	}
	for path, body := range map[string][]byte{
		"/workspace/Dockerfile":                  []byte(spec.Dockerfile),
		"/workspace/.dockerignore":               []byte("build.json\ncreateos-template-runner.sh\n"),
		"/workspace/createos-template-runner.sh": sandboxRunner,
		"/workspace/build.json":                  configJSON,
	} {
		if err := e.upload(ctx, id, path, body); err != nil {
			return err
		}
	}
	processID, err := e.startProcess(ctx, id)
	if err != nil {
		return err
	}
	if err := e.patchLabels(ctx, id, map[string]string{buildLabelProcessID: processID}); err != nil {
		// Do not guess this process during recovery if persistence fails. The
		// deferred sandbox delete terminates it in the normal live-builder path.
		return fmt.Errorf("persist build process label: %w", err)
	}
	return e.waitProcess(ctx, id, processID)
}

func (e *SandboxExecutor) create(ctx context.Context, tplID string) (string, error) {
	ingress := false
	rootfs := e.cfg.Rootfs
	// Sandbox names are capped at 22 characters. Keep the tail of the ULID,
	// which carries the random portion. Name uniqueness is enforced by control.
	idSuffix := strings.ToLower(strings.TrimPrefix(tplID, "tpl_"))
	if len(idSuffix) > 16 {
		idSuffix = idSuffix[len(idSuffix)-16:]
	}
	name := "build-" + idSuffix
	body, err := json.Marshal(proto.CreateReq{
		Shape: e.cfg.Shape, Rootfs: &rootfs, Name: &name, DiskMib: e.cfg.DiskMiB,
		Region: e.cfg.Region, IngressEnabled: &ingress,
		Labels: map[string]string{
			buildLabelSystem:     buildLabelSystemName,
			buildLabelTemplateID: tplID,
		},
	})
	if err != nil {
		return "", err
	}
	resp, err := e.do(ctx, http.MethodPost, "/v1/sandboxes", "application/json", body)
	if err != nil {
		return "", fmt.Errorf("create build sandbox: %w", err)
	}
	defer resp.Body.Close()
	var env jsendEnvelope
	if err := decodeResponse(resp, &env); err != nil {
		return "", fmt.Errorf("create build sandbox: %w", err)
	}
	var created proto.CreateResp
	if err := json.Unmarshal(env.Data, &created); err != nil || created.ID == "" {
		return "", fmt.Errorf("create build sandbox: invalid response")
	}
	return created.ID, nil
}

func (e *SandboxExecutor) upload(ctx context.Context, id, path string, body []byte) error {
	endpoint := "/v1/sandboxes/" + url.PathEscape(id) + "/files?path=" + url.QueryEscape(path)
	resp, err := e.do(ctx, http.MethodPut, endpoint, "application/octet-stream", body)
	if err != nil {
		return fmt.Errorf("upload %s: %w", path, err)
	}
	defer resp.Body.Close()
	if err := expectSuccess(resp); err != nil {
		return fmt.Errorf("upload %s: %w", path, err)
	}
	return nil
}

func (e *SandboxExecutor) startProcess(ctx context.Context, id string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"cmd": "/bin/sh", "args": []string{"/workspace/createos-template-runner.sh"},
	})
	resp, err := e.do(ctx, http.MethodPost, "/v1/sandboxes/"+url.PathEscape(id)+"/processes", "application/json", body)
	if err != nil {
		return "", fmt.Errorf("start build process: %w", err)
	}
	defer resp.Body.Close()
	var env jsendEnvelope
	if err := decodeResponse(resp, &env); err != nil {
		return "", fmt.Errorf("start build process: %w", err)
	}
	var process proto.ProcessDetails
	if err := json.Unmarshal(env.Data, &process); err != nil || process.ID == "" {
		return "", fmt.Errorf("start build process: invalid response")
	}
	return process.ID, nil
}

func (e *SandboxExecutor) patchLabels(ctx context.Context, id string, labels map[string]string) error {
	body, err := json.Marshal(map[string]any{"labels": labels})
	if err != nil {
		return err
	}
	resp, err := e.do(ctx, http.MethodPatch, "/v1/sandboxes/"+url.PathEscape(id), "application/json", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return expectSuccess(resp)
}

func (e *SandboxExecutor) waitProcess(ctx context.Context, sandboxID, processID string) error {
	// The runner starts dockerd, which intentionally remains alive after the
	// runner shell exits. Its leader exit code is the build result; waiting for
	// the whole tree would wait on dockerd until the sandbox is destroyed.
	endpoint := "/v1/sandboxes/" + url.PathEscape(sandboxID) + "/processes/" + url.PathEscape(processID) + "/wait?scope=leader&timeout_ms=30000"
	for {
		resp, err := e.do(ctx, http.MethodGet, endpoint, "", nil)
		if err != nil {
			return fmt.Errorf("wait for build process: %w", err)
		}
		if resp.StatusCode == http.StatusRequestTimeout {
			resp.Body.Close()
			continue
		}
		var env jsendEnvelope
		decodeErr := decodeResponse(resp, &env)
		resp.Body.Close()
		if decodeErr != nil {
			return fmt.Errorf("wait for build process: %w", decodeErr)
		}
		var process proto.ProcessDetails
		if err := json.Unmarshal(env.Data, &process); err != nil {
			return fmt.Errorf("wait for build process: invalid response: %w", err)
		}
		if !process.LeaderExited {
			continue
		}
		if process.ExitCode == nil {
			return fmt.Errorf("build process exited without exit status")
		}
		if *process.ExitCode != 0 {
			return fmt.Errorf("runner exited with status %d", *process.ExitCode)
		}
		return nil
	}
}

func (e *SandboxExecutor) destroy(ctx context.Context, id string) error {
	resp, err := e.do(ctx, http.MethodDelete, "/v1/sandboxes/"+url.PathEscape(id), "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return expectSuccess(resp)
}

// ListBuildSandboxes discovers running build sandboxes from server-side labels. The
// dedicated builder API key scopes the listing to sandboxes owned by builder,
// while the system label excludes any unrelated sandbox owned by that user.
func (e *SandboxExecutor) ListBuildSandboxes(ctx context.Context) ([]BuildSandbox, error) {
	const limit = 500
	labels, err := json.Marshal(map[string]string{buildLabelSystem: buildLabelSystemName})
	if err != nil {
		return nil, err
	}
	var out []BuildSandbox
	for offset := 0; ; offset += limit {
		endpoint := fmt.Sprintf("/v1/sandboxes?status=running&labels=%s&limit=%d&offset=%d",
			url.QueryEscape(string(labels)), limit, offset)
		resp, err := e.do(ctx, http.MethodGet, endpoint, "", nil)
		if err != nil {
			return nil, fmt.Errorf("list build sandboxes: %w", err)
		}
		var env jsendEnvelope
		decodeErr := decodeResponse(resp, &env)
		resp.Body.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("list build sandboxes: %w", decodeErr)
		}
		var page proto.Page[[]proto.SandboxView]
		if err := json.Unmarshal(env.Data, &page); err != nil {
			return nil, fmt.Errorf("list build sandboxes: decode page: %w", err)
		}
		for _, sandbox := range page.Data {
			tplID := sandbox.Labels[buildLabelTemplateID]
			if sandbox.ID == "" || tplID == "" {
				log.WithContext(ctx).Warnf("[builder] ignoring malformed labeled sandbox %q without template id", sandbox.ID)
				continue
			}
			out = append(out, BuildSandbox{ID: sandbox.ID, TemplateID: tplID, ProcessID: sandbox.Labels[buildLabelProcessID]})
		}
		if page.Pagination.Count == 0 || offset+page.Pagination.Count >= page.Pagination.Total {
			break
		}
	}
	return out, nil
}

func (e *SandboxExecutor) DestroyBuildSandbox(ctx context.Context, id string) error {
	return e.destroy(ctx, id)
}

func (e *SandboxExecutor) BuildProcessFinished(ctx context.Context, sandbox BuildSandbox) (bool, error) {
	endpoint := "/v1/sandboxes/" + url.PathEscape(sandbox.ID) + "/processes/" + url.PathEscape(sandbox.ProcessID)
	resp, err := e.do(ctx, http.MethodGet, endpoint, "", nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return true, nil
	}
	var env jsendEnvelope
	if err := decodeResponse(resp, &env); err != nil {
		return false, err
	}
	var process proto.ProcessDetails
	if err := json.Unmarshal(env.Data, &process); err != nil {
		return false, err
	}
	return process.LeaderExited || process.TreeExited || process.State == proto.ProcessLifecycleExited || process.State == proto.ProcessLifecycleFailed, nil
}

func (e *SandboxExecutor) do(ctx context.Context, method, path, contentType string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(e.cfg.APIURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set(proto.HeaderAPIKey, e.cfg.APIKey)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return e.client.Do(req)
}

func decodeResponse(resp *http.Response, dst any) error {
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return responseError(resp)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(dst); err != nil {
		return err
	}
	return nil
}

func expectSuccess(resp *http.Response) error {
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	return responseError(resp)
}

func responseError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}
