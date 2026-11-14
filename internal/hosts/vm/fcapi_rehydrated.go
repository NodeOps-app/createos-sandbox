package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// FirecrackerAPI talks to a running firecracker over its unix API socket.
// Used when we need to drive a VM whose SDK Machine handle is gone —
// specifically rehydrated VMs that survive a serve restart.
type FirecrackerAPI struct {
	client *http.Client
}

func NewFirecrackerAPI(socketPath string) *FirecrackerAPI {
	// DisableKeepAlives: this Transport is constructed per rehydrate /
	// pause / resume operation. Without disabling keepalive, its idle
	// persistConn goroutines would outlive the FirecrackerAPI struct
	// and leak until process exit.
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
		DisableKeepAlives: true,
	}
	return &FirecrackerAPI{client: &http.Client{Transport: tr}}
}

const (
	FirecrackerStatePaused  = "Paused"
	FirecrackerStateRunning = "Running"
)

// VMState reads Firecracker's actual state from GET /. Unexpected states and
// invalid responses are errors, never evidence that a guest has resumed.
func (a *FirecrackerAPI) VMState(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/", nil)
	if err != nil {
		return "", err
	}
	res, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("get VM state: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("get VM state: HTTP %d", res.StatusCode)
	}
	const maxStateBytes = 4096
	body, err := io.ReadAll(io.LimitReader(res.Body, maxStateBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxStateBytes {
		return "", fmt.Errorf("VM state response exceeds size limit")
	}
	var info struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", fmt.Errorf("decode VM state: %w", err)
	}
	switch info.State {
	case FirecrackerStatePaused, FirecrackerStateRunning:
		return info.State, nil
	default:
		return "", fmt.Errorf("unexpected VM state %q", info.State)
	}
}

func (a *FirecrackerAPI) do(ctx context.Context, method, path, body string) error {
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("build req: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("call %s %s: %w", method, path, err)
	}
	defer res.Body.Close()
	if res.StatusCode >= http.StatusMultipleChoices {
		buf, _ := io.ReadAll(res.Body)
		return fmt.Errorf("%s %s HTTP %d: %s", method, path, res.StatusCode, string(buf))
	}
	return nil
}

// PauseVM transitions the running VM into the paused state. Idempotent
// per firecracker docs — paused → paused is a no-op.
func (a *FirecrackerAPI) PauseVM(ctx context.Context) error {
	return a.do(ctx, http.MethodPatch, "/vm", `{"state":"Paused"}`)
}

// ResumeVM transitions paused → running. Idempotent.
func (a *FirecrackerAPI) ResumeVM(ctx context.Context) error {
	return a.do(ctx, http.MethodPatch, "/vm", `{"state":"Resumed"}`)
}

// CreateSnapshot writes memfile + vmstate to the given paths. Caller
// must PauseVM first; firecracker rejects /snapshot/create on a
// running VM. Overwrites existing files.
func (a *FirecrackerAPI) CreateSnapshot(ctx context.Context, memPath, vmStatePath string) error {
	body := fmt.Sprintf(`{"mem_file_path":%q,"snapshot_path":%q}`, memPath, vmStatePath)
	return a.do(ctx, http.MethodPut, "/snapshot/create", body)
}

// UpdateDrive rebinds the named virtio-blk drive to a new host file via
// PATCH /drives/<id>. Requires the VM to be paused (or not yet started)
// — firecracker rejects PATCH on a live drive. Used at pause time to
// re-point the overlay drive at a stable path inside the paused dir
// (instead of the live runtime path that embeds the serve PID and
// disappears across restarts), so the captured vmstate references a
// path that survives until resume.
func (a *FirecrackerAPI) UpdateDrive(ctx context.Context, driveID, pathOnHost string) error {
	body := fmt.Sprintf(`{"drive_id":%q,"path_on_host":%q}`, driveID, pathOnHost)
	return a.do(ctx, http.MethodPatch, "/drives/"+driveID, body)
}

// SetMetadata replaces the MMDS document (PUT /mmds). Used for live
// disk attach / detach when the SDK Machine handle isn't available
// (rehydrated VMs) or as a uniform path alongside the SDK-driven
// SetMetadata used at boot / restore.
func (a *FirecrackerAPI) SetMetadata(ctx context.Context, jsonBody string) error {
	return a.do(ctx, http.MethodPut, "/mmds", jsonBody)
}

// getMMDSRaw returns the current MMDS document as raw bytes. Used by
// the live disk reconfigure path on rehydrated VMs where the SDK
// Machine.GetMetadata isn't available.
func (a *FirecrackerAPI) getMMDSRaw(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/mmds", nil)
	if err != nil {
		return nil, fmt.Errorf("build req: %w", err)
	}
	res, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call GET /mmds: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if res.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("GET /mmds HTTP %d: %s", res.StatusCode, string(body))
	}
	return body, nil
}
