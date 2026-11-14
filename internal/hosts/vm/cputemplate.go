package vm

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
)

// CPU templates mask guest CPU features through Firecracker's PUT /cpu-config
// endpoint before cold boot or prewarm capture. Masking can reduce differences
// between hosts, but does not guarantee snapshot portability: CPU vendor,
// KVM register state, TSC compatibility, and the Firecracker runtime still matter.
// Restoring an existing snapshot retains its captured CPU configuration.
//
// The configured cpu_template_path is loaded once at startup. We send its JSON
// directly over the API socket because the SDK integration uses the custom
// CPU-config endpoint rather than the static machine-config template field.
// After changing a template, regenerate affected prewarm snapshots explicitly;
// preserve user pause/full-snapshot bundles and their compatible runtimes.

// cpuTemplatePathMu guards cpuTemplateBody against a startup
// SetCPUTemplatePath racing the first cold-create's read.
var cpuTemplatePathMu sync.RWMutex

// SetCPUTemplatePath caches the template body in memory and arms the
// per-VM PUT /cpu-config handler. Called once by serve startup before
// the first Create. Empty path disarms (no-op handler).
func SetCPUTemplatePath(path string) error {
	cpuTemplatePathMu.Lock()
	defer cpuTemplatePathMu.Unlock()
	if path == "" {
		cpuTemplateBody = nil
		return nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read cpu template %s: %w", path, err)
	}
	if len(body) == 0 {
		return fmt.Errorf("cpu template %s is empty", path)
	}
	cpuTemplateBody = body
	return nil
}

// cpuTemplateBody is the pre-loaded JSON body. Cached so each VM
// create does zero file IO.
var cpuTemplateBody []byte

// cpuTemplateActive returns the cached body if a template is loaded,
// nil otherwise.
func cpuTemplateActive() []byte {
	cpuTemplatePathMu.RLock()
	defer cpuTemplatePathMu.RUnlock()
	return cpuTemplateBody
}

// applyCPUTemplateHandler returns an SDK init handler that PUTs the
// cached template JSON to firecracker's /cpu-config endpoint over the
// machine's API socket. Inserted into the FcInit chain right after
// StartVMM (socket up) and well before InstanceStart (boot). No-op
// when no template is configured.
func applyCPUTemplateHandler() firecracker.Handler {
	return firecracker.Handler{
		Name: "createos.PutCPUConfig",
		Fn: func(ctx context.Context, m *firecracker.Machine) error {
			body := cpuTemplateActive()
			if body == nil {
				return nil // no template configured; native CPUID
			}
			// Single-use transport: we PUT one CPU-config and return.
			// DisableKeepAlives = no idle conn pool, so the persistConn
			// read/write goroutines exit as soon as the response body
			// closes — instead of lingering 90 s on the default
			// IdleConnTimeout. Multiplied by N concurrent VM boots this
			// would otherwise pile up ~2N leaked goroutines until the
			// timeout fires; on a high-churn host we measured 100+
			// leaked persistConn pairs after 100 spawns. Single-use
			// unix-socket dial gains nothing from keep-alive anyway.
			tr := &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", m.Cfg.SocketPath)
				},
				DisableKeepAlives: true,
			}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr}
			req, err := http.NewRequestWithContext(ctx, http.MethodPut,
				"http://unix/cpu-config", strings.NewReader(string(body)))
			if err != nil {
				return fmt.Errorf("cpu-config build req: %w", err)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("cpu-config call: %w", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode >= http.StatusMultipleChoices {
				buf, _ := io.ReadAll(resp.Body)
				return fmt.Errorf("cpu-config HTTP %d: %s", resp.StatusCode, string(buf))
			}
			return nil
		},
	}
}
