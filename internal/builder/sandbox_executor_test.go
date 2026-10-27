package builder

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/NodeOps-app/sandbox/internal/proto"
)

func TestSandboxExecutorRunAndCleanup(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	seen := map[string]int{}
	exit := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Api-Key"); got != "builder-key" {
			t.Errorf("api key = %q", got)
		}
		mu.Lock()
		seen[r.Method+" "+r.URL.Path]++
		mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes":
			var req proto.CreateReq
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode create request: %v", err)
			}
			if req.Labels[buildLabelSystem] != buildLabelSystemName || req.Labels[buildLabelTemplateID] != "tpl_123" {
				t.Errorf("create labels = %#v", req.Labels)
			}
			if req.Name == nil || *req.Name != "build-123" || len(*req.Name) > 22 {
				t.Errorf("create name = %v", req.Name)
			}
			fmt.Fprint(w, `{"status":"success","data":{"id":"sb_build","status":"running"}}`)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/files"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/processes"):
			fmt.Fprint(w, `{"status":"success","data":{"process_id":"proc_test","state":"running","tree_exited":false}}`)
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/sandboxes/sb_build":
			var req struct {
				Labels map[string]string `json:"labels"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Labels[buildLabelProcessID] != "proc_test" {
				t.Errorf("process labels = %#v", req.Labels)
			}
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/wait"):
			if got := r.URL.Query().Get("scope"); got != "leader" {
				t.Errorf("wait scope = %q, want leader", got)
			}
			fmt.Fprintf(w, `{"status":"success","data":{"process_id":"proc_test","state":"exited","leader_exited":true,"tree_exited":false,"exit_code":%d}}`, exit)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/sandboxes/sb_build":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	executor := NewSandboxExecutor(SandboxExecutorConfig{
		APIURL: server.URL, APIKey: "builder-key", Rootfs: "devbox:1",
		Shape: "s-2vcpu-4gb", DiskMiB: 20480,
	}, server.Client())
	err := executor.Run(context.Background(), BuildSpec{
		TplID: "tpl_123", Dockerfile: "FROM nodeops/sandbox:debian",
		Grants:     &Grants{JWT: "scoped-jwt", RootfsPutURL: "https://storage.invalid/put"},
		ControlURL: server.URL, SizeCapMiB: 5120,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := seen[http.MethodPut+" /v1/sandboxes/sb_build/files"]; got != 4 {
		t.Fatalf("file uploads = %d, want 4", got)
	}
	if got := seen[http.MethodDelete+" /v1/sandboxes/sb_build"]; got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
}

func TestSandboxExecutorBuildNameFitsSandboxLimit(t *testing.T) {
	t.Parallel()
	var gotName string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req proto.CreateReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Name != nil {
			gotName = *req.Name
		}
		fmt.Fprint(w, `{"status":"success","data":{"id":"sb_build"}}`)
	}))
	defer server.Close()

	executor := NewSandboxExecutor(SandboxExecutorConfig{APIURL: server.URL}, server.Client())
	if _, err := executor.create(context.Background(), "tpl_01M5KJ7WKM194QVPMQAEKTN2H1"); err != nil {
		t.Fatal(err)
	}
	if gotName != "build-194qvpmqaektn2h1" {
		t.Fatalf("build sandbox name = %q", gotName)
	}
	if len(gotName) != 22 {
		t.Fatalf("build sandbox name length = %d, want 22", len(gotName))
	}
}

func TestSandboxExecutorCleansUpAfterRunnerFailure(t *testing.T) {
	t.Parallel()
	deleted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/processes"):
			fmt.Fprint(w, `{"status":"success","data":{"process_id":"proc_test"}}`)
		case r.Method == http.MethodPost:
			fmt.Fprint(w, `{"status":"success","data":{"id":"sb_failed"}}`)
		case r.Method == http.MethodPut:
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPatch:
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/wait"):
			fmt.Fprint(w, `{"status":"success","data":{"process_id":"proc_test","leader_exited":true,"tree_exited":false,"exit_code":17}}`)
		case r.Method == http.MethodDelete:
			deleted = true
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	executor := NewSandboxExecutor(SandboxExecutorConfig{
		APIURL: server.URL, APIKey: "key", Rootfs: "devbox:1",
		Shape: "s-2vcpu-4gb", DiskMiB: 20480,
	}, server.Client())
	err := executor.Run(context.Background(), BuildSpec{
		TplID: "tpl_bad", Dockerfile: "FROM nodeops/sandbox:debian",
		Grants:     &Grants{JWT: "jwt", RootfsPutURL: "https://storage.invalid/put"},
		ControlURL: server.URL, SizeCapMiB: 5120,
	})
	if err == nil || !strings.Contains(err.Error(), "status 17") {
		t.Fatalf("error = %v", err)
	}
	if !deleted {
		t.Fatal("build sandbox was not cleaned up")
	}
}

func TestSandboxExecutorListsLabeledBuildSandboxes(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/sandboxes" {
			http.NotFound(w, r)
			return
		}
		var labels map[string]string
		if err := json.Unmarshal([]byte(r.URL.Query().Get("labels")), &labels); err != nil {
			t.Fatalf("decode labels query: %v", err)
		}
		if labels[buildLabelSystem] != buildLabelSystemName {
			t.Fatalf("labels query = %#v", labels)
		}
		if status := r.URL.Query().Get("status"); status != "running" {
			t.Fatalf("status query = %q, want running", status)
		}
		fmt.Fprint(w, `{"status":"success","data":{"data":[{"id":"sb_build","labels":{"createos.system":"template-builder","createos.template_id":"tpl_123","createos.process_id":"proc_test"}}],"pagination":{"total":1,"limit":500,"offset":0,"count":1}}}`)
	}))
	defer server.Close()

	executor := NewSandboxExecutor(SandboxExecutorConfig{APIURL: server.URL, APIKey: "builder-key"}, server.Client())
	got, err := executor.ListBuildSandboxes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != (BuildSandbox{ID: "sb_build", TemplateID: "tpl_123", ProcessID: "proc_test"}) {
		t.Fatalf("build sandboxes = %#v", got)
	}
}
