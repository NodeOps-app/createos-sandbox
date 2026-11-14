package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/hosts/controlclient"
	"github.com/NodeOps-app/createos-sandbox/internal/hosts/vm"
)

func TestTemplateEvictionRechecksLocalUsers(t *testing.T) {
	dir := t.TempDir()
	const id = "tpl_eviction_test"
	path := filepath.Join(dir, id+".ext4")
	if err := os.WriteFile(path, []byte("template"), 0600); err != nil {
		t.Fatal(err)
	}
	m := &vm.Manager{Rootfses: map[string]string{id: path}, Sandboxes: map[string]*vm.Sandbox{}}
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// A VM becomes locally visible while the control response still says zero.
			m.Mu.Lock()
			m.Sandboxes["sb-test"] = &vm.Sandbox{Rootfs: id}
			m.Mu.Unlock()
			fmt.Fprint(w, `{"status":"success","data":{"count":0}}`)
		} else {
			fmt.Fprint(w, `{"status":"success","data":{}}`)
		}
	}))
	defer control.Close()
	s := &Service{Mgr: m, Repo: controlclient.NewClient(control.URL), TplCfg: TemplateConfig{HostID: "host-test", TemplatesDir: dir}}
	if s.evict(context.Background(), id) {
		t.Error("evicted template used by a local VM")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("live template removed: %v", err)
	}
}

func TestTemplateUseExcludesEviction(t *testing.T) {
	s := &Service{}
	const id = "tpl_test"
	var wg sync.WaitGroup
	releases := make(chan func(), 32)
	for range 32 {
		wg.Go(func() {
			release, err := s.useTemplate(context.Background(), id)
			if err != nil {
				t.Error(err)
				return
			}
			releases <- release
		})
	}
	wg.Wait()
	if _, ok := s.claimTemplateEviction(id); ok {
		t.Fatal("eviction claimed an in-use template")
	}
	other, ok := s.claimTemplateEviction("tpl_other")
	if !ok {
		t.Fatal("unrelated template blocked")
	}
	other()
	close(releases)
	for release := range releases {
		release()
	}
	finish, ok := s.claimTemplateEviction(id)
	if !ok {
		t.Fatal("released template remains busy")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.useTemplate(ctx, id); err != context.Canceled {
		t.Fatalf("wait cancellation: %v", err)
	}
	acquired := make(chan func(), 1)
	go func() {
		release, err := s.useTemplate(context.Background(), id)
		if err == nil {
			acquired <- release
		}
	}()
	select {
	case <-acquired:
		t.Fatal("acquired during eviction")
	case <-time.After(20 * time.Millisecond):
	}
	finish()
	select {
	case release := <-acquired:
		release()
	case <-time.After(time.Second):
		t.Fatal("waiter did not wake")
	}
	if len(s.tplUses) != 0 {
		t.Fatal("unused template coordination entries retained")
	}
}

func TestTemplateEvictionRemovesUnusedTemplate(t *testing.T) {
	dir := t.TempDir()
	const id = "tpl_unused"
	path := filepath.Join(dir, id+".ext4")
	if err := os.WriteFile(path, []byte("template"), 0600); err != nil {
		t.Fatal(err)
	}
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"success","data":{"count":0}}`)
	}))
	defer control.Close()
	m := &vm.Manager{Rootfses: map[string]string{id: path}}
	s := &Service{Mgr: m, Repo: controlclient.NewClient(control.URL), TplCfg: TemplateConfig{HostID: "host-test", TemplatesDir: dir}}
	release, err := s.useTemplate(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if s.evict(context.Background(), id) {
		t.Fatal("evicted during startup")
	}
	release()
	if !s.evict(context.Background(), id) {
		t.Fatal("unused template not evicted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("template remains: %v", err)
	}
	if _, ok := m.LookupRootfs(id); ok {
		t.Fatal("catalog entry remains")
	}
}
