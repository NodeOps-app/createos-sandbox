package handlers

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NodeOps-app/createos-sandbox/database"
	"github.com/NodeOps-app/createos-sandbox/internal/storage"
	"github.com/NodeOps-app/createos-sandbox/models"
	"github.com/jackc/pgx/v5"
)

var forkDSNFile = flag.String("audit-dev-dsn-file", "", "explicit dev DSN file for isolated fork fixtures")

func forkFixture(t *testing.T) (context.Context, *models.Repo) {
	t.Helper()
	if *forkDSNFile == "" {
		t.Skip("explicit dev PostgreSQL fixture required")
	}
	raw, err := os.ReadFile(*forkDSNFile)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	base, err := pgx.Connect(ctx, strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal("connect fixture failed")
	}
	schema := fmt.Sprintf("audit_fork_%d", time.Now().UnixNano())
	if _, err = base.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := base.Exec(c, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error(err)
		}
		base.Close(c)
	})
	u, err := url.Parse(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal("invalid DSN")
	}
	q := u.Query()
	q.Set("search_path", schema)
	q.Set("application_name", schema)
	u.RawQuery = q.Encode()
	d, err := database.OpenDbWithPoolConfig(ctx, u.String(), database.PoolConfig{MinConns: 1, MaxConns: 4})
	if err != nil {
		t.Fatal("open fixture failed")
	}
	t.Cleanup(d.Close)
	_, err = d.Con.Exec(ctx, `CREATE TABLE sandboxes (LIKE public.sandboxes INCLUDING ALL);
 CREATE TABLE snapshots(sandbox_id text,status text,captured_at timestamptz,deleted_at timestamptz);
 CREATE TABLE sandbox_access_tokens(sandbox_id text);
 INSERT INTO sandboxes(id,status,created_by,region,created_at,bundle_uploaded_at,snapshot_manifest) VALUES ('sb-source','paused','audit-user','eu',now(),now(),'{"generation":"A"}');`)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, &models.Repo{DB: d}
}

// Pause the worker after its first real memory-store copy. This deterministically
// places source mutations between artifact copies without changing live storage.
type forkBlockingStorage struct {
	storage.Storage
	copied, release chan struct{}
	once            sync.Once
	fail            bool
}

func (s *forkBlockingStorage) Copy(ctx context.Context, src, dst string) error {
	if strings.HasSuffix(src, storage.ArtifactMemfile) {
		if err := s.Storage.Copy(ctx, src, dst); err != nil {
			return err
		}
		s.once.Do(func() { close(s.copied) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	}
	if s.fail {
		return errors.New("injected copy failure")
	}
	return s.Storage.Copy(ctx, src, dst)
}

func TestForkSourceMutationDuringCopy(t *testing.T) {
	for _, mode := range []string{"delete", "resume", "copy failure", "child deleted", "watchdog failure"} {
		t.Run(mode, func(t *testing.T) {
			ctx, repo := forkFixture(t)
			rec, err := repo.MarkForking(ctx, "sb-source", models.Sandbox{ID: "sb-child", CreatedBy: "audit-user", Region: "eu", CreatedAt: time.Now()})
			if err != nil {
				t.Fatal(err)
			}
			if rec == nil {
				t.Fatal("fork row missing")
			}
			mem := storage.NewMemStorage()
			names := []string{storage.ArtifactMemfile, storage.ArtifactVMState, storage.ArtifactOverlay, storage.ArtifactManifest}
			for _, n := range names {
				if err = mem.Put(ctx, storage.BundlePrefix("sb-source")+n, strings.NewReader("A"), 1, ""); err != nil {
					t.Fatal(err)
				}
			}
			st := &forkBlockingStorage{Storage: mem, copied: make(chan struct{}), release: make(chan struct{}), fail: mode == "copy failure"}
			h := &Handler{repo: repo, storage: st}
			done := make(chan struct{})
			go func() {
				defer close(done)
				h.runForkBackground("sb-source", "sb-child", models.Sandbox{SnapshotManifest: []byte(`{"generation":"A"}`)}, mode != "child deleted" && mode != "watchdog failure")
			}()
			released := false
			t.Cleanup(func() {
				if !released {
					close(st.release)
				}
				<-done
			})
			select {
			case <-st.copied:
			case <-ctx.Done():
				t.Fatal("copy barrier not reached")
			}
			switch mode {
			case "delete":
				changed, e := repo.MarkDestroyingFromTerminalCAS(ctx, "sb-source")
				if e != nil {
					t.Fatal(e)
				}
				if changed {
					t.Error("source deletion accepted during fork")
					for _, n := range names {
						_ = mem.Delete(ctx, storage.BundlePrefix("sb-source")+n)
					}
				}
			case "resume":
				status, e := repo.MarkResuming(ctx, "sb-source", false, time.Now())
				if e != nil {
					t.Fatal(e)
				}
				if status != "" {
					t.Error("source resume accepted during fork")
					for _, n := range names {
						_ = mem.Put(ctx, storage.BundlePrefix("sb-source")+n, strings.NewReader("B"), 1, "")
					}
				}
			case "child deleted":
				if _, err = repo.MarkDestroying(ctx, "sb-child"); err != nil {
					t.Fatal(err)
				}
			case "watchdog failure":
				msg := "injected worker loss"
				if _, err = repo.MarkForkFailed(ctx, "sb-child", &msg, nil); err != nil {
					t.Fatal(err)
				}

			}
			close(st.release)
			released = true
			<-done
			statuses, err := repo.StatusOfIDs(ctx, []string{"sb-child"})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("child status=%s", statuses["sb-child"])
			if mode == "copy failure" || mode == "watchdog failure" {
				if statuses["sb-child"] != "failed" {
					t.Error("failure was not retained")
				}
			}

			if mode == "delete" || mode == "resume" {
				if statuses["sb-child"] != "paused" {
					t.Error("fork did not complete")
				}
				for _, n := range names {
					r, _, e := mem.Get(ctx, storage.BundlePrefix("sb-child")+n)
					if e != nil {
						t.Error(e)
						continue
					}
					b, _ := io.ReadAll(r)
					r.Close()
					if string(b) != "A" {
						t.Errorf("mixed generation artifact %s=%s", n, b)
					}
				}
			} else {
				for _, n := range names {
					exists, _ := mem.Exists(ctx, storage.BundlePrefix("sb-child")+n)
					if exists {
						t.Errorf("abandoned child artifact retained: %s", n)
					}
				}
			}
			if status, e := repo.MarkResuming(ctx, "sb-source", false, time.Now()); e != nil || status != "resuming" {
				t.Fatalf("source remains blocked after worker completion: %s %v", status, e)
			}
		})
	}
}

func TestForkLockedManifestAndOwnership(t *testing.T) {
	ctx, repo := forkFixture(t)
	tx, err := repo.DB.Con.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `UPDATE sandboxes SET snapshot_manifest='{"generation":"B"}' WHERE id='sb-source'`); err != nil {
		t.Fatal(err)
	}
	result := make(chan *models.Sandbox, 1)
	errs := make(chan error, 1)
	go func() {
		r, e := repo.MarkForking(ctx, "sb-source", models.Sandbox{ID: "sb-child", CreatedBy: "audit-user", Region: "eu", CreatedAt: time.Now(), SnapshotManifest: []byte(`{"generation":"A"}`)})
		result <- r
		errs <- e
	}()
	for {
		var waiting bool
		if err = repo.DB.Con.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=current_setting('application_name') AND wait_event_type='Lock')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("fork did not wait on source")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	r := <-result
	if err = <-errs; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(r.SnapshotManifest), "B") {
		t.Fatalf("stale manifest: %s", r.SnapshotManifest)
	}
	for _, rec := range []models.Sandbox{{ID: "wrong-owner", CreatedBy: "other", Region: "eu"}, {ID: "wrong-region", CreatedBy: "audit-user", Region: "us"}} {
		if _, err = repo.MarkForking(ctx, "sb-source", rec); !errors.Is(err, models.ErrForkSourceUnavailable) {
			t.Fatalf("ownership/region accepted: %v", err)
		}
	}
	if _, err = repo.DB.Con.Exec(ctx, "UPDATE sandboxes SET bundle_uploaded_at=NULL WHERE id='sb-source'"); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.MarkForking(ctx, "sb-source", models.Sandbox{ID: "no-bundle", CreatedBy: "audit-user", Region: "eu"}); !errors.Is(err, models.ErrForkSourceUnavailable) {
		t.Fatalf("missing bundle accepted: %v", err)
	}
}

func TestParallelForkCopyAndSourceRelease(t *testing.T) {
	ctx, repo := forkFixture(t)
	mem := storage.NewMemStorage()
	names := []string{storage.ArtifactMemfile, storage.ArtifactVMState, storage.ArtifactOverlay, storage.ArtifactManifest}
	for _, n := range names {
		if err := mem.Put(ctx, storage.BundlePrefix("sb-source")+n, strings.NewReader("original-content"), 16, ""); err != nil {
			t.Fatal(err)
		}
	}
	h := &Handler{repo: repo, storage: mem}
	rows := make(chan *models.Sandbox, 15)
	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec, err := repo.MarkForking(ctx, "sb-source", models.Sandbox{ID: fmt.Sprintf("sb-child-%d", i), CreatedBy: "audit-user", Region: "eu", CreatedAt: time.Now()})
			if err != nil {
				t.Error(err)
				return
			}
			rows <- rec
		}(i)
	}
	wg.Wait()
	close(rows)
	if len(rows) != 15 {
		t.Fatal("parallel fork inserts incomplete")
	}
	if changed, err := repo.MarkDestroyingFromTerminalCAS(ctx, "sb-source"); err != nil || changed {
		t.Fatal("source not protected")
	}
	var children []*models.Sandbox
	for rec := range rows {
		children = append(children, rec)
	}
	// Leave one child copying while all others finish.
	for _, rec := range children[:14] {
		wg.Add(1)
		go func(rec *models.Sandbox) { defer wg.Done(); h.runForkBackground("sb-source", rec.ID, *rec, true) }(rec)
	}
	wg.Wait()
	if status, err := repo.MarkResuming(ctx, "sb-source", false, time.Now()); err != nil || status != "" {
		t.Fatal("source released before last fork finished")
	}
	h.runForkBackground("sb-source", children[14].ID, *children[14], true)
	// A cleanup retry after successful publication must preserve the bundle.
	h.cleanupFailedFork(children[14].ID)
	for _, rec := range children {
		states, err := repo.StatusOfIDs(ctx, []string{rec.ID})
		if err != nil || states[rec.ID] != "paused" {
			t.Fatalf("child not paused: %v %v", states, err)
		}
		for _, n := range names {
			r, _, err := mem.Get(ctx, storage.BundlePrefix(rec.ID)+n)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(r)
			r.Close()
			if string(b) != "original-content" {
				t.Error("fork content mismatch")
			}
		}
	}
	if status, err := repo.MarkResuming(ctx, "sb-source", false, time.Now()); err != nil || status != "resuming" {
		t.Fatalf("source not released: %s %v", status, err)
	}
}

func TestForkLeaseVisibleAfterLockWait(t *testing.T) {
	ctx, repo := forkFixture(t)
	tx, err := repo.DB.Con.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `SELECT id FROM sandboxes WHERE id='sb-source' FOR UPDATE; INSERT INTO sandboxes(id,status,forked_from,created_at) VALUES ('sb-child','forking','sb-source',now())`); err != nil {
		t.Fatal(err)
	}
	result := make(chan string, 1)
	errs := make(chan error, 1)
	go func() {
		status, e := repo.MarkResuming(ctx, "sb-source", false, time.Now())
		result <- status
		errs <- e
	}()
	for {
		var waiting bool
		if err = repo.DB.Con.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=current_setting('application_name') AND wait_event_type='Lock')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("resume did not wait on source lock")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	status := <-result
	if err = <-errs; err != nil || status != "" {
		t.Fatalf("resume missed newly committed fork: %s %v", status, err)
	}
}
