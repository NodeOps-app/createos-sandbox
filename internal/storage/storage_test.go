package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

// memRoundTrip exercises Put -> Get -> Exists -> Copy -> Delete on
// the MemStorage. Acts as the contract test the R2 impl must also
// satisfy (we don't run R2 in unit tests; covered by integration).
func TestMemStorageRoundTrip(t *testing.T) {
	ms := NewMemStorage()
	ctx := context.Background()

	if err := ms.Put(ctx, "a/b", bytes.NewReader([]byte("hello")), 5, ""); err != nil {
		t.Fatal(err)
	}
	exists, err := ms.Exists(ctx, "a/b")
	if err != nil || !exists {
		t.Fatalf("exists got=%v err=%v", exists, err)
	}
	rc, size, err := ms.Get(ctx, "a/b")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if size != 5 {
		t.Fatalf("size got=%d want=5", size)
	}
	got, _ := io.ReadAll(rc)
	if string(got) != "hello" {
		t.Fatalf("got=%q want=hello", got)
	}

	if err := ms.Copy(ctx, "a/b", "a/c"); err != nil {
		t.Fatal(err)
	}
	rc2, _, _ := ms.Get(ctx, "a/c")
	got2, _ := io.ReadAll(rc2)
	rc2.Close()
	if string(got2) != "hello" {
		t.Fatalf("copy got=%q", got2)
	}

	if err := ms.Delete(ctx, "a/b"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ms.Get(ctx, "a/b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// TestLocalCacheHitMiss verifies the basic LocalCache contract: local
// hit returns local bytes; miss falls through to underlying.
func TestLocalCacheHitMiss(t *testing.T) {
	dir := t.TempDir()
	ms := NewMemStorage()
	ctx := context.Background()
	if err := ms.Put(ctx, "k", bytes.NewReader([]byte("from-mem")), 8, ""); err != nil {
		t.Fatal(err)
	}
	lc := &LocalCache{Dir: dir, Underlying: ms}

	// Miss → underlying.
	rc, _, err := lc.Get(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if string(got) != "from-mem" {
		t.Fatalf("miss path got=%q", got)
	}

	// Plant a local file with different content; subsequent Get
	// should hit the local copy.
	if err := os.WriteFile(filepath.Join(dir, "k"), []byte("from-local"), 0o644); err != nil {
		t.Fatal(err)
	}
	rc2, _, err := lc.Get(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	got2, _ := io.ReadAll(rc2)
	rc2.Close()
	if string(got2) != "from-local" {
		t.Fatalf("hit path got=%q want=from-local", got2)
	}
}

func TestHashingReader(t *testing.T) {
	hr := NewHashingReader(strings.NewReader("hello world"))
	_, _ = io.Copy(io.Discard, hr) // strings.Reader never errors; the assertions below cover it
	got := hr.Sum()
	// sha256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
	want := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if got != want {
		t.Fatalf("sum got=%s want=%s", got, want)
	}
	if hr.BytesRead() != int64(len("hello world")) {
		t.Fatalf("bytes read got=%d", hr.BytesRead())
	}
}

func TestManifestRoundTrip(t *testing.T) {
	mem := ArtifactDescriptor{SHA256: "aaa", Size: 100}
	vms := ArtifactDescriptor{SHA256: "bbb", Size: 50}
	ovl := ArtifactDescriptor{SHA256: "ccc", Size: 200}
	m, body, err := NewManifest(mem, vms, ovl, "/tmp/fc-overlay-99-1.ext4", "/var/lib/createos/images/devbox.ext4")
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != ManifestVersion {
		t.Fatalf("version got=%d", m.Version)
	}
	if m.Encryption.Mode != "none" {
		t.Fatalf("encryption got=%s", m.Encryption.Mode)
	}

	parsed, err := ParseManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Artifacts[ArtifactMemfile].SHA256 != "aaa" {
		t.Fatalf("roundtrip mismatch")
	}

	// Verify success.
	if err := parsed.VerifyArtifact(ArtifactMemfile, "aaa", 100); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Verify mismatch.
	if err := parsed.VerifyArtifact(ArtifactMemfile, "wrong", 100); err == nil {
		t.Fatal("expected sha256 mismatch error")
	}
	if err := parsed.VerifyArtifact(ArtifactMemfile, "aaa", 99); err == nil {
		t.Fatal("expected size mismatch error")
	}
}

// A storage backend may accept the body and stall before response headers.
// The caller's upload deadline must stop the SDK, including its internal retries.
func TestR2PutDeadlineWhileWaitingForResponse(t *testing.T) {
	received := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case <-received:
		default:
			close(received)
		}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	defer close(release)
	store, err := NewR2(R2Config{Endpoint: server.URL, Region: "test", Bucket: "test-bucket", AccessKeyID: "test", SecretAccessKey: "test"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = store.Put(ctx, "snapshot", strings.NewReader("snapshot"), 8, "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected upload deadline, got %v", err)
	}
	select {
	case <-received:
	default:
		t.Fatal("server never received upload")
	}
}

func TestUploadProgressStopsStallsButAllowsActiveTransfers(t *testing.T) {
	logger := log.New()
	logger.SetOutput(io.Discard)
	for _, active := range []bool{false, true} {
		t.Run(fmt.Sprint(active), func(t *testing.T) {
			parent, stop := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer stop()
			ctx, cancel := context.WithCancelCause(parent)
			defer cancel(nil)
			progress := &uploadProgress{start: time.Now()}
			done := make(chan struct{})
			go func() {
				defer close(done)
				progress.watch(ctx, cancel, log.NewEntry(logger), 150*time.Millisecond, 10*time.Millisecond)
			}()
			if active {
				ticker := time.NewTicker(10 * time.Millisecond)
				defer ticker.Stop()
			loop:
				for {
					select {
					case <-ctx.Done():
						break loop
					case <-ticker.C:
						progress.Read([]byte("progress"))
					}
				}
			}
			<-done
			want := errUploadIdle
			if active {
				want = context.DeadlineExceeded
			}
			if !errors.Is(context.Cause(ctx), want) {
				t.Fatalf("cause=%v, want %v", context.Cause(ctx), want)
			}
		})
	}
}

func TestManifestPreservesFirecrackerBuild(t *testing.T) {
	artifact := ArtifactDescriptor{SHA256: strings.Repeat("a", 64), Size: 1}
	original, body, err := NewManifest(artifact, artifact, artifact, "overlay", "rootfs")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := ParseManifest(body)
	if err != nil || legacy.FirecrackerBuild != "" {
		t.Fatalf("legacy manifest: %#v %v", legacy, err)
	}
	original.FirecrackerBuild = strings.Repeat("b", 64)
	body, err = json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, full := range []bool{false, true} {
		if !full {
			delete(original.Artifacts, ArtifactMemfile)
			delete(original.Artifacts, ArtifactVMState)
			body, err = json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			original.Artifacts[ArtifactMemfile] = artifact
			original.Artifacts[ArtifactVMState] = artifact
			body, err = json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
		}
		parsed, err := ParseCaptureManifest(body, full)
		if err != nil || parsed.FirecrackerBuild != original.FirecrackerBuild {
			t.Fatalf("capture manifest lost build: %#v %v", parsed, err)
		}
	}
}
