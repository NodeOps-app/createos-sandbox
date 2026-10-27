package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

// TestLocalCachePopulate verifies that GetWithCachePopulate writes
// the bytes to disk on a miss so the next Get is a hit.
func TestLocalCachePopulate(t *testing.T) {
	dir := t.TempDir()
	ms := NewMemStorage()
	ctx := context.Background()
	if err := ms.Put(ctx, "sub/k", bytes.NewReader([]byte("payload")), 7, ""); err != nil {
		t.Fatal(err)
	}
	lc := &LocalCache{Dir: dir, Underlying: ms}

	rc, _, err := lc.GetWithCachePopulate(ctx, "sub/k")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	if err := rc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("read got=%q", got)
	}

	// File should exist on disk now.
	onDisk, err := os.ReadFile(filepath.Join(dir, "sub/k"))
	if err != nil {
		t.Fatalf("expected populated cache file: %v", err)
	}
	if string(onDisk) != "payload" {
		t.Fatalf("disk got=%q", onDisk)
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
