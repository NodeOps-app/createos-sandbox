package vm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFirecrackerRuntimeSelection(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("runtime files must be root-owned")
	}
	root := t.TempDir()
	source := t.TempDir()
	binary, policy := filepath.Join(source, "firecracker"), filepath.Join(source, "seccomp.bpf")
	write := func(path, contents string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(contents), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(binary, "old binary", 0755)
	write(policy, "old policy", 0644)
	old, err := pinFirecrackerRuntime(root, binary, policy)
	if err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(root, "legacy"), old.Build+"\n", 0644)
	write(binary, "new binary", 0755)
	write(policy, "new policy", 0644)
	current, err := pinFirecrackerRuntime(root, binary, policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ build, want, policy string }{{"", old.Build, "old policy"}, {old.Build, old.Build, "old policy"}, {current.Build, current.Build, "new policy"}} {
		rt, err := loadFirecrackerRuntime(root, tc.build)
		if err != nil {
			t.Fatal(err)
		}
		if rt.Build != tc.want {
			t.Fatalf("selected %s, want %s", rt.Build, tc.want)
		}
		b, err := os.ReadFile(rt.Seccomp)
		if err != nil || string(b) != tc.policy {
			t.Fatalf("wrong policy: %q, %v", b, err)
		}
	}
	// Changing the default and restarting the resolver must preserve old pairs.
	if _, err := pinFirecrackerRuntime(root, binary, policy); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"../firecracker", strings.Repeat("a", 64), "2026.11.6"} {
		if _, err := loadFirecrackerRuntime(root, bad); err == nil {
			t.Fatalf("accepted unavailable/invalid build %q", bad)
		}
	}
	write(policy, "different policy", 0644)
	if _, err := pinFirecrackerRuntime(root, binary, policy); err == nil {
		t.Fatal("replaced immutable policy")
	}
	if err := os.Remove(old.Seccomp); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFirecrackerRuntime(root, ""); err == nil {
		t.Fatal("restored legacy without its policy")
	}
	write(current.Binary, "tampered", 0755)
	if _, err := loadFirecrackerRuntime(root, current.Build); err == nil {
		t.Fatal("accepted changed executable")
	}
}

func TestFirecrackerRuntimeRefusesWritableFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("runtime files must be root-owned")
	}
	root, src := t.TempDir(), t.TempDir()
	binary := filepath.Join(src, "binary")
	if err := os.WriteFile(binary, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	rt, err := pinFirecrackerRuntime(root, binary, "")
	if err != nil {
		t.Fatal(err)
	}
	if rt.Seccomp != "" {
		t.Fatal("expected built-in seccomp")
	}
	if err := os.Chmod(rt.Binary, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFirecrackerRuntime(root, rt.Build); err == nil {
		t.Fatal("accepted writable binary")
	}
	if _, err := loadFirecrackerRuntime(root, ""); err == nil {
		t.Fatal("guessed a legacy build")
	}
}

func TestTemplateManifestPreservesProducerBuild(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("manifest publication requires root ownership")
	}
	for _, build := range []string{"", strings.Repeat("a", 64), strings.Repeat("b", 64)} {
		dir := t.TempDir()
		files := &snapshotFiles{
			FirecrackerBuild: build,
			VmStatePath:      filepath.Join(dir, "vmstate.generation"),
			MemFilePath:      filepath.Join(dir, "mem.generation"),
			BaseOverlay:      filepath.Join(dir, "base.generation.ext4"),
		}
		if err := publishSnapshotManifest(dir, files); err != nil {
			t.Fatal(err)
		}
		got, err := readSnapshotManifest(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got.FirecrackerBuild != build || got.VmStatePath != files.VmStatePath {
			t.Fatalf("template producer or generation changed: %+v", got)
		}
	}
}
