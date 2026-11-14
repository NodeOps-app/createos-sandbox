package vm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// Root-owned, immutable binary/policy pairs shared by pause and full restores.
// Provision the same pairs on every migration destination. The legacy file
// contains the SHA256 of the old binary used by manifests without a build ID.
const firecrackerRuntimeDir = "/usr/local/lib/createos/firecracker"

type firecrackerRuntime struct {
	Build   string
	Binary  string
	Seccomp string
}

func firecrackerDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func validFirecrackerBuild(build string) bool {
	if len(build) != sha256.Size*2 {
		return false
	}
	for _, c := range build {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Slot UIDs must never be able to replace a registered executable or policy.
func secureRuntimePath(path string, directory bool) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || st.Mode().Perm()&0022 != 0 || st.IsDir() != directory || (!directory && !st.Mode().IsRegular()) {
		return fmt.Errorf("insecure Firecracker runtime path %s", path)
	}
	return nil
}

func loadFirecrackerRuntime(root, build string) (firecrackerRuntime, error) {
	if err := secureRuntimePath(root, true); err != nil {
		return firecrackerRuntime{}, err
	}
	if build == "" {
		if err := secureRuntimePath(filepath.Join(root, "legacy"), false); err != nil {
			return firecrackerRuntime{}, err
		}
		b, err := os.ReadFile(filepath.Join(root, "legacy"))
		if err != nil {
			return firecrackerRuntime{}, fmt.Errorf("legacy Firecracker build unavailable: %w", err)
		}
		build = strings.TrimSpace(string(b))
	}
	if !validFirecrackerBuild(build) {
		return firecrackerRuntime{}, fmt.Errorf("invalid Firecracker build ID")
	}
	dir := filepath.Join(root, build)
	if err := secureRuntimePath(dir, true); err != nil {
		return firecrackerRuntime{}, err
	}
	for _, name := range []string{"firecracker", "seccomp.bpf"} {
		if err := secureRuntimePath(filepath.Join(dir, name), false); err != nil {
			return firecrackerRuntime{}, err
		}
	}
	rt := firecrackerRuntime{Build: build, Binary: filepath.Join(dir, "firecracker"), Seccomp: filepath.Join(dir, "seccomp.bpf")}
	got, err := firecrackerDigest(rt.Binary)
	if err != nil {
		return firecrackerRuntime{}, fmt.Errorf("Firecracker build %s unavailable: %w", build, err)
	}
	if got != build {
		return firecrackerRuntime{}, fmt.Errorf("Firecracker build checksum mismatch")
	}
	st, err := os.Stat(rt.Binary)
	if err != nil || st.Mode().Perm()&0111 == 0 {
		return firecrackerRuntime{}, fmt.Errorf("Firecracker build is not executable")
	}
	policy, err := os.Stat(rt.Seccomp)
	if err != nil {
		return firecrackerRuntime{}, fmt.Errorf("Firecracker policy unavailable: %w", err)
	}
	// An empty file explicitly records use of this binary's built-in filter.
	if policy.Size() == 0 {
		rt.Seccomp = ""
	}
	return rt, nil
}

// Pin the configured pair once at host startup. Replacing the default executable
// later cannot change which build is launched or mislabeled in a snapshot.
func pinFirecrackerRuntime(root, binary, policy string) (firecrackerRuntime, error) {
	build, err := firecrackerDigest(binary)
	if err != nil {
		return firecrackerRuntime{}, err
	}
	if err := os.MkdirAll(root, 0755); err != nil {
		return firecrackerRuntime{}, err
	}
	if err := secureRuntimePath(root, true); err != nil {
		return firecrackerRuntime{}, err
	}
	tmp, err := os.MkdirTemp(root, ".install-")
	if err != nil {
		return firecrackerRuntime{}, err
	}
	defer os.RemoveAll(tmp)
	copyFile := func(src, dst string, mode os.FileMode) error {
		data := []byte{}
		if src != "" {
			var err error
			data, err = os.ReadFile(src)
			if err != nil {
				return err
			}
		}
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := f.Write(data); err != nil {
			return err
		}
		return f.Sync()
	}
	if err := copyFile(binary, filepath.Join(tmp, "firecracker"), 0755); err != nil {
		return firecrackerRuntime{}, err
	}
	if err := copyFile(policy, filepath.Join(tmp, "seccomp.bpf"), 0644); err != nil {
		return firecrackerRuntime{}, err
	}
	if err := os.Chmod(tmp, 0755); err != nil {
		return firecrackerRuntime{}, err
	}
	// Verify the copied bytes too: an operator may have replaced the source.
	if got, err := firecrackerDigest(filepath.Join(tmp, "firecracker")); err != nil || got != build {
		return firecrackerRuntime{}, fmt.Errorf("Firecracker changed while pinning")
	}
	want, err := firecrackerDigest(filepath.Join(tmp, "seccomp.bpf"))
	if err != nil {
		return firecrackerRuntime{}, err
	}
	if err := syncRuntimeDir(tmp); err != nil {
		return firecrackerRuntime{}, err
	}
	dst := filepath.Join(root, build)
	if _, err := os.Lstat(dst); os.IsNotExist(err) {
		if err := os.Rename(tmp, dst); err != nil {
			return firecrackerRuntime{}, err
		}
		if err := syncRuntimeDir(root); err != nil {
			return firecrackerRuntime{}, err
		}
	} else if err != nil {
		return firecrackerRuntime{}, err
	}
	rt, err := loadFirecrackerRuntime(root, build)
	if err != nil {
		return firecrackerRuntime{}, err
	}
	got, err := firecrackerDigest(filepath.Join(dst, "seccomp.bpf"))
	if err != nil || got != want {
		return firecrackerRuntime{}, fmt.Errorf("Firecracker build already registered with a different seccomp policy")
	}
	return rt, nil
}

func syncRuntimeDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func currentFirecrackerRuntime(policy string) (firecrackerRuntime, error) {
	binary, err := exec.LookPath(firecrackerBin)
	if err != nil {
		return firecrackerRuntime{}, err
	}
	return pinFirecrackerRuntime(firecrackerRuntimeDir, binary, policy)
}

// SnapshotFirecrackerBuild identifies the actual producer, including a process
// rehydrated after a host-agent restart or running an unlinked old executable.
// Never infer it from the default binary on disk or from capture timestamps.
func (m *Manager) SnapshotFirecrackerBuild(sb *Sandbox) (string, error) {
	if sb.FCPid <= 0 {
		return "", fmt.Errorf("snapshot source has no Firecracker process")
	}
	build, err := firecrackerDigest(fmt.Sprintf("/proc/%d/exe", sb.FCPid))
	if err != nil {
		return "", err
	}
	if _, err := loadFirecrackerRuntime(firecrackerRuntimeDir, build); err != nil {
		return "", err
	}
	return build, nil
}
