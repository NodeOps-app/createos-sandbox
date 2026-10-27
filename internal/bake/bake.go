package bake

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Run converts a Docker image to a Firecracker-ready rootfs file and rebuilds
// the initrd containing the given agent binary.
//
// If outputPath is empty, a default path under images/ is derived from the
// image name. If sizeMB is 0 or too small, it is auto-sized from the actual
// rootfs size.
func Run(image, outputPath string, sizeMB int64, agentBinary string) error {
	if outputPath == "" {
		// python:3.12-slim → images/python-3.12-slim.ext4
		name := strings.ReplaceAll(image, "/", "-")
		name = strings.ReplaceAll(name, ":", "-")
		outputPath = filepath.Join("images", name+".ext4")
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("mkdir output: %w", err)
	}

	fmt.Printf("Baking %s → %s (%dMB)\n\n", image, outputPath, sizeMB)

	tmpDir, err := os.MkdirTemp("", "fc-bake-")
	if err != nil {
		return fmt.Errorf("tmpdir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	ociDir := filepath.Join(tmpDir, "oci")
	bundleDir := filepath.Join(tmpDir, "bundle")

	// Step 1: Pull image via skopeo.
	// `image` may be either a registry ref (`python:3.12-slim` →
	// `docker://...`) OR a full skopeo URI (`docker-daemon:foo:bar`,
	// `docker-archive:/path`, etc.). We detect the latter by the
	// presence of a `xxx:yyy:zzz` pattern with a known transport prefix,
	// to let operators bake locally-built images without pushing.
	fmt.Printf("[1/4] Pulling %s ...\n", image)
	src := image
	if !hasSkopeoTransport(image) {
		src = "docker://" + image
	}
	out, err := exec.Command("skopeo", "copy",
		src,
		"oci:"+ociDir+":latest",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("skopeo copy failed: %w\n%s", err, out)
	}
	fmt.Println("      done")

	// Step 2: Unpack OCI image to a rootfs bundle
	fmt.Println("[2/4] Unpacking layers ...")
	out, err = exec.Command("umoci", "unpack",
		"--image", ociDir+":latest",
		bundleDir,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("umoci unpack failed: %w\n%s", err, out)
	}
	rootfsDir := filepath.Join(bundleDir, "rootfs")
	fmt.Println("      done")

	// Step 3: Create ext4 image and copy rootfs into it
	fmt.Println("[3/4] Creating ext4 image ...")

	// Calculate actual size needed
	actualSize, _ := dirSize(rootfsDir)
	minSizeMB := (actualSize / (1024 * 1024)) + 100 // actual + 100MB headroom
	if sizeMB < minSizeMB {
		sizeMB = minSizeMB
		fmt.Printf("      auto-sized to %dMB (rootfs is %dMB)\n", sizeMB, actualSize/(1024*1024))
	}

	// Create and format ext4
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create image: %w", err)
	}
	if err := f.Truncate(sizeMB * 1024 * 1024); err != nil {
		f.Close()
		return fmt.Errorf("truncate: %w", err)
	}
	f.Close()

	out, err = exec.Command("mkfs.ext4", "-F", outputPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mkfs.ext4: %w\n%s", err, out)
	}

	// Mount and copy
	mountDir := filepath.Join(tmpDir, "mnt")
	if err := os.MkdirAll(mountDir, 0755); err != nil {
		return fmt.Errorf("mkdir mountpoint: %w", err)
	}
	if out, err := exec.Command("mount", outputPath, mountDir).CombinedOutput(); err != nil {
		return fmt.Errorf("mount: %w\n%s", err, out)
	}

	// Copy rootfs contents (preserve permissions, symlinks, etc.)
	out, err = exec.Command("cp", "-a", rootfsDir+"/.", mountDir+"/").CombinedOutput()
	if err != nil {
		_ = exec.Command("umount", mountDir).Run() // best-effort cleanup; the cp failure is the real error
		return fmt.Errorf("cp rootfs: %w\n%s", err, out)
	}

	// Ensure /etc/resolv.conf points to /proc/net/pnp for DNS
	resolv := filepath.Join(mountDir, "etc", "resolv.conf")
	os.Remove(resolv)
	if err := os.Symlink("/proc/net/pnp", resolv); err != nil {
		_ = exec.Command("umount", mountDir).Run() // best-effort cleanup; the symlink failure is the real error
		return fmt.Errorf("symlink resolv.conf: %w", err)
	}

	if out, err := exec.Command("umount", mountDir).CombinedOutput(); err != nil {
		return fmt.Errorf("umount: %w\n%s", err, out)
	}
	fmt.Println("      done")

	// Step 4: Rebuild initrd with our agent
	fmt.Println("[4/4] Building initrd ...")
	if err := buildInitrd(agentBinary); err != nil {
		return err
	}
	fmt.Println("      done")

	fmt.Printf("\nBaked successfully!\n")
	fmt.Printf("  Rootfs : %s\n", outputPath)
	fmt.Printf("  Initrd : images/initrd.gz\n")
	fmt.Printf("\nRun:\n")
	fmt.Printf("  ./machine host --rootfs %s\n", outputPath)
	return nil
}

// hasSkopeoTransport returns true if `s` starts with a known skopeo
// transport scheme followed by ":". Anything else is treated as a bare
// registry ref and gets `docker://` prepended.
func hasSkopeoTransport(s string) bool {
	prefixes := []string{
		"docker://",
		"docker-daemon:",
		"docker-archive:",
		"oci:",
		"oci-archive:",
		"containers-storage:",
		"dir:",
	}
	for _, p := range prefixes {
		if len(s) >= len(p) && s[:len(p)] == p {
			return true
		}
	}
	return false
}

// BuildInitrd is the exported wrapper so callers (e.g. the `image initrd`
// subcommand) can rebuild just the initrd without running a full bake.
func BuildInitrd(agentBinary string) error { return buildInitrd(agentBinary) }

func buildInitrd(agentBinary string) error {
	tmpDir, err := os.MkdirTemp("", "fc-initrd-")
	if err != nil {
		return fmt.Errorf("tmpdir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	for _, dir := range []string{"usr/local/bin", "bin", "proc", "sys", "dev", "mnt", "overlay", "lower", "merged", "tmp"} {
		if err := os.MkdirAll(filepath.Join(tmpDir, dir), 0755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	// Copy the agent binary to /usr/local/bin/agent inside the initrd
	// (kernel rdinit= points here).
	if err := copyFile(agentBinary, filepath.Join(tmpDir, "usr/local/bin/agent")); err != nil {
		return err
	}

	// Copy busybox for basic tools
	if _, err := os.Stat("/bin/busybox"); err == nil {
		if err := copyFile("/bin/busybox", filepath.Join(tmpDir, "bin/busybox")); err != nil {
			return err
		}
	}

	// Create cpio initrd
	absInitrd, _ := filepath.Abs(filepath.Join("images", "initrd.gz"))
	if err := os.MkdirAll(filepath.Dir(absInitrd), 0755); err != nil {
		return fmt.Errorf("mkdir images dir: %w", err)
	}
	cmd := exec.Command("bash", "-c",
		fmt.Sprintf("cd %s && find . | cpio -o -H newc 2>/dev/null | gzip > %s",
			tmpDir, absInitrd))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cpio: %w\n%s", err, out)
	}
	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	if err := os.WriteFile(dst, data, 0755); err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}
	return nil
}

func dirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}
