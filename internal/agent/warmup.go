package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"time"

	"syscall"
	"unsafe"
)

const (
	warmupManifest    = "/etc/createos/warmup.json"
	warmupMaxManifest = 64 << 10
	warmupMaxFiles    = 5
	warmupMaxRanges   = 256
	warmupMaxBytes    = 32 << 20
	warmupTimeout     = 2 * time.Second
)

type warmupRange struct {
	Offset int64 `json:"offset"`
	Length int64 `json:"length"`
}
type warmupFile struct {
	Path   string        `json:"path"`
	Ranges []warmupRange `json:"ranges"`
}
type warmupPlan struct {
	Files []warmupFile `json:"files"`
}

// Run the reader before starting the child reaper or publishing phase-1
// readiness. The child is reaped before snapshotting; timed-out work cannot
// survive into every restored VM. No image-supplied program is executed.
func prepareWarmup() {
	ctx, cancel := context.WithTimeout(context.Background(), warmupTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "--warmup-rootfs")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "agent: optional image warmup skipped or interrupted")
	}
}

// Open with O_PATH first: even opening a device or FIFO for reading can have
// side effects. Resolve absolute symlinks inside the image, verify a regular
// inode, then reopen that pinned inode, never the untrusted path.
func openWarmupFile(root *os.File, name string) (*os.File, error) {
	if name == "/" || !path.IsAbs(name) || path.Clean(name) != name {
		return nil, errors.New("invalid warmup path")
	}
	// Linux ABI flags; keep the guest agent stdlib-only like files.go.
	const oPath = 0x200000
	const resolveInRoot = 0x10
	const resolveNoMagiclinks = 0x02
	const resolveNoXdev = 0x01
	how := openHow{Flags: oPath | syscall.O_CLOEXEC, Resolve: resolveInRoot | resolveNoMagiclinks | resolveNoXdev}
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}
	raw, _, errno := syscall.Syscall6(sysOpenat2, root.Fd(), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0)
	if errno != 0 {
		return nil, errno
	}
	fd := int(raw)
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, errors.New("warmup requires regular files")
	}
	return os.Open(fmt.Sprintf("/proc/self/fd/%d", fd))
}

func decodeWarmup(data []byte) (warmupPlan, error) {
	var p warmupPlan
	if len(data) > warmupMaxManifest {
		return p, errors.New("warmup manifest too large")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return p, errors.New("trailing warmup data")
	}
	if len(p.Files) > warmupMaxFiles {
		return p, errors.New("too many warmup files")
	}
	var total int64
	ranges := 0
	for _, f := range p.Files {
		if f.Path == "/" || !path.IsAbs(f.Path) || path.Clean(f.Path) != f.Path {
			return p, errors.New("invalid warmup path")
		}
		ranges += len(f.Ranges)
		if ranges > warmupMaxRanges {
			return p, errors.New("too many warmup ranges")
		}
		for _, r := range f.Ranges {
			// Page alignment bounds cache use even for tiny disjoint reads. Check
			// overflow before addition and charge rounded pages against the budget.
			if r.Offset < 0 || r.Offset%4096 != 0 || r.Length <= 0 || r.Length > warmupMaxBytes || r.Offset > int64(^uint64(0)>>1)-r.Length {
				return p, errors.New("invalid warmup range")
			}
			total += (r.Length + 4095) / 4096 * 4096
			if total > warmupMaxBytes {
				return p, errors.New("warmup byte budget exceeded")
			}
		}
	}
	return p, nil
}

func warmImage(rootPath string) error {
	root, err := os.Open(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	manifest, err := openWarmupFile(root, warmupManifest)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(manifest, warmupMaxManifest+1))
	manifest.Close()
	if err != nil {
		return err
	}
	plan, err := decodeWarmup(data)
	if err != nil {
		return err
	}
	type opened struct {
		f      *os.File
		ranges []warmupRange
	}
	var files []opened
	defer func() {
		for _, f := range files {
			f.f.Close()
		}
	}()
	seen := make(map[[2]uint64]bool)
	// Validate every present file before reading any payload. An invalid plan
	// skips all warmup; absent optional files are harmless in derived images.
	for _, entry := range plan.Files {
		f, err := openWarmupFile(root, entry.Path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		files = append(files, opened{f, entry.Ranges})
		var st syscall.Stat_t
		if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
			return err
		}
		identity := [2]uint64{uint64(st.Dev), st.Ino}
		if seen[identity] {
			return errors.New("duplicate warmup file")
		}
		seen[identity] = true
		for _, r := range entry.Ranges {
			if r.Offset > st.Size || r.Length > st.Size-r.Offset {
				return errors.New("warmup range outside file")
			}
		}
	}
	buf := make([]byte, 32<<10)
	var total int64
	for _, file := range files {
		// Avoid uncontrolled sequential readahead outside the declared ranges.
		const fadvRandom = 1
		if _, _, errno := syscall.Syscall6(syscall.SYS_FADVISE64, file.f.Fd(), 0, 0, fadvRandom, 0, 0); errno != 0 {
			return errno
		}
		for _, r := range file.ranges {
			n, err := io.CopyBuffer(io.Discard, io.NewSectionReader(file.f, r.Offset, r.Length), buf)
			total += n
			if err != nil {
				return err
			}
		}
	}
	fmt.Fprintf(os.Stderr, "agent: image warmup loaded %d bytes from %d files\n", total, len(files))
	return nil
}
