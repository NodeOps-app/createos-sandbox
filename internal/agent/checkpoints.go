package agent

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/proto"
)

// Directory checkpoints use the raw per-VM filesystem, like container storage,
// rather than placing another writable overlay on the guest root overlay.
const checkpointStorageDir = "/.fc-overlay/_checkpoints"
const checkpointMaxManifestBytes = 1 << 20

var (
	errCheckpointPath    = errors.New("checkpoint requires a supported absolute directory path")
	errCheckpointOverlap = errors.New("checkpoint directory overlaps another managed directory")
	errCheckpointMount   = errors.New("checkpoint directory crosses an unsupported mount")
)

// Protect both these trees and parents containing them. Capturing /var/lib,
// for example, must not enroll container storage through its parent directory.
// Application trees such as /opt/app, /root/project and /home/user/app remain
// eligible; this is not a fixed /workspace-only feature.
var checkpointProtectedTrees = [...]string{
	"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/usr",
	"/etc", "/boot", "/dev", "/proc", "/sys", "/run", "/lost+found",
	"/.fc-overlay", "/overlay", "/lower", "/merged", "/oldroot",
	"/var/lib/docker", "/var/lib/containerd", "/var/lib/rancher",
}

func checkpointPathWithin(path, root string) bool {
	return root == "/" || path == root || strings.HasPrefix(path, root+"/")
}

// validateCheckpointPath performs lexical policy checks. Filesystem resolution
// still requires openCheckpointDirectory: a clean string alone is not proof
// against symlinks or guest-controlled mount aliases.
func validateCheckpointPath(raw string, managedRoots []string) (string, error) {
	if !filepath.IsAbs(raw) || strings.IndexByte(raw, 0) >= 0 {
		return "", errCheckpointPath
	}
	path := filepath.Clean(raw)
	// Capturing an entire temporary-files tree would also move unrelated
	// process scratch files. Its ordinary application subdirectories are allowed.
	if path == "/" || path == "/tmp" || path == "/var/tmp" {
		return "", errCheckpointPath
	}
	for _, protected := range checkpointProtectedTrees {
		if checkpointPathWithin(path, protected) || checkpointPathWithin(protected, path) {
			return "", errCheckpointPath
		}
	}
	for _, root := range managedRoots {
		root = filepath.Clean(root)
		if path != root && (checkpointPathWithin(path, root) || checkpointPathWithin(root, path)) {
			return "", errCheckpointOverlap
		}
	}
	return path, nil
}

// checkCheckpointMounts rejects attachments, bind aliases and nested mounts.
// A managed root's own overlay mount is the sole exception. A child of a
// separate mount is rejected too: its files may live outside the per-VM disk.
func checkCheckpointMounts(path string, managed bool, mounts io.Reader) error {
	scanner := bufio.NewScanner(mounts)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	seenRoot := false
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if len(fields) < 10 || separator < 6 || separator+3 >= len(fields) {
			return errCheckpointMount
		}
		point := unescape.Replace(fields[4])
		if !filepath.IsAbs(point) || filepath.Clean(point) != point {
			return errCheckpointMount
		}
		if point == "/" {
			seenRoot = true
			continue
		}
		if point == path && managed && fields[separator+1] == "overlay" {
			continue
		}
		if checkpointPathWithin(path, point) || checkpointPathWithin(point, path) {
			return errCheckpointMount
		}
	}
	if scanner.Err() != nil || !seenRoot {
		return errCheckpointMount
	}
	return nil
}

// openCheckpointDirectory pins the directory without following any component
// symlinks, using the agent's existing openat2 wrapper. Fail closed on kernels
// lacking that operation. The caller owns the returned descriptor.
//
// This is enrollment validation, not lifecycle locking. Before moving files or
// switching mounts, the manager must coordinate writers, revalidate mount/path
// identity, and use descriptor-relative operations. Guest processes can rename
// directories after validation; reopening this string would reintroduce a race.
func openCheckpointDirectory(raw string, managedRoots []string) (*os.File, string, error) {
	path, err := validateCheckpointPath(raw, managedRoots)
	if err != nil {
		return nil, "", err
	}
	fd, err := openat2NoSymlinks(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", errCheckpointPath
	}
	dir := os.NewFile(uintptr(fd), path)
	managed := false
	for _, root := range managedRoots {
		if filepath.Clean(root) == path {
			managed = true
			break
		}
	}
	mounts, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		dir.Close()
		return nil, "", errCheckpointMount
	}
	err = checkCheckpointMounts(path, managed, mounts)
	mounts.Close()
	if err != nil {
		dir.Close()
		return nil, "", err
	}
	return dir, path, nil
}

// Checkpoint mounts are guest-local. No layer is uploaded or placed outside the
// sandbox disk. A manifest is fsynced before a mount transition; on cold boot
// recovery restores that committed view before any user processes are started.
// Callers must quiesce writers. Busy checks detect existing use, not application
// transactions, and checkpoints are not suitable for capturing live databases.
type checkpointView struct {
	Layers []string `json:"layers"` // newest first; "base" is the original directory
	Upper  string   `json:"upper"`
	Parent *string  `json:"parent,omitempty"`
}
type checkpointEntry struct {
	proto.DirectoryCheckpoint
	Layers []string `json:"layers"`
}
type checkpointDirectory struct {
	Version int               `json:"version"`
	ID      string            `json:"id"`
	Path    string            `json:"path"`
	View    checkpointView    `json:"view"`
	Entries []checkpointEntry `json:"entries"`
	// Sealed means the original directory passed the post-enrollment reference
	// check. Until then no checkpoint may reference its original contents.
	Sealed bool `json:"sealed"`
}
type checkpointManager struct {
	storage string
	mu      sync.Mutex
	roots   map[string]*checkpointDirectory
	failed  error
}

var guestCheckpoints = &checkpointManager{storage: checkpointStorageDir}
var (
	errCheckpointBusy     = errors.New("directory is busy; stop processes using it and retry")
	errCheckpointMissing  = errors.New("checkpoint not found")
	errCheckpointLimit    = errors.New("checkpoint layer limit reached")
	errCheckpointRecovery = errors.New("checkpoint recovery is required")
)

func newCheckpointID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "cp_" + base64.RawURLEncoding.EncodeToString(b[:]), nil
}
func (m *checkpointManager) dir(d *checkpointDirectory) string { return filepath.Join(m.storage, d.ID) }
func (m *checkpointManager) layer(d *checkpointDirectory, id string) string {
	return filepath.Join(m.dir(d), id)
}
func (m *checkpointManager) manifest(d *checkpointDirectory) string {
	return filepath.Join(m.dir(d), "state.json")
}

func checkpointAtomicJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	// Never publish a record larger than boot recovery is willing to read.
	if len(data) > checkpointMaxManifestBytes {
		return errCheckpointLimit
	}
	// A random, exclusive temporary file never follows a preexisting symlink.
	f, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func validateCheckpointDirectory(d *checkpointDirectory) error {
	if d.Version != 1 || proto.ValidateCheckpointID(d.ID) != nil {
		return errCheckpointRecovery
	}
	if p, err := validateCheckpointPath(d.Path, nil); err != nil || p != d.Path {
		return errCheckpointRecovery
	}
	validLayers := func(layers []string) bool {
		if len(layers) == 0 || len(layers) > 32 || layers[len(layers)-1] != "base" {
			return false
		}
		seen := map[string]bool{}
		for _, id := range layers {
			if seen[id] || (id != "base" && proto.ValidateCheckpointID(id) != nil) {
				return false
			}
			seen[id] = true
		}
		return true
	}
	if proto.ValidateCheckpointID(d.View.Upper) != nil || !validLayers(d.View.Layers) || len(d.Entries) > 128 || (!d.Sealed && len(d.Entries) != 0) {
		return errCheckpointRecovery
	}
	for _, layer := range d.View.Layers {
		if layer == d.View.Upper {
			return errCheckpointRecovery
		}
	}
	ids := map[string]bool{}
	for _, e := range d.Entries {
		if proto.ValidateCheckpointID(e.ID) != nil || ids[e.ID] || e.Path != d.Path || !validLayers(e.Layers) {
			return errCheckpointRecovery
		}
		if e.ParentID != nil && proto.ValidateCheckpointID(*e.ParentID) != nil {
			return errCheckpointRecovery
		}
		if proto.ValidateCheckpointName(e.Name) != nil {
			return errCheckpointRecovery
		}
		for _, layer := range e.Layers {
			if layer == d.View.Upper {
				return errCheckpointRecovery
			}
		}
		ids[e.ID] = true
	}
	if d.View.Parent != nil && proto.ValidateCheckpointID(*d.View.Parent) != nil {
		return errCheckpointRecovery
	}
	return nil
}

// initialize is also called before guest services start, so disk-based restores
// recreate the original-directory bind and live OverlayFS mounts. A full memory
// restore retains both the manager and mounts and needs no reconstruction.
func (m *checkpointManager) initialize() error {
	if m.failed != nil {
		return m.failed
	}
	if m.roots != nil {
		return nil
	}
	m.roots = make(map[string]*checkpointDirectory)
	entries, err := os.ReadDir(m.storage)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		m.failed = err
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || proto.ValidateCheckpointID(entry.Name()) != nil {
			continue
		}
		path := filepath.Join(m.storage, entry.Name(), "state.json")
		fd, e := openat2NoSymlinks(path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if os.IsNotExist(e) {
			continue
		} // preparation never committed
		if e != nil {
			m.failed = e
			return e
		}
		f := os.NewFile(uintptr(fd), path)
		var d checkpointDirectory
		dec := json.NewDecoder(io.LimitReader(f, checkpointMaxManifestBytes+1))
		dec.DisallowUnknownFields()
		e = dec.Decode(&d)
		var extra any
		if e == nil && dec.Decode(&extra) != io.EOF {
			e = errCheckpointRecovery
		}
		f.Close()
		if e == nil {
			e = validateCheckpointDirectory(&d)
		}
		if e != nil || d.ID != entry.Name() {
			m.failed = errCheckpointRecovery
			return m.failed
		}
		var roots []string
		for p := range m.roots {
			roots = append(roots, p)
		}
		if _, e = validateCheckpointPath(d.Path, roots); e != nil || m.roots[d.Path] != nil {
			m.failed = errCheckpointRecovery
			return m.failed
		}
		m.roots[d.Path] = &d
	}
	for _, d := range m.roots {
		if err = m.recoverDirectory(d); err != nil {
			m.failed = err
			return err
		}
	}
	return nil
}

func (m *checkpointManager) rootsList() []string {
	out := make([]string, 0, len(m.roots))
	for path := range m.roots {
		out = append(out, path)
	}
	return out
}

// mountinfo identifies the *top* mount through the opened directory's mnt_id,
// rather than trusting any overlay mount that happens to use the same path.
func checkpointMountInfo(path string) (string, error) {
	fd, err := openat2NoSymlinks(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer syscall.Close(fd)
	info, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		return "", err
	}
	id := ""
	for _, line := range strings.Split(string(info), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "mnt_id:" {
			id = fields[1]
		}
	}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), 1<<20)
	for s.Scan() {
		if strings.HasPrefix(s.Text(), id+" ") && id != "" {
			return s.Text(), nil
		}
	}
	return "", errCheckpointMount
}
func (m *checkpointManager) viewMatches(d *checkpointDirectory) bool {
	line, err := checkpointMountInfo(d.Path)
	if err != nil {
		return false
	}
	parts := strings.SplitN(line, " - ", 2)
	if len(parts) != 2 {
		return false
	}
	fields := strings.Fields(parts[1])
	if len(fields) < 3 || fields[0] != "overlay" {
		return false
	}
	upper, lower := "", ""
	for _, opt := range strings.Split(fields[2], ",") {
		if strings.HasPrefix(opt, "upperdir=") {
			upper = strings.TrimPrefix(opt, "upperdir=")
		}
		if strings.HasPrefix(opt, "lowerdir=") {
			lower = strings.TrimPrefix(opt, "lowerdir=")
		}
	}
	return upper == m.layer(d, d.View.Upper) && lower == m.lowerOption(d)
}
func (m *checkpointManager) lowerOption(d *checkpointDirectory) string {
	paths := make([]string, len(d.View.Layers))
	for i, id := range d.View.Layers {
		paths[i] = m.layer(d, id)
	}
	return strings.Join(paths, ":")
}
func (m *checkpointManager) mountView(d *checkpointDirectory) error {
	for _, id := range append(append([]string{}, d.View.Layers...), d.View.Upper, d.View.Upper+"-work") {
		fd, err := openat2NoSymlinks(m.layer(d, id), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		syscall.Close(fd)
	}
	opts := "lowerdir=" + m.lowerOption(d) + ",upperdir=" + m.layer(d, d.View.Upper) + ",workdir=" + m.layer(d, d.View.Upper+"-work") + ",index=off,redirect_dir=off,metacopy=off"
	if len(opts) >= 4096 {
		return errCheckpointLimit
	}
	fd, err := openat2NoSymlinks(d.Path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return syscall.Mount("overlay", fmt.Sprintf("/proc/self/fd/%d", fd), "overlay", syscall.MS_NOATIME, opts)
}
func checkpointBindRO(source, target string) error {
	if err := syscall.Mount(source, target, "", syscall.MS_BIND, ""); err != nil {
		return err
	}
	if err := syscall.Mount("", target, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
		_ = syscall.Unmount(target, 0)
		return err
	}
	return nil
}
func (m *checkpointManager) newUpper(d *checkpointDirectory) error {
	id, err := newCheckpointID()
	if err != nil {
		return err
	}
	if err = os.Mkdir(m.layer(d, id), 0700); err != nil {
		return err
	}
	prepared := false
	defer func() {
		if !prepared {
			_ = os.RemoveAll(m.layer(d, id+"-work"))
			_ = os.RemoveAll(m.layer(d, id))
		}
	}()
	if err = os.Mkdir(m.layer(d, id+"-work"), 0700); err != nil {
		return err
	}
	source := d.Path
	if len(d.View.Layers) > 1 {
		source = m.layer(d, d.View.Layers[0])
	}
	if err = checkpointCopyDirectoryMetadata(source, m.layer(d, id)); err != nil {
		return err
	}
	d.View.Upper = id
	prepared = true
	return nil
}

// recoverDirectory is called only at boot, before accepting guest requests.
// Never stack a new view on an unknown live mount or substitute missing layers.
func (m *checkpointManager) recoverDirectory(d *checkpointDirectory) error {
	if m.viewMatches(d) {
		return nil
	}
	f, _, err := openCheckpointDirectory(d.Path, nil)
	if err != nil {
		return err
	}
	defer f.Close()
	base := m.layer(d, "base")
	if err = checkpointBindRO(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), base); err != nil {
		return err
	}
	if err = checkpointBindGuard(base, d.Path, f); err != nil {
		return err
	}
	return m.mountView(d)
}

// Busy detection covers cwd/root, descriptors and mmap-only references. It is
// conservative, and is not an alternative to the caller quiescing its writers.
func checkpointDirectoryBusy(path string, originalDev *uint64, ignoreFD ...int) error {
	processes, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, p := range processes {
		pid, e := strconv.Atoi(p.Name())
		if e != nil {
			continue
		}
		base := "/proc/" + p.Name()
		links := []string{base + "/cwd", base + "/root"}
		for _, sub := range []string{"fd", "map_files"} {
			entries, e := os.ReadDir(base + "/" + sub)
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				return errCheckpointBusy
			}
			for _, entry := range entries {
				links = append(links, base+"/"+sub+"/"+entry.Name())
			}
		}
		for _, link := range links {
			ignored := false
			if pid == os.Getpid() {
				for _, fd := range ignoreFD {
					if link == fmt.Sprintf("/proc/%d/fd/%d", pid, fd) {
						ignored = true
						break
					}
				}
			}
			if ignored {
				continue
			}
			name, e := os.Readlink(link)
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				return errCheckpointBusy
			}
			name = strings.TrimSuffix(name, " (deleted)")
			if !checkpointPathWithin(name, path) {
				continue
			}
			if originalDev != nil {
				var st syscall.Stat_t
				if e = syscall.Stat(link, &st); os.IsNotExist(e) {
					continue
				}
				if e != nil {
					return errCheckpointBusy
				}
				if st.Dev != *originalDev {
					continue
				}
			}
			return errCheckpointBusy
		}
	}
	return nil
}

// OverlayFS without an index can split lower hardlinks during copy-up. The
// original root overlay cannot provide the export handles required for an
// indexed lower. Reject links rather than silently change alias semantics.
func checkpointCheckLinks(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() && !info.IsDir() {
			return fmt.Errorf("%w: special files are not supported", errCheckpointPath)
		}
		if info.Mode().IsRegular() && info.Sys().(*syscall.Stat_t).Nlink > 1 {
			return fmt.Errorf("%w: hardlinked files are not supported", errCheckpointPath)
		}
		return nil
	})
}

func (m *checkpointManager) enroll(path string) (*checkpointDirectory, error) {
	f, path, err := openCheckpointDirectory(path, m.rootsList())
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err = checkpointDirectoryBusy(path, nil, int(f.Fd())); err != nil {
		return nil, err
	}
	if err = checkpointCheckLinks(path); err != nil {
		return nil, err
	}
	if err = os.MkdirAll(m.storage, 0700); err != nil {
		return nil, err
	}
	fd, err := openat2NoSymlinks(m.storage, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	syscall.Close(fd)
	id, err := newCheckpointID()
	if err != nil {
		return nil, err
	}
	d := &checkpointDirectory{Version: 1, ID: id, Path: path, View: checkpointView{Layers: []string{"base"}}, Entries: []checkpointEntry{}}
	if err = os.Mkdir(m.dir(d), 0700); err != nil {
		return nil, err
	}
	// Until the manifest exists no mount or user content has changed. Failed
	// preparations can be removed; an ambiguous manifest commit must be retained.
	defer func() {
		if _, e := os.Stat(m.manifest(d)); os.IsNotExist(e) {
			_ = os.RemoveAll(m.dir(d))
		}
	}()
	if err = os.Mkdir(m.layer(d, "base"), 0700); err != nil {
		return nil, err
	}
	if err = m.newUpper(d); err != nil {
		return nil, err
	}
	if err = checkpointSyncFS(m.storage); err != nil {
		return nil, err
	}
	// Record the view before exposing it. Recovery can complete enrollment even
	// if the machine loses power between either bind mount and the overlay mount.
	if err = checkpointAtomicJSON(m.manifest(d), d); err != nil {
		if _, e := os.Stat(m.manifest(d)); !os.IsNotExist(e) {
			m.failed = err
		}
		return nil, err
	}
	m.roots[path] = d
	if err = checkpointBindRO(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), m.layer(d, "base")); err != nil {
		m.failed = err
		return nil, err
	}
	if err = checkpointBindGuard(m.layer(d, "base"), path, f); err != nil {
		m.failed = err
		return nil, err
	}
	if err = m.mountView(d); err != nil {
		m.failed = err
		return nil, err
	}
	return d, nil
}

func (m *checkpointManager) seal(d *checkpointDirectory) error {
	if d.Sealed {
		return nil
	}
	var st syscall.Stat_t
	if err := syscall.Stat(m.layer(d, "base"), &st); err != nil {
		return err
	}
	if err := checkpointDirectoryBusy(d.Path, &st.Dev); err != nil {
		return err
	}
	if err := checkpointCheckLinks(m.layer(d, "base")); err != nil {
		return err
	}
	d.Sealed = true
	return checkpointAtomicJSON(m.manifest(d), d)
}

// switchView persists the chosen view before making it visible. EBUSY never
// permits a forced/lazy unmount. The read-only guard remains mounted underneath
// the live overlay, so an intervening open cannot write to a saved base layer.
func (m *checkpointManager) switchView(old, next *checkpointDirectory) error {
	if !m.viewMatches(old) {
		return errCheckpointMount
	}
	if err := checkpointDirectoryBusy(old.Path, nil); err != nil {
		return err
	}
	// Persist file data before publishing a checkpoint record.
	if err := checkpointSyncFS(m.layer(old, old.View.Upper)); err != nil {
		return err
	}
	if err := syscall.Unmount(old.Path, 0); err != nil {
		if errors.Is(err, syscall.EBUSY) {
			return errCheckpointBusy
		}
		return err
	}
	// Re-sync after unmount: a writer may have closed between the first sync
	// and the kernel's final busy check. No writer can now reach the old upper.
	if err := checkpointSyncFS(m.layer(old, old.View.Upper)); err != nil {
		if rollback := m.mountView(old); rollback != nil {
			m.failed = rollback
		}
		return err
	}
	if err := checkpointAtomicJSON(m.manifest(next), next); err != nil {
		// The rename may have committed even if directory fsync failed. Do not
		// expose either view until durable metadata and the mount agree again.
		if rollback := checkpointAtomicJSON(m.manifest(old), old); rollback != nil {
			m.failed = rollback
			return err
		}
		if rollback := m.mountView(old); rollback != nil {
			m.failed = rollback
		}
		return err
	}
	if err := m.mountView(next); err != nil {
		if rollback := checkpointAtomicJSON(m.manifest(old), old); rollback != nil {
			m.failed = rollback
			return err
		}
		if rollback := m.mountView(old); rollback != nil {
			m.failed = rollback
		}
		return err
	}
	m.roots[next.Path] = next
	m.gc(next)
	return nil
}
func checkpointSyncFS(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, _, errno := syscall.Syscall(checkpointSyncFSNumber(), f.Fd(), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
func cloneCheckpointDirectory(d *checkpointDirectory) *checkpointDirectory {
	n := *d
	n.View.Layers = append([]string{}, d.View.Layers...)
	n.Entries = append([]checkpointEntry{}, d.Entries...)
	return &n
}
func (m *checkpointManager) create(req proto.CheckpointCreateReq) (proto.DirectoryCheckpoint, error) {
	var empty proto.DirectoryCheckpoint
	path, err := validateCheckpointPath(req.Path, m.rootsList())
	if err != nil {
		return empty, err
	}
	d := m.roots[path]
	if d == nil {
		d, err = m.enroll(path)
		if err != nil {
			return empty, err
		}
	}
	if err = checkpointCheckLinks(path); err != nil {
		return empty, err
	}
	if err = m.seal(d); err != nil {
		return empty, err
	}
	if len(d.View.Layers) >= 32 || len(d.Entries) >= 128 {
		return empty, errCheckpointLimit
	}
	n := cloneCheckpointDirectory(d)
	id, err := newCheckpointID()
	if err != nil {
		return empty, err
	}
	e := checkpointEntry{DirectoryCheckpoint: proto.DirectoryCheckpoint{ID: id, Path: path, Name: req.Name, ParentID: d.View.Parent, CreatedAt: time.Now().UTC()}, Layers: append([]string{d.View.Upper}, d.View.Layers...)}
	n.Entries = append(n.Entries, e)
	n.View.Layers = e.Layers
	n.View.Parent = &id
	if err = m.newUpper(n); err != nil {
		return empty, err
	}
	if err = m.switchView(d, n); err != nil {
		m.gc(d)
		return empty, err
	}
	return e.DirectoryCheckpoint, nil
}
func (m *checkpointManager) lookup(id string) (*checkpointDirectory, int) {
	for _, d := range m.roots {
		for i, e := range d.Entries {
			if e.ID == id {
				return d, i
			}
		}
	}
	return nil, 0
}
func (m *checkpointManager) restore(id string) (proto.CheckpointRestoreResp, error) {
	var empty proto.CheckpointRestoreResp
	d, i := m.lookup(id)
	if d == nil {
		return empty, errCheckpointMissing
	}
	n := cloneCheckpointDirectory(d)
	n.View.Layers = append([]string{}, d.Entries[i].Layers...)
	n.View.Parent = &id
	if err := m.newUpper(n); err != nil {
		return empty, err
	}
	if err := m.switchView(d, n); err != nil {
		m.gc(d)
		return empty, err
	}
	return proto.CheckpointRestoreResp{CheckpointID: id, Path: d.Path}, nil
}
func (m *checkpointManager) delete(id string) error {
	d, i := m.lookup(id)
	if d == nil {
		return errCheckpointMissing
	}
	if !m.viewMatches(d) {
		return errCheckpointMount
	}
	n := cloneCheckpointDirectory(d)
	n.Entries = append(n.Entries[:i], n.Entries[i+1:]...)
	if err := checkpointAtomicJSON(m.manifest(n), n); err != nil {
		m.failed = err
		return err
	}
	m.roots[n.Path] = n
	m.gc(n)
	return nil
}
func (m *checkpointManager) list() []proto.DirectoryCheckpoint {
	out := []proto.DirectoryCheckpoint{}
	for _, d := range m.roots {
		for _, e := range d.Entries {
			out = append(out, e.DirectoryCheckpoint)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}
func (m *checkpointManager) gc(d *checkpointDirectory) {
	if m.failed != nil || !m.viewMatches(d) {
		return
	}
	keep := map[string]bool{"base": true, d.View.Upper: true, d.View.Upper + "-work": true}
	for _, id := range d.View.Layers {
		keep[id] = true
	}
	for _, e := range d.Entries {
		for _, id := range e.Layers {
			keep[id] = true
		}
	}
	entries, err := os.ReadDir(m.dir(d))
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if keep[name] || proto.ValidateCheckpointID(strings.TrimSuffix(name, "-work")) != nil {
			continue
		}
		// Only unreferenced generated layer directories, never the original base
		// bind, manifests, or arbitrary names supplied in a request, are removed.
		if err = os.RemoveAll(m.layer(d, name)); err != nil {
			log.Printf("agent.checkpoint event=gc_failed root_id=%s layer=%s error=%v", d.ID, name, err)
		}
	}
}

// syncfs is not exposed by the frozen stdlib syscall package.
func checkpointSyncFSNumber() uintptr {
	if runtime.GOARCH == "amd64" {
		return 306
	}
	return 267 // arm64 uses the generic Linux syscall table
}

func checkpointCopyDirectoryMetadata(source, target string) error {
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	st := info.Sys().(*syscall.Stat_t)
	if err = os.Chown(target, int(st.Uid), int(st.Gid)); err != nil {
		return err
	}
	if err = os.Chmod(target, info.Mode()); err != nil {
		return err
	}
	size, err := syscall.Listxattr(source, nil)
	if errors.Is(err, syscall.ENOTSUP) {
		return nil
	}
	if err != nil {
		return err
	}
	names := make([]byte, size)
	if _, err = syscall.Listxattr(source, names); err != nil {
		return err
	}
	for _, name := range strings.Split(string(names), "\x00") {
		if name == "" || strings.HasPrefix(name, "trusted.overlay.") {
			continue
		}
		n, e := syscall.Getxattr(source, name, nil)
		if e != nil {
			return e
		}
		value := make([]byte, n)
		if _, e = syscall.Getxattr(source, name, value); e != nil {
			return e
		}
		if e = syscall.Setxattr(target, name, value, 0); e != nil {
			return e
		}
	}
	return os.Chtimes(target, time.Unix(st.Atim.Sec, st.Atim.Nsec), time.Unix(st.Mtim.Sec, st.Mtim.Nsec))
}

// The base bind is already read-only; a second bind inherits those flags. Bind
// onto the pinned original directory, not a caller-controlled pathname. Do not
// remount through its pre-bind fd: that fd belongs to the parent root mount.
func checkpointBindGuard(base, path string, original *os.File) error {
	target := fmt.Sprintf("/proc/self/fd/%d", original.Fd())
	if err := syscall.Mount(base, target, "", syscall.MS_BIND, ""); err != nil {
		return err
	}
	fd, err := openat2NoSymlinks(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	actual := os.NewFile(uintptr(fd), path)
	defer actual.Close()
	before, err := original.Stat()
	if err != nil {
		return err
	}
	after, err := actual.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, after) {
		return errCheckpointMount
	}
	return nil
}
