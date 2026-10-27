package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/NodeOps-app/sandbox/internal/proto"
)

// diskRuntimeRoot is the tmpfs-backed scratch dir where each attachment's
// per-mount files live. /run is tmpfs in the devbox rootfs.
//
// Per-attachment layout (one disk can be mounted at multiple paths in
// the same VM, so directories must be keyed by both):
//
//	/run/createos/disks/<dirkey>/passwd-s3fs   — mode 0600, "access:secret"
//	/run/createos/disks/<dirkey>/mount_path    — the absolute mount path
//
// `dirkey` is `<disk_id>--<8-hex-of-sha1(mount_path)>` so two attachments
// of the same disk at different mount paths get distinct dirs. The
// pre-pause hook walks $base/*/ + reads $dir/mount_path so it doesn't
// care about the dirkey shape.
const diskRuntimeRoot = "/run/createos/disks"

// diskKey identifies one attachment in agent-local maps. (Two mounts of
// the same disk at different paths are independent attachments.)
type diskKey struct {
	ID        string
	MountPath string
}

// diskStatus is the per-attachment tri-state surfaced via /disks/status.
type diskStatus struct {
	DiskID    string `json:"disk_id"`
	MountPath string `json:"mount_path"`
	Status    string `json:"status"`          // "pending" | "mounted" | "failed"
	Error     string `json:"error,omitempty"` // truncated to 1 KiB
}

// diskState is the agent-local view of which attachments have been
// mounted and what their current status is. Read by the /disks/status
// endpoint; written by applyDisks under stateMu.
var (
	applyMu     sync.Mutex // serialize mount/unmount side effects across both reconcilers
	stateMu     sync.RWMutex
	diskStates  = map[diskKey]diskStatus{}
	diskHashes  = map[diskKey]string{} // per-entry content hash for cred-rotation detection
	lastApplied = ""                   // hash of last applied disks set to dedup
)

// diskEntryHash returns a content fingerprint over the fields that
// determine the s3fs invocation: bucket / endpoint / creds / sub-path.
// mount_path and disk_id are NOT included because they're the key.
// A change here means the existing mount is now wrong (e.g. credentials
// rotated via PATCH /v1/disks/:id) and must be unmounted + re-run.
func diskEntryHash(d proto.MMDSDisk) string {
	h := sha256.New()
	h.Write([]byte(d.Config.Bucket))
	h.Write([]byte{0})
	h.Write([]byte(d.Config.Endpoint))
	h.Write([]byte{0})
	h.Write([]byte(d.Config.Region))
	h.Write([]byte{0})
	if d.Config.UsePathStyle {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	h.Write([]byte(d.SubPath))
	h.Write([]byte{0})
	h.Write([]byte(d.Credentials.AccessKey))
	h.Write([]byte{0})
	h.Write([]byte(d.Credentials.SecretKey))
	return hex.EncodeToString(h.Sum(nil))
}

// diskRuntimeDir returns the per-attachment tmpfs subdir. Same disk at
// two different mount paths gets two distinct dirs.
func diskRuntimeDir(diskID, mountPath string) string {
	h := sha256.Sum256([]byte(mountPath))
	return filepath.Join(diskRuntimeRoot, diskID+"--"+hex.EncodeToString(h[:4]))
}

// applyDisks is the agent-side reconciler. Idempotent: called on every
// MMDS change. Mounts new attachments, unmounts ones that disappeared,
// and refreshes diskStates so /disks/status is current.
func applyDisks(disks []proto.MMDSDisk) {
	applyMu.Lock()
	defer applyMu.Unlock()
	h := hashDisks(disks)
	stateMu.RLock()
	prev := lastApplied
	stateMu.RUnlock()
	if h == prev {
		return
	}
	if err := os.MkdirAll(diskRuntimeRoot, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "agent: mkdir %s: %v\n", diskRuntimeRoot, err)
		return
	}

	// Build desired set, then reconcile against the previous in-memory
	// set so vanished attachments get unmounted. Keyed by (id, mount)
	// so two mounts of the same disk are independent.
	desired := make(map[diskKey]proto.MMDSDisk, len(disks))
	for _, d := range disks {
		desired[diskKey{ID: d.ID, MountPath: d.MountPath}] = d
	}

	stateMu.Lock()
	prevKeys := make([]diskKey, 0, len(diskStates))
	for k := range diskStates {
		prevKeys = append(prevKeys, k)
	}
	stateMu.Unlock()

	blockedMounts := make(map[string]bool)
	// Unmount + clean up attachments that are no longer in the desired set.
	for _, k := range prevKeys {
		if _, ok := desired[k]; ok {
			continue
		}
		stateMu.RLock()
		st := diskStates[k]
		stateMu.RUnlock()
		if err := unmountDisk(st.MountPath); err != nil {
			updateStatus(k.ID, k.MountPath, "failed", truncErr("unmount: "+err.Error()))
			blockedMounts[k.MountPath] = true
			continue // retain tracking and credentials until cleanup succeeds
		}
		_ = os.RemoveAll(diskRuntimeDir(k.ID, k.MountPath))
		stateMu.Lock()
		delete(diskStates, k)
		delete(diskHashes, k)
		stateMu.Unlock()
	}

	// Detect in-place content changes (e.g. PATCH /v1/disks credential
	// rotation). For every desired entry that's already in our state
	// map, compare its content hash to the one we recorded at last
	// mount; if it changed, unmount so mountOneS3 below sees an empty
	// mount point and re-runs s3fs with the new creds.
	for _, d := range disks {
		if d.Kind != "s3" {
			continue
		}
		k := diskKey{ID: d.ID, MountPath: d.MountPath}
		stateMu.RLock()
		prevHash, hadPrev := diskHashes[k]
		stateMu.RUnlock()
		newHash := diskEntryHash(d)
		if hadPrev && prevHash != newHash {
			if err := unmountDisk(d.MountPath); err != nil {
				updateStatus(d.ID, d.MountPath, "failed", truncErr("unmount: "+err.Error()))
				blockedMounts[d.MountPath] = true
			}
		}
	}

	// Mount each desired entry. Idempotent — re-running on an already-
	// mounted target is a no-op.
	for _, d := range disks {
		if d.Kind != "s3" {
			updateStatus(d.ID, d.MountPath, "failed",
				fmt.Sprintf("unsupported disk kind %q", d.Kind))
			continue
		}
		if !blockedMounts[d.MountPath] {
			mountOneS3(d)
		}
	}

	stateMu.Lock()
	lastApplied = h
	stateMu.Unlock()
}

// mountOneS3 mounts a single S3 disk via geesefs (parallel Go FUSE
// client). Fails the attachment with a clear error when geesefs is
// missing from the rootfs — older devbox / template images without it
// must be rebuilt off the current base.
func mountOneS3(d proto.MMDSDisk) {
	if d.MountPath == "" {
		updateStatus(d.ID, "", "failed", "empty mount_path")
		return
	}
	if d.Config.Bucket == "" || d.Config.Endpoint == "" {
		updateStatus(d.ID, d.MountPath, "failed", "bucket and endpoint required")
		return
	}
	if d.Credentials.AccessKey == "" || d.Credentials.SecretKey == "" {
		updateStatus(d.ID, d.MountPath, "failed", "credentials missing")
		return
	}

	dir := diskRuntimeDir(d.ID, d.MountPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		updateStatus(d.ID, d.MountPath, "failed", "creds dir: "+err.Error())
		return
	}
	passwd := []byte(d.Credentials.AccessKey + ":" + d.Credentials.SecretKey + "\n")
	passwdFile := filepath.Join(dir, "passwd-s3fs")
	if err := os.WriteFile(passwdFile, passwd, 0o600); err != nil {
		updateStatus(d.ID, d.MountPath, "failed", "creds write: "+err.Error())
		return
	}
	// Record mount_path next to the creds so the pre-pause hook can
	// enumerate live mounts without parsing MMDS itself.
	_ = os.WriteFile(filepath.Join(dir, "mount_path"), []byte(d.MountPath+"\n"), 0o600)

	if err := os.MkdirAll(d.MountPath, 0o755); err != nil {
		updateStatus(d.ID, d.MountPath, "failed", "mountpoint: "+err.Error())
		return
	}

	if isMounted(d.MountPath) {
		updateStatus(d.ID, d.MountPath, "mounted", "")
		stateMu.Lock()
		diskHashes[diskKey{ID: d.ID, MountPath: d.MountPath}] = diskEntryHash(d)
		stateMu.Unlock()
		// Already mounted (e.g. carried over from a previous apply, or
		// raced with a parallel mount). Still warm — on a pause/resume
		// the FUSE socket got recycled even if our state map didn't.
		go warmS3Mount(d.MountPath)
		return
	}

	geesePath := findGeeseFS()
	if geesePath == "" {
		updateStatus(d.ID, d.MountPath, "failed", "geesefs binary not found in rootfs")
		return
	}
	mountOneGeeseFS(d, geesePath, dir)
}

// guestMemLimitMiB returns ~25% of MemTotal in MiB, clamped to a
// 64 MiB floor and a 4 GiB ceiling. Used to size geesefs's stale-
// content cache so it can't outgrow the VM's RAM.
func guestMemLimitMiB() int {
	const (
		floorMiB = 64
		ceilMiB  = 4096
	)
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return floorMiB
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			break
		}
		kib, err := strconv.Atoi(f[1])
		if err != nil {
			break
		}
		mib := kib / 1024 / 4 // 25%
		if mib < floorMiB {
			return floorMiB
		}
		if mib > ceilMiB {
			return ceilMiB
		}
		return mib
	}
	return floorMiB
}

// findGeeseFS returns the absolute path to geesefs if present, or "".
// Static binary, baked into base-debian / base-alpine.
func findGeeseFS() string {
	if p, err := exec.LookPath("geesefs"); err == nil {
		return p
	}
	for _, cand := range []string{"/usr/local/bin/geesefs", "/usr/bin/geesefs"} {
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return ""
}

// mountOneGeeseFS spawns geesefs for one attachment. dir is the
// per-attachment runtime tmpdir (already created, holds passwd-s3fs
// + mount_path marker).
func mountOneGeeseFS(d proto.MMDSDisk, geesePath, dir string) {
	// geesefs reads creds from an AWS-style INI file. Write one
	// alongside the s3fs passwd file so the pre-pause hook + s3fs
	// fallback keep working without modification.
	creds := fmt.Sprintf("[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n",
		d.Credentials.AccessKey, d.Credentials.SecretKey)
	credsFile := filepath.Join(dir, "aws-credentials")
	if err := os.WriteFile(credsFile, []byte(creds), 0o600); err != nil {
		updateStatus(d.ID, d.MountPath, "failed", "geesefs creds write: "+err.Error())
		return
	}

	args := []string{
		"--endpoint=" + d.Config.Endpoint,
		"--shared-config=" + credsFile,
		"-o", "allow_other",
		// Background daemonise after mount is ready, matching s3fs UX.
		"-f=false",
		// Daemon mode defaults to syslog, but the guest has no /dev/log and
		// geesefs closes stdout/stderr after mounting. Give it a real sink so
		// an ERROR log (for example, unsupported link(2)) cannot kill the
		// daemon and disconnect the FUSE mount.
		"--log-file=" + filepath.Join(dir, "geesefs.log"),
		// Cap geesefs's in-memory stale-content cache to ~25% of the
		// guest's RAM. Default is 1000 MiB, which is larger than total
		// RAM on a 0.25c/512mb shape — under sustained I/O the kernel
		// OOM would fire before geesefs evicts. Floor at 64 MiB so
		// tiny shapes still get a workable cache.
		fmt.Sprintf("--memory-limit=%d", guestMemLimitMiB()),
		// Worst-case multi-attach staleness window. Default 1m means
		// a write from VM-A is invisible to VM-B for up to 60 s. Drop
		// to 10 s — every open()/stat() inside the window is still
		// served from local cache, so this only costs an extra S3
		// HEAD on the first access after the TTL expires.
		"--stat-cache-ttl=10s",
	}
	if d.Config.Region != "" {
		args = append(args, "--region="+d.Config.Region)
	}
	// In-bucket prefix: geesefs uses positional `bucket:prefix` syntax
	// (no leading slash) — it doesn't have an --subdir flag. Empty
	// SubPath = mount bucket root. geesefs synthesises any missing
	// directory markers itself, so no compat_dir-style helper needed.
	source := d.Config.Bucket
	if sp := strings.Trim(d.SubPath, "/"); sp != "" {
		source = d.Config.Bucket + ":" + sp
	}
	args = append(args, "--", source, d.MountPath)

	cmd := exec.Command(geesePath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		if len(msg) > 1024 {
			msg = msg[:1024]
		}
		updateStatus(d.ID, d.MountPath, "failed", msg)
		return
	}
	if !isMounted(d.MountPath) {
		updateStatus(d.ID, d.MountPath, "failed", "geesefs returned but mount not visible")
		return
	}
	updateStatus(d.ID, d.MountPath, "mounted", "")
	stateMu.Lock()
	diskHashes[diskKey{ID: d.ID, MountPath: d.MountPath}] = diskEntryHash(d)
	stateMu.Unlock()
	go warmS3Mount(d.MountPath)
}

// warmS3Mount issues a single readdir against the mount root to force
// s3fs to populate its bucket-metadata cache + dial its endpoint
// connection pool. Bounded by a short deadline so a wedged endpoint
// can't leak a goroutine across many resumes.
func warmS3Mount(mountPath string) {
	if mountPath == "" {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		// One opendir+readdir+closedir against s3fs translates into
		// one LIST against the bucket — the minimum needed to seed
		// s3fs's directory cache.
		_, _ = os.ReadDir(mountPath)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		// Endpoint slow or wedged. Drop the warm — the user's own
		// request will pay the cost (or fail loudly), which is
		// better than holding a goroutine forever.
	}
}

func unmountDisk(mountPath string) error {
	if mountPath == "" {
		return nil
	}
	mounted, err := mountPresent(mountPath)
	if err != nil || !mounted {
		return err
	}
	// Bound both attempts: an unhealthy FUSE mount must not stall MMDS
	// reconciliation forever. Lazy unmount detaches busy mounts immediately.
	var lastErr error
	for _, option := range []string{"-u", "-uz"} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		lastErr = exec.CommandContext(ctx, "fusermount", option, mountPath).Run()
		cancel()
		mounted, err := mountPresent(mountPath)
		if err != nil {
			return err
		}
		if !mounted {
			return nil
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("mount remains attached at %s", mountPath)
}

// isMounted parses /proc/self/mounts and reports whether any mountpoint
// matches the given absolute path. Stdlib only. Both sides are
// path.Clean'd so a caller-supplied "//double" matches the kernel's
// canonical "/double" in /proc/self/mounts.
func isMounted(mp string) bool {
	mounted, _ := mountPresent(mp)
	return mounted
}

func mountPresent(mp string) (bool, error) {
	f, err := os.Open("/proc/self/mounts")
	if err != nil {
		return false, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return false, err
	}
	want := path.Clean(mp)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// /proc/mounts escapes whitespace and backslashes in mount paths.
		mountPath := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(fields[1])
		if path.Clean(mountPath) == want {
			return true, nil
		}
	}
	return false, nil
}

func updateStatus(diskID, mountPath, status, errMsg string) {
	stateMu.Lock()
	diskStates[diskKey{ID: diskID, MountPath: mountPath}] = diskStatus{
		DiskID:    diskID,
		MountPath: mountPath,
		Status:    status,
		Error:     errMsg,
	}
	stateMu.Unlock()
	switch status {
	case "failed":
		fmt.Fprintf(os.Stderr, "agent: disk %s mount at %s failed: %s\n", diskID, mountPath, errMsg)
	case "mounted":
		fmt.Printf("agent: disk %s mounted at %s\n", diskID, mountPath)
	}
}

// hashDisks returns a content hash of the desired disks set so the
// MMDS watcher can dedup re-applies. Order-independent: sorts by id
// before hashing.
func hashDisks(disks []proto.MMDSDisk) string {
	// Sort by ID to make this order-independent (in case MMDS reorders).
	// Simple insertion sort — N is small (typically 1–4 disks).
	sorted := make([]proto.MMDSDisk, len(disks))
	copy(sorted, disks)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j-1].ID > sorted[j].ID; j-- {
			sorted[j-1], sorted[j] = sorted[j], sorted[j-1]
		}
	}
	buf, err := json.Marshal(sorted)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

// resetDisksApplyCache busts the content-hash dedup used by applyDisks
// so the next watchMMDS tick treats the disks slice as fresh, even
// when the slice itself hasn't changed across pause/resume. We
// deliberately do NOT wipe diskStates here — the in-memory map is
// what applyDisks consults to figure out which attachments to
// unmount when they disappear from MMDS. Wiping it on resume would
// leave any pre-pause mount that wasn't taken down by the
// /etc/createos/pre-pause.d/ hooks stuck in the kernel mount table
// after resume (older rootfses don't ship the hook). With the map
// preserved, applyDisks correctly diffs the post-resume desired set
// against the still-mounted state and unmounts attachments that the
// user dropped while paused.
func resetDisksApplyCache() {
	stateMu.Lock()
	lastApplied = ""
	stateMu.Unlock()
}

// diskStatusSnapshot returns the current view of all disk statuses,
// safe to serialise via the /disks/status endpoint. Any entry currently
// in `mounted` is reachability-probed before being surfaced: a hung
// s3fs (egress blocked) or a dead s3fs (DNS blocked) gets demoted to
// `failed` with a short specific error string.
func diskStatusSnapshot() []diskStatus {
	stateMu.RLock()
	snap := make([]diskStatus, 0, len(diskStates))
	for _, s := range diskStates {
		snap = append(snap, s)
	}
	stateMu.RUnlock()
	for i := range snap {
		if snap[i].Status != "mounted" {
			continue
		}
		if ok, errMsg := probeMount(snap[i].MountPath); !ok {
			snap[i].Status = "failed"
			snap[i].Error = truncErr(errMsg)
		}
	}
	return snap
}

// probeMount checks an existing mountpoint is actually reachable.
// Pre-check: s3fs process for this mountpoint still alive (cheap; cuts
// the hung-statfs path when DNS blocked the daemon from starting or
// the daemon exited).
// Primary: statfs(2) with a 5 s timeout. Hung egress to the S3
// endpoint blocks statfs forever inside the FUSE driver; we run it in
// a goroutine and time-bound. ESTALE/EIO from statfs also count as
// unreachable.
func probeMount(mountPath string) (bool, string) {
	if mountPath == "" {
		return true, ""
	}
	if !s3fsAliveFor(mountPath) {
		return false, "s3fs process not running"
	}
	type res struct {
		err error
	}
	ch := make(chan res, 1)
	go func() {
		var st syscall.Statfs_t
		ch <- res{err: syscall.Statfs(mountPath, &st)}
	}()
	select {
	case r := <-ch:
		if r.err == nil {
			return true, ""
		}
		if r.err == syscall.ESTALE {
			return false, "s3fs unreachable: ESTALE"
		}
		if r.err == syscall.EIO {
			return false, "s3fs unreachable: EIO"
		}
		return false, "s3fs unreachable: " + r.err.Error()
	case <-time.After(5 * time.Second):
		return false, "s3fs unreachable: statfs timed out"
	}
}

// s3fsAliveFor scans /proc/*/cmdline for an s3fs process whose argv
// contains the given mount path. Stdlib only; cheap enough to run on
// every status poll (host polls every 30 s).
func s3fsAliveFor(mountPath string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		// If we can't read /proc, fall through to statfs probe.
		return true
	}
	want := path.Clean(mountPath)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "" || name[0] < '0' || name[0] > '9' {
			continue
		}
		data, err := os.ReadFile("/proc/" + name + "/cmdline")
		if err != nil || len(data) == 0 {
			continue
		}
		// cmdline is NUL-separated argv.
		argv := strings.Split(string(data), "\x00")
		if len(argv) == 0 {
			continue
		}
		exe := argv[0]
		// Match basename to handle absolute paths like /usr/bin/s3fs.
		if base := exe; len(base) > 0 {
			if i := strings.LastIndex(base, "/"); i >= 0 {
				base = base[i+1:]
			}
			if base != "geesefs" {
				continue
			}
		}
		for _, a := range argv[1:] {
			if a == "" {
				continue
			}
			if path.Clean(a) == want {
				return true
			}
		}
	}
	return false
}

// truncErr clips an error string to <1 KiB, matching the host-side
// mount_error truncation rule.
func truncErr(s string) string {
	if len(s) > 1024 {
		return s[:1024]
	}
	return s
}

// handleDiskStatus serves GET /disks/status — the agent-side surface
// the host polls to update sandbox_disks.mount_status in the DB.
// Mounted on the file-server mux in serveFilesOn.
func handleDiskStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(struct {
		Disks []diskStatus `json:"disks"`
	}{Disks: diskStatusSnapshot()}); err != nil {
		fmt.Fprintf(os.Stderr, "agent: encode disk status: %v\n", err)
	}
}

// runDiskApplyLoop spawns a slow background watcher that re-applies the
// disks from MMDS every diskApplyInterval. Catches "MMDS unchanged but a
// previous mount failed and we want to retry" without bothering the
// 2ms watchMMDS hot loop. Removed mounts are retried even with an empty doc.
const diskApplyInterval = 30 * time.Second

func runDiskApplyLoop() {
	for {
		time.Sleep(diskApplyInterval)
		doc, err := fetchMMDS(500 * time.Millisecond)
		if err != nil {
			continue
		}
		// Retry only the failed ones — leave mounted entries alone.
		stateMu.RLock()
		retry := false
		desired := make(map[diskKey]bool, len(doc.Disks))
		for _, d := range doc.Disks {
			desired[diskKey{ID: d.ID, MountPath: d.MountPath}] = true
			st, ok := diskStates[diskKey{ID: d.ID, MountPath: d.MountPath}]
			if !ok || st.Status != "mounted" {
				retry = true
			}
		}
		for key := range diskStates {
			if !desired[key] {
				retry = true
			}
		}
		stateMu.RUnlock()
		if !retry {
			continue
		}
		// Force re-apply by busting lastApplied. We pass the full doc.Disks
		// so disks that were removed get reconciled too.
		stateMu.Lock()
		lastApplied = ""
		stateMu.Unlock()
		applyDisks(doc.Disks)
	}
}
