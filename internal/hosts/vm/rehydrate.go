package vm

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// RehydrateSpec carries the persisted fields needed to re-attach to a
// firecracker VM that survived a serve restart. Populated by the caller
// from a store.Record. Keeping this type inside the vm package avoids a
// circular import on store.
type RehydrateSpec struct {
	Freezing              bool // durable reusable-capture freeze intent for this incarnation
	ID                    string
	IP                    string // VM IP, e.g. "192.168.0.4"
	MAC                   string
	ContainerID           string // netpool slot id, e.g. "fcp7"
	APISock               string // firecracker API socket path
	OverlayPath           string
	FCPid                 int
	VCPU                  int
	MemMib                int
	DiskMib               int64
	Rootfs                string
	Egress                []string
	BandwidthQuota        int64
	BandwidthUsed         int64
	BandwidthIngressBytes int64
	BandwidthCapped       bool
	SecretToken           string
	Envs                  map[string]string
}

// Rehydrate registers a previously-created, still-running VM in the
// Manager's in-memory map. Called at serve startup for every sandbox
// row whose firecracker process is still alive.
//
// Returns an error if the firecracker PID is gone or the netns has
// vanished — caller should mark the sandbox destroyed in that case.
//
// Note: the returned Sandbox has Machine==nil (the SDK handle cannot
// survive across a process restart). Destroy() has a branch that handles
// this by SIGTERMing the PID.
func (m *Manager) Rehydrate(spec RehydrateSpec) error {
	if spec.FCPid <= 0 {
		return fmt.Errorf("no fc_pid recorded")
	}
	if !pidIsFirecracker(spec.FCPid) {
		return fmt.Errorf("pid %d is not a live firecracker", spec.FCPid)
	}
	nsPath := NetnsPathRoot + spec.ContainerID
	if _, err := os.Stat(nsPath); err != nil {
		return fmt.Errorf("netns %s missing: %w", nsPath, err)
	}

	// Rebuild the /31 IPPair from the VM's IP. In our IPAM convention
	// the VM always takes the lower (even) address and the gateway is
	// vmIP+1. See enumeratePairs in ipam.go.
	gwIP, err := adjacentIP(spec.IP)
	if err != nil {
		return fmt.Errorf("gateway for %s: %w", spec.IP, err)
	}
	pair := IPPair{VMCIDR: spec.IP + "/31", Gateway: gwIP}

	_, ipnet, _ := net.ParseCIDR(pair.VMCIDR)

	// Reconstruct VsockCID from ContainerID — it's a stateless derivation
	// (cid = 100 + parsePoolN(containerID)) so we don't need a DB column.
	// Without this, pause's chown of /var/lib/createos/paused/<sb>/ to
	// the per-slot UID lands on UID 100000+0 = 100000 (root-adjacent)
	// instead of the real slot UID — and firecracker (running as the
	// real slot UID) gets EACCES on CreateSnapshot, the row stalls in
	// `destroying`, and the sweep eventually reaps it.
	cid := uint32(0)
	if n := parsePoolN(spec.ContainerID); n > 0 {
		cid = 100 + uint32(n)
	}
	pn := &PooledNet{
		NetNSPath:   nsPath,
		TapName:     "tap0",
		MAC:         spec.MAC,
		IP:          *ipnet,
		Gateway:     net.ParseIP(pair.Gateway),
		VMIfName:    "eth0",
		ContainerID: spec.ContainerID,
		VsockCID:    cid,
		pair:        pair,
		ipam:        m.Pool.IPAM(),
	}

	hostVeth, err := HostVethFor(spec.IP)
	if err != nil {
		// Not fatal — egress rules will be skipped. Still rehydrate the
		// sandbox so exec/destroy work.
		log.Warnf("[rehydrate] %s: HostVethFor(%s) failed: %v — egress unmanaged", spec.ID, spec.IP, err)
	}

	sb := &Sandbox{
		ID:              spec.ID,
		IP:              spec.IP,
		ApiSocket:       spec.APISock,
		Machine:         nil, // SDK handle cannot be reattached across restart
		FCPid:           spec.FCPid,
		Net:             pn,
		OverlayPath:     spec.OverlayPath,
		Rootfs:          spec.Rootfs,
		VCPU:            spec.VCPU,
		MemMib:          spec.MemMib,
		DiskMib:         spec.DiskMib,
		Egress:          spec.Egress,
		HostVeth:        hostVeth,
		BandwidthQuota:  spec.BandwidthQuota,
		BandwidthUsed:   spec.BandwidthUsed,
		BandwidthCapped: spec.BandwidthCapped,
		SecretToken:     spec.SecretToken,
		Envs:            spec.Envs,
		guestConsole:    rehydratedGuestConsole(spec.ID),
	}

	// Pinned counters cover this VM incarnation, not earlier resumes.
	baseline, err := os.ReadFile(filepath.Join(SlotRuntimeDir(spec.ID), "meter-baseline.json"))
	var totals [2]int64
	if err == nil {
		err = json.Unmarshal(baseline, &totals)
	}
	if err != nil || totals[0] < 0 || totals[1] < 0 {
		// Upgrade compatibility: older hosts did not save the baseline.
		// Reconstruct conservatively from the last persisted total and the
		// current counters, keeping reported totals from moving backwards.
		eg, in, _ := ReadBPFMeter(spec.ID)
		totals = [2]int64{max(0, spec.BandwidthUsed-int64(eg)), max(0, spec.BandwidthIngressBytes-int64(in))}
		if err := saveMeterBaseline(spec.ID, totals[0], totals[1]); err != nil {
			log.Warnf("[rehydrate] %s save meter baseline: %v", spec.ID, err)
		}
	}
	sb.BandwidthBaseline, sb.BandwidthIngressBaseline = totals[0], totals[1]
	sb.BandwidthIngressBytes = spec.BandwidthIngressBytes

	pn.trackExistingProcess(spec.FCPid)
	sb.Freezing.Store(spec.Freezing)
	m.Mu.Lock()
	m.Sandboxes[spec.ID] = sb
	m.Mu.Unlock()

	// Rehydrated VMs have no SDK Machine handle — WatchDeath falls back
	// to polling /proc/<fcPid>, which is all we need here.
	m.WatchDeath(sb)
	m.WatchLiveness(sb)

	log.Infof("[rehydrate] %s pid=%d ip=%s ns=%s veth=%s", spec.ID, spec.FCPid, spec.IP, spec.ContainerID, hostVeth)
	return nil
}

// pidIsFirecracker returns true if /proc/<pid>/comm starts with
// "firecracker". A plain kill(-0) check isn't enough because the kernel
// may have reused the PID for something else since the previous serve
// exited.
func pidIsFirecracker(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(string(b)), "firecracker")
}

// OrphanCleanupSpec carries just-enough identifiers to tear down every
// host-side artifact a sandbox left behind, without requiring the
// sandbox to be in Manager.Sandboxes. Used by the reconcile "dead" path
// and by ad-hoc operator tooling. All fields are best-effort; missing
// values mean the corresponding artifact can't be cleaned (the caller
// usually doesn't care — idempotent).
type OrphanCleanupSpec struct {
	ID          string
	IP          string
	ContainerID string // e.g. "fcp7"
	APISock     string
	OverlayPath string
	FCPid       int
}

// CleanupOrphan reclaims every artifact for a sandbox that's no longer
// tracked in Manager.Sandboxes: iptables chains (egress, bandwidth meter),
// host veth, netns, overlay file, api_sock, and the firecracker process
// if it's somehow still alive.
//
// Idempotent: each step individually no-ops if the target is already gone.
// Safe to call at reconcile time BEFORE NewManager, because it only touches
// host-side state (no Manager deps).
func CleanupOrphan(spec OrphanCleanupSpec) {
	CleanupVMArtifacts(spec)
	// Netns + veth. The netns name is the ContainerID; inside it lives
	// the tap that was attached to firecracker. Deleting the netns tears
	// down every interface inside; deleting the host-side veth removes
	// its peer entry from the root namespace.
	if spec.ContainerID != "" {
		hostVeth := vethNameFor(spec.ContainerID)
		if err := teardownNetDirect(hostVeth); err != nil {
			// Leave the netns marker mounted so NewNetPool's startup reaper
			// can discover and retry this exact slot. It will fail startup
			// closed if the veth remains undeletable.
			log.Warnf("[orphan-cleanup] sandbox=%s veth=%s: %v; retaining netns for retry", spec.ID, hostVeth, err)
		} else {
			nsPath := NetnsPathRoot + spec.ContainerID
			if _, err := os.Stat(nsPath); err == nil {
				_ = unix.Unmount(nsPath, unix.MNT_DETACH)
				_ = os.Remove(nsPath)
			}
		}
	}

	// Complete the per-VM filesystem cleanup in this reconciliation pass.
	// These were previously left for the one-minute orphan sweep, which was
	// safe but made a fully reconciled sandbox appear partially present until
	// the next tick. Keep the sweeper as a fallback for races/failures.
	//
	// Guard the identifier before joining paths: CleanupOrphan intentionally
	// accepts partially populated specs, and an empty ID must never resolve to
	// the runtime or cgroup parent directory.
	if strings.HasPrefix(spec.ID, "sb-") && !strings.ContainsAny(spec.ID, `/\\`) {
		RemoveVMCgroup(spec.ID)
		_ = os.RemoveAll(SlotRuntimeDir(spec.ID))
	}
}

// CleanupVMArtifacts removes the *per-VM* host-side state — firecracker
// process, per-VM BPF map entries, per-VM iptables chain, overlay file,
// API socket — but leaves the slot's netns + veth intact. Safe to run
// over and over on the same id: every step no-ops when its target is
// already gone. Use this in reconcile loops to scrub any stragglers
// without risking teardown of a slot the NetPool still owns.
func CleanupVMArtifacts(spec OrphanCleanupSpec) {
	// Kill any straggler firecracker first so it stops holding onto the
	// tap / overlay file. Harmless if PID 0 or already gone.
	if spec.FCPid > 0 {
		stopFirecrackerByPID(spec.FCPid, spec.ID)
	}

	// iptables chains (egress + bandwidth meter). HostVethFor derives the
	// veth name from the VM IP via the /31 invariant; it works without
	// the veth actually being up anymore — it just calls into netlink to
	// look up the peer. If the veth is already gone we skip these (the
	// chains likely went with the netns already, but Remove* is idempotent).
	if spec.IP != "" {
		if veth, err := HostVethFor(spec.IP); err == nil && veth != "" {
			RemoveEgress(spec.ID, veth)
			DetachBPFMeter(spec.ID, veth)
			ResetBPFMeter(spec.ID)
		}
	}

	// Stray files on /tmp.
	if spec.OverlayPath != "" {
		_ = os.Remove(spec.OverlayPath)
	}
	if spec.APISock != "" {
		_ = os.Remove(spec.APISock)
	}
}

// openSandboxProcess binds the process before reading /proc. If that PID exits
// and gets reused during validation, signals through this fd still refer only
// to the original process. Never fall back to signalling a numeric PID.
func openSandboxProcess(pid int, id string) (int, error) {
	if pid <= 0 || id == "" {
		return -1, fmt.Errorf("missing process identity")
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return -1, err
	}
	valid := false
	defer func() {
		if !valid {
			_ = unix.Close(fd)
		}
	}()
	if !pidIsFirecracker(pid) {
		return -1, fmt.Errorf("process is not firecracker")
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return -1, err
	}
	args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	found := ""
	for i := 1; i < len(args); i++ {
		if args[i] != "--id" {
			continue
		}
		if found != "" || i+1 >= len(args) {
			return -1, fmt.Errorf("ambiguous process identity")
		}
		i++
		found = args[i]
	}
	if found != id {
		return -1, fmt.Errorf("sandbox process identity mismatch")
	}
	valid = true
	return fd, nil
}

// stopFirecrackerByPID stops only the expected sandbox, including escalation.
// An unreadable/mismatched identity or unavailable pidfd never permits a signal.
func stopFirecrackerByPID(pid int, id string) {
	fd, err := openSandboxProcess(pid, id)
	if errors.Is(err, unix.ESRCH) || errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		log.Warnf("[orphan-cleanup] sandbox=%s pid=%d: skipping signal: %v", id, pid, err)
		return
	}
	defer unix.Close(fd)
	if err = unix.PidfdSendSignal(fd, unix.SIGINT, nil, 0); err != nil {
		if !errors.Is(err, unix.ESRCH) {
			log.Warnf("[orphan-cleanup] sandbox=%s pid=%d interrupt: %v", id, pid, err)
		}
		return
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		remaining := max(0, time.Until(deadline).Milliseconds())
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, int(remaining))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			log.Warnf("[orphan-cleanup] sandbox=%s pid=%d wait: %v", id, pid, err)
			return
		}
		if n > 0 && fds[0].Revents&unix.POLLIN != 0 {
			return
		}
		break
	}
	if err = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		log.Warnf("[orphan-cleanup] sandbox=%s pid=%d kill: %v", id, pid, err)
	}
}

// adjacentIP returns vmIP+1 as a dotted-quad string. Used to reconstruct
// the gateway address of a /31 pair from just the VM's IP on rehydrate.
func adjacentIP(vmIP string) (string, error) {
	parts := strings.Split(vmIP, ".")
	if len(parts) != 4 {
		return "", fmt.Errorf("not a dotted IPv4: %q", vmIP)
	}
	last, err := strconv.Atoi(parts[3])
	if err != nil || last >= 255 {
		return "", fmt.Errorf("invalid last octet in %q", vmIP)
	}
	parts[3] = strconv.Itoa(last + 1)
	return strings.Join(parts, "."), nil
}

// saveMeterBaseline persists the carried-over totals once per resume, before
// the new VM starts. Pinned BPF counters are added to these after host restart.
func saveMeterBaseline(id string, egress, ingress int64) error {
	path := slotRuntimePath(id, "meter-baseline.json")
	body, err := json.Marshal([2]int64{egress, ingress})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".meter-baseline-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
