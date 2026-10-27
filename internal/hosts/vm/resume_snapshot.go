package vm

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	models "github.com/firecracker-microvm/firecracker-go-sdk/client/models"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/proto"
)

// ResumeSpec is the per-VM input to Manager.ResumeFromSnapshot. Distinct
// from CreateRequest: the caller has already downloaded + decompressed
// snapshot artifacts to local paths and just wants firecracker spawned
// with them. Sizing and rootfs identity must match what was paused.
type ResumeSpec struct {
	ID string
	// Name is the user-facing VM name, carried from the durable store
	// record. Pushed into the guest via MMDS as `hostname` on resume.
	Name        string
	MemPath     string // decompressed memfile (pause produced .zst; PauseOrchestrator decompresses)
	VMStatePath string // raw vmstate (not compressed)
	OverlayPath string // decompressed per-VM ext4 overlay (where the bytes live on this host)
	// VMStateOverlayPath is the drive path baked into vmstate. Resume
	// must surface a file at this path (typically via symlink to
	// OverlayPath) so firecracker's snapshot-load step finds the
	// overlay. Carried on the Sandbox struct across re-pauses so the
	// next manifest records the same baked path.
	VMStateOverlayPath string
	Shape              string
	Rootfs             string
	VCPU               int
	MemMib             int
	DiskMib            int64 // for RLIMIT_FSIZE cap; 0 = use 16 GiB default
	Egress             []string
	SecretToken        string
	Envs               map[string]string
	// BandwidthQuota is the per-VM byte cap for VM-initiated egress.
	// Carried through pause/resume so the resumed VM enforces the same
	// cap on its new host. 0 = use DefaultBandwidthQuotaBytes. Negative
	// values are rejected at the API and treated as 0 here defensively.
	BandwidthQuota int64
	// BandwidthUsedBaseline is the cumulative byte total the VM had used
	// before this resume — read from the row's bandwidth_used_bytes. The
	// meter loop adds the new host's chain counter to it so the lifetime
	// total survives migration. 0 on a first-ever resume.
	BandwidthUsedBaseline int64
	// BandwidthIngressBaseline mirrors BandwidthUsedBaseline for the
	// inbound counter so lifetime ingress survives cross-host migration.
	BandwidthIngressBaseline int64
	// Disks is the decrypted disk bundle to push into MMDS at resume.
	// Populated by the pause orchestrator from control's resolve endpoint
	// (creds re-decrypted on every resume).
	Disks []proto.MMDSDisk
}

// ResumeFromSnapshot spins firecracker against arbitrary on-disk
// snapshot artifacts (per-VM, not the per-shape prewarm template).
// Mirrors createFromSnapshot but is parameterised by spec instead of
// looking up by shape.
//
// Network: a fresh NetPool slot is allocated; the VM gets a NEW
// IP/MAC/veth on resume — pause/resume is explicitly NOT IP-retaining.
//
// UFFD: per-VM resume always uses file-backed snapshot load. UFFD
// would be possible but adds complexity (per-VM page server lifetime
// management) and we want resume to be restart-survivable.
func (m *Manager) ResumeFromSnapshot(ctx context.Context, spec ResumeSpec) (*Sandbox, error) {
	releaseRuntime := m.HoldRuntime(spec.ID)
	defer releaseRuntime()
	rootfsPath, ok := m.LookupRootfs(spec.Rootfs)
	if !ok {
		return nil, fmt.Errorf("resume: rootfs %q not in catalog", spec.Rootfs)
	}

	if err := saveMeterBaseline(spec.ID, spec.BandwidthUsedBaseline, spec.BandwidthIngressBaseline); err != nil {
		return nil, fmt.Errorf("resume: save meter baseline: %w", err)
	}

	pn, _ := m.Pool.GetWithDepth()
	uid := m.SlotUID(pn.VsockCID)
	leaseGranted := false
	keepLease := false
	if err := m.grantTemplateAccess(spec.Rootfs, rootfsPath, uid); err != nil {
		m.Pool.Return(pn)
		return nil, err
	}
	leaseGranted = uid > 0 && isTemplateRootfs(spec.Rootfs)
	defer func() {
		if leaseGranted && !keepLease {
			_ = revokeTemplateAccess(spec.Rootfs, rootfsPath, uid)
		}
	}()
	// Per-VM runtime dir (see manager.go::Create). Created mode 0700
	// owned by root; chowned to the slot UID below when uid base set.
	socketPath := slotRuntimePath(spec.ID, "fc.sock")
	m.ChownForSlot(SlotRuntimeDir(spec.ID), pn.VsockCID)
	// Pause's teardown can leave the api-sock behind if the firecracker
	// process exited before the SDK cleaned up. Remove it explicitly
	// so NewMachine doesn't choke on "socket already exists".
	_ = os.Remove(socketPath)
	prefix, _ := pn.IP.Mask.Size()

	cfg := firecracker.Config{
		ForwardSignals: []os.Signal{},
		SocketPath:     socketPath,
		MachineCfg: models.MachineConfiguration{
			VcpuCount:  firecracker.Int64(int64(spec.VCPU)),
			MemSizeMib: firecracker.Int64(int64(spec.MemMib)),
		},
		MmdsAddress: net.ParseIP("169.254.169.254"),
		MmdsVersion: firecracker.MMDSv1,
		Drives: []models.Drive{
			{
				DriveID:      firecracker.String("rootfs"),
				PathOnHost:   firecracker.String(rootfsPath),
				IsRootDevice: firecracker.Bool(false),
				IsReadOnly:   firecracker.Bool(true),
			},
			{
				DriveID:      firecracker.String("overlayfs"),
				PathOnHost:   firecracker.String(spec.OverlayPath),
				IsRootDevice: firecracker.Bool(false),
				IsReadOnly:   firecracker.Bool(false),
			},
		},
		NetworkInterfaces: firecracker.NetworkInterfaces{
			{
				AllowMMDS: true,
				StaticConfiguration: &firecracker.StaticNetworkConfiguration{
					HostDevName: pn.TapName,
					MacAddress:  pn.MAC,
					IPConfiguration: &firecracker.IPConfiguration{
						IPAddr:      pn.IP,
						Gateway:     pn.Gateway,
						Nameservers: pn.DNS,
						IfName:      pn.VMIfName,
					},
				},
			},
		},
		NetNS: pn.NetNSPath,
	}

	// Per-VM vsock UDS path for the resumed VM. Vmstate has the prior
	// incarnation's UDS path baked in; vsock_override swaps it so that
	// even if the old socket file is still on disk (e.g. cross-host
	// resume from R2 bundle, or pause/resume on same host where the
	// pause path didn't clean it), the bind succeeds.
	var vsockUDS string
	if m.agentProbeTransport == "vsock" {
		vsockUDS = slotRuntimePath(spec.ID, "vsock.uds")
		_ = os.Remove(vsockUDS)
	}

	mctx, cancel := context.WithCancel(context.Background())
	guestConsole := newGuestConsoleCapture(spec.ID)
	defer guestConsole.releaseParent()
	// When per-slot UIDs are enabled, transfer per-VM bundle files
	// (overlay, memfile, vmstate) to the slot's UID so the post-drop
	// firecracker can read/write them. Bundle was downloaded by root
	// from R2 and lands with root ownership.
	// Parent dir traversal (x bit) is required for firecracker to open
	// the files inside. The paused bundle dir is root:root mode 0700 at
	// rest; ChownForSlot drops it to the resume slot uid mode 0700.
	if dir := filepath.Dir(spec.VMStatePath); dir != "" && dir != "." && dir != "/" {
		m.ChownForSlot(dir, pn.VsockCID)
	}
	m.ChownForSlot(spec.OverlayPath, pn.VsockCID)
	m.ChownForSlot(spec.MemPath, pn.VsockCID)
	m.ChownForSlot(spec.VMStatePath, pn.VsockCID)

	opts := []firecracker.Opt{
		firecracker.WithLogger(log.NewEntry(log.StandardLogger())),
		firecracker.WithSnapshot(spec.MemPath, spec.VMStatePath, func(sc *firecracker.SnapshotConfig) {
			sc.ResumeVM = true
		}),
	}
	cfg.VMID = spec.ID
	opts = append(opts, firecracker.WithProcessRunner(
		buildFirecrackerCmd(mctx, cfg, uid, uid, []uint32{m.KVMGID()}, m.seccompFilterPath, guestConsole.writer())))
	fm, err := firecracker.NewMachine(mctx, cfg, opts...)
	if err != nil {
		cancel()
		m.Pool.Return(pn)
		return nil, fmt.Errorf("resume: NewMachine: %w", err)
	}
	// Always pass overlayfs as a block_path_override so vmstate's
	// embedded drive path is irrelevant at restore — the live file is
	// whatever this host calls spec.OverlayPath. Same-sandbox resume:
	// override == vmstate path, no-op. Fork resume: override points at
	// the fork's own paused-dir file; vmstate's reference to the
	// source's path is harmlessly ignored. Removes the need for the
	// cross-id symlink + 0o711 chmod dance in pauseresume.go.
	blockOverrides := map[string]string{"overlayfs": spec.OverlayPath}
	if vsockUDS != "" || len(blockOverrides) > 0 {
		fm.Handlers.FcInit = fm.Handlers.FcInit.Swap(firecracker.Handler{
			Name: firecracker.LoadSnapshotHandlerName,
			Fn:   loadSnapshotFn(spec.VMStatePath, spec.MemPath, "", vsockUDS, blockOverrides),
		})
	}

	if err := fm.Start(mctx); err != nil {
		cancel()
		m.Pool.Return(pn)
		return nil, fmt.Errorf("resume: Start: %w", err)
	}

	// Push fresh IP / token via MMDS so the agent re-applies network
	// post-restore (its watchMMDS goroutine is what reconfigures eth0).
	mmdsData := map[string]any{
		"id":       spec.ID,
		"hostname": spec.Name, // user-facing VM name; agent Sethostname's it
		"token":    spec.SecretToken,
		"phase":    "live",
		"now_ns":   time.Now().UnixNano(),
		"network": map[string]any{
			"ip":      pn.IP.IP.String(),
			"prefix":  prefix,
			"gateway": pn.Gateway.String(),
			"dns":     m.vmDNS(pn),
			"mac":     pn.MAC,
		},
	}
	// Always stamp the disks key — including when empty — so a resume
	// that follows a detach-while-paused (DB row removed, list now empty)
	// actually replaces the pre-pause disks set in MMDS. Skipping the
	// field meant SetMetadata (PATCH semantics in the SDK) left the
	// stale entry behind and the agent kept the old mount.
	disks := spec.Disks
	if disks == nil {
		disks = []proto.MMDSDisk{}
	}
	mmdsData["disks"] = disks
	if err := fm.SetMetadata(mctx, mmdsData); err != nil {
		log.WithContext(ctx).Warnf("[resume] %s SetMetadata: %v", spec.ID, err)
	}

	// vmstateOverlay defaults to spec.OverlayPath (first-time resume,
	// no manifest tracking yet); a re-pause+re-resume should preserve
	// the path baked in vmstate so the symlink chain stays consistent.
	vmstateOverlay := spec.VMStateOverlayPath
	if vmstateOverlay == "" {
		vmstateOverlay = spec.OverlayPath
	}
	sb := &Sandbox{
		ID:                 spec.ID,
		Name:               spec.Name,
		IP:                 pn.IP.IP.String(),
		ApiSocket:          socketPath,
		Machine:            fm,
		Net:                pn,
		OverlayPath:        spec.OverlayPath,
		VMStateOverlayPath: vmstateOverlay,
		Rootfs:             spec.Rootfs,
		VCPU:               spec.VCPU,
		MemMib:             spec.MemMib,
		Egress:             spec.Egress,
		SecretToken:        spec.SecretToken,
		Envs:               spec.Envs,
		Disks:              spec.Disks,
		VsockUDSPath:       vsockUDS,
		cancel:             cancel,
		guestConsole:       guestConsole,
	}
	// Capture the firecracker child PID — required for serve-restart
	// rehydrate, where reconcile() matches row.fc_pid against live
	// procs to decide between rehydrate and kill. Without this, a
	// resumed VM survives until the next serve restart, then gets
	// killed by reconcile because row.fc_pid=0 != live_pid. Matches
	// the cold-create path in Manager.Create.
	if pid, err := fm.PID(); err == nil {
		sb.FCPid = pid
		// Resume path was missing both cgroup attach and rlimits.
		// Without these, a paused VM that resumes — or a fork — runs
		// with unbounded pids/fds/fsize and no memcg, breaking the
		// isolation properties cold-create has. Apply the same
		// defenses async-and-best-effort, matching Manager.Create.
		// Re-derive cpu quota from the shape catalog; the row doesn't
		// persist it (it's a shape-level attribute).
		cpuQuotaPct := 0
		if spec.Shape != "" {
			if _, _, _, q, err := m.shapeCatalog().Resolve(spec.Shape); err == nil {
				cpuQuotaPct = q
			}
		}
		if cpuQuotaPct > 0 || spec.MemMib > 0 {
			go EnsureVMCgroup(spec.ID, spec.Shape, pid, cpuQuotaPct, spec.MemMib)
		}
		if m.firecrackerUIDBase > 0 {
			go ApplyRlimits(pid, int64(spec.DiskMib))
		}
	} else {
		log.WithContext(ctx).Warnf("[resume] %s PID() failed: %v (rehydrate after restart will kill this VM)", spec.ID, err)
	}

	// Install egress + meter chains for the fresh veth.
	hostVeth := vethNameFor(pn.ContainerID)
	sb.HostVeth = hostVeth
	if len(spec.Egress) > 0 {
		if err := InstallEgress(sb.ID, pn.IP.IP.String(), hostVeth, spec.Egress); err != nil {
			stopFailedVM(sb)
			RemoveSandboxIPTables(sb.ID, hostVeth)
			_ = os.Remove(socketPath)
			_ = os.Remove(vsockUDS)
			_ = os.RemoveAll(SlotRuntimeDir(spec.ID))
			m.Pool.Return(pn)
			return nil, fmt.Errorf("resume: install egress policy: %w", err)
		}
	}
	// Meter chain is always installed (even when unmetered=−1) so a later
	// recharge/quota change can take effect without reinstall. Mirrors the
	// fresh-create path in Manager.Create.
	if err := m.installMeterFor(sb.ID, hostVeth); err != nil {
		log.WithContext(ctx).Warnf("[meter] resume install failed for %s: %v", spec.ID, err)
	}
	if spec.BandwidthQuota <= 0 {
		sb.BandwidthQuota = DefaultBandwidthQuotaBytes
	} else {
		sb.BandwidthQuota = spec.BandwidthQuota
	}
	// Carry the lifetime cumulative forward; the new host's chain
	// counter starts at zero, so `Used = Baseline + chain` keeps the
	// total true across migrations. If the carried-over total already
	// exceeds the quota the meter loop will install the cap on its
	// next tick.
	sb.BandwidthBaseline = spec.BandwidthUsedBaseline
	sb.BandwidthUsed = spec.BandwidthUsedBaseline
	sb.BandwidthIngressBaseline = spec.BandwidthIngressBaseline
	sb.BandwidthIngressBytes = spec.BandwidthIngressBaseline
	// Wait for agent on :1024 before declaring success.
	readyCtx, readyCancel := context.WithTimeout(ctx, 5*time.Second)
	defer readyCancel()
	if err := waitForAgentByTransport(readyCtx, sb, m.agentProbeTransport); err != nil {
		_ = fm.StopVMM()
		_ = fm.Wait(context.Background())
		cancel()
		m.Pool.Return(pn)
		return nil, fmt.Errorf("resume: agent not ready: %w", err)
	}

	m.Mu.Lock()
	m.Sandboxes[sb.ID] = sb
	m.Mu.Unlock()
	m.WatchDeath(sb)
	m.WatchLiveness(sb)
	if len(spec.Disks) > 0 {
		m.settleDiskStatus(sb.ID)
	}

	keepLease = true
	return sb, nil
}
