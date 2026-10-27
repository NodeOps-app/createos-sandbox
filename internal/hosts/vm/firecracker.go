package vm

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	models "github.com/firecracker-microvm/firecracker-go-sdk/client/models"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/proto"
)

// createBaseSnapshot boots a template VM of the given shape+rootfs, waits for
// the agent, pauses, and writes an immutable generation directly beneath
// Manager.SnapshotDir. Snapshot artifacts are never staged under /tmp.
func (m *Manager) createBaseSnapshot(key shapeKey) error {
	vcpu, mem := key.VCPU, key.MemMib
	rootfsPath, ok := m.LookupRootfs(key.Rootfs)
	if !ok {
		return fmt.Errorf("rootfs %q not in catalog", key.Rootfs)
	}
	log.Infof("[snapshot] booting template VM for %s...", key)

	snapshotDir := filepath.Join(m.SnapshotDir, key.String())
	if err := os.MkdirAll(snapshotDir, 0o755); err != nil {
		return fmt.Errorf("mkdir snapshot: %w", err)
	}
	if err := os.Chown(snapshotDir, 0, 0); err != nil {
		return fmt.Errorf("secure snapshot dir owner: %w", err)
	}
	if err := os.Chmod(snapshotDir, 0o755); err != nil {
		return fmt.Errorf("secure snapshot dir mode: %w", err)
	}

	// Each rebuild gets immutable artifact names. Never truncate the legacy
	// canonical files (or a previous generation): running Firecracker VMs may
	// still have their RAM privately mapped from those inodes.
	generation := strings.TrimPrefix(newSandboxID(), "sb-")
	vmStatePath := filepath.Join(snapshotDir, "vmstate."+generation)
	memFilePath := filepath.Join(snapshotDir, "mem."+generation)
	// Template-side vsock UDS is temporary and is not a published snapshot
	// artifact, so it does not need a generation suffix. Keeping this name
	// short matters: sockaddr_un has a small fixed path limit, and a custom
	// tpl_<ULID> shape directory plus another ULID exceeded it. The absolute
	// path baked into vmstate is harmless because every restore supplies its
	// own unique per-VM path through vsock_override.
	vsockTemplateUDS := filepath.Join(snapshotDir, "vsock-template.uds")
	_ = os.Remove(vsockTemplateUDS) // stale from prior prewarm
	defer os.Remove(vsockTemplateUDS)

	// We need a temporary network + overlay for the template VM. The overlay
	// uses the pool's default size since snapshot restores get their own
	// per-VM overlay anyway — only vmstate+mem need to persist.
	pn := m.Pool.Get()
	defer m.Pool.Return(pn)

	// Base overlay lives inside the snapshot dir at a canonical, stable path.
	// Firecracker bakes this path into vmstate; restoring the snapshot on a
	// different process or after a reboot (which wipes /tmp) must still find
	// the file. Living next to vmstate/mem means it has the same lifecycle.
	overlayPath := filepath.Join(snapshotDir, "base."+generation+".ext4")
	committed := false
	defer func() {
		if committed {
			return
		}
		_ = os.Remove(vmStatePath)
		_ = os.Remove(memFilePath)
		_ = os.Remove(overlayPath)
		_ = os.Remove(baseExt4MetaPath(overlayPath))
	}()
	if err := createOverlayAt(overlayPath, m.DiskSizeMB); err != nil {
		return fmt.Errorf("overlay: %w", err)
	}

	socketPath := runtimePath(fmt.Sprintf("fc-template-%s.sock", key))
	defer os.Remove(socketPath)

	kernelArgs := "console=ttyS0 reboot=k panic=1 pci=off rdinit=/usr/local/bin/agent overlay_root=vdb"

	prefix, _ := pn.IP.Mask.Size()

	cfg := firecracker.Config{
		// ForwardSignals=[] disables the SDK's default SIGTERM/SIGINT
		// forwarding to the firecracker child. Without this, a graceful
		// serve restart (SIGTERM) would cascade into every VM, defeating
		// rehydrate. Nil means "use default" so we must pass an empty
		// (but non-nil) slice.
		ForwardSignals:  []os.Signal{},
		SocketPath:      socketPath,
		KernelImagePath: m.KernelPath,
		InitrdPath:      m.InitrdPath,
		KernelArgs:      kernelArgs,
		MachineCfg: models.MachineConfiguration{
			VcpuCount:  firecracker.Int64(int64(vcpu)),
			MemSizeMib: firecracker.Int64(int64(mem)),
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
				PathOnHost:   firecracker.String(overlayPath),
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
		VsockDevices: []firecracker.VsockDevice{
			{
				ID:   "vsock0",
				Path: vsockTemplateUDS,
				CID:  pn.VsockCID,
			},
		},
		NetNS: pn.NetNSPath,
	}

	mmdsData := map[string]any{
		"network": map[string]any{
			"ip":      pn.IP.IP.String(),
			"prefix":  prefix,
			"gateway": pn.Gateway.String(),
			"dns":     m.vmDNS(pn),
			"mac":     pn.MAC,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Note on closing the orphan-template leak window: we previously
	// tried Pdeathsig=SIGKILL on the prewarm child, but Go's M:N
	// scheduler makes PR_SET_PDEATHSIG fire whenever the *creating
	// OS thread* exits — not when the whole serve process dies — so
	// firecracker got SIGKILL'd immediately during normal goroutine
	// rescheduling. The reliable defense is ReapOrphanedPrewarmTemplates
	// in NewManager, which sweeps orphans at the next serve startup.
	fm, err := firecracker.NewMachine(ctx, cfg,
		firecracker.WithLogger(log.NewEntry(log.StandardLogger())),
	)
	if err != nil {
		return fmt.Errorf("create template VM: %w", err)
	}
	// PUT /cpu-config after the API socket is up but before InstanceStart.
	// No-op when no template is configured. See cputemplate.go.
	fm.Handlers.FcInit = fm.Handlers.FcInit.AppendAfter(
		firecracker.StartVMMHandlerName, applyCPUTemplateHandler())
	// Pin firecracker to the boot lane after StartVMM (process up,
	// PID available) so /snapshot/load and cold-boot CPUID/vCPU init
	// run on dedicated cores. No-op when lane carving is disabled.
	fm.Handlers.FcInit = fm.Handlers.FcInit.AppendAfter(
		firecracker.StartVMMHandlerName, pinToBootLaneHandler())

	if err := fm.Start(ctx); err != nil {
		return fmt.Errorf("start template VM: %w", err)
	}

	if err := fm.SetMetadata(ctx, mmdsData); err != nil {
		log.Warnf("[snapshot] template SetMetadata failed: %v", err)
	}

	// Wait for the agent to reach the phase-1 probe listener (port 1023) —
	// this is the snapshot boundary. The agent has NOT mounted /dev/vdb yet
	// and has NOT started the exec listener; every restored VM will do that
	// fresh with its own overlay, which is how disk_mib sizing stays correct.
	readyCtx, readyCancel := context.WithTimeout(ctx, 15*time.Second)
	defer readyCancel()
	if err := waitForPhase1Probe(readyCtx, pn.IP.IP.String()); err != nil {
		_ = fm.StopVMM()
		return fmt.Errorf("template phase1 probe not reachable: %w", err)
	}

	log.Infof("[snapshot] template VM in phase1 for %s, pausing...", key)

	// Pause the VM
	if err := fm.PauseVM(ctx); err != nil {
		_ = fm.StopVMM()
		return fmt.Errorf("pause: %w", err)
	}

	// Create snapshot
	if err := fm.CreateSnapshot(ctx, memFilePath, vmStatePath); err != nil {
		_ = fm.StopVMM()
		return fmt.Errorf("snapshot: %w", err)
	}
	// Prewarmed snapshot files are SHARED across all VMs of this shape.
	// mem/vmstate are root-owned 0644: only root can modify them, while each
	// unprivileged per-slot Firecracker UID can open the tenant-free base
	// snapshot read-only. Mode 0600 would break snapshot restores.
	// No tenant data is in a prewarmed-from-base-rootfs snapshot, so
	// world-readable is acceptable.
	//
	// base.ext4 is the scratch overlay the prewarm template booted on;
	// the vmstate has its absolute path baked in and every restoring
	// firecracker opens it directly (read-only — createos passes a
	// fresh per-VM overlay separately).
	for _, path := range []string{memFilePath, vmStatePath} {
		if err := os.Chown(path, 0, 0); err != nil {
			_ = fm.StopVMM()
			return fmt.Errorf("secure snapshot artifact owner %s: %w", path, err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			_ = fm.StopVMM()
			return fmt.Errorf("secure snapshot artifact mode %s: %w", path, err)
		}
	}
	// base.ext4 used to need 0660 root:kvm so the tenant Firecracker could
	// open it O_RDWR. block_path_overrides now sends it directly to the
	// per-VM overlay, so keep the shared base root-only under every mode.
	if err := os.Chown(overlayPath, 0, 0); err != nil {
		_ = fm.StopVMM()
		return fmt.Errorf("secure snapshot base owner: %w", err)
	}
	if err := os.Chmod(overlayPath, 0o600); err != nil {
		_ = fm.StopVMM()
		return fmt.Errorf("secure snapshot base mode: %w", err)
	}

	// Integrity sidecar: capture (mtime, size) AFTER the chmod above so
	// the recorded mtime matches what every future stat() will see for
	// an untouched file. Any subsequent write by a slot-uid firecracker
	// bumps mtime, which the restore-time check catches.
	if err := writeBaseExt4Meta(overlayPath); err != nil {
		log.Warnf("[snapshot] %s: write base.ext4 meta: %v (integrity check disabled for this snapshot)", key, err)
	}

	files := &snapshotFiles{
		VmStatePath: vmStatePath,
		MemFilePath: memFilePath,
		BaseOverlay: overlayPath,
		Ready:       true,
	}
	// This atomic rename is the only publication point. A crash before it
	// leaves the prior manifest intact; readers can never observe a mixed
	// vmstate/memory generation.
	if err := publishSnapshotManifest(snapshotDir, files); err != nil {
		_ = fm.StopVMM()
		return fmt.Errorf("publish snapshot: %w", err)
	}
	committed = true

	log.Infof("[snapshot] snapshot %s created: %s, %s", key, vmStatePath, memFilePath)

	// Stop the template VM
	// Best-effort: the template VM has served its purpose, nothing left to
	// recover if teardown reports an error.
	_ = fm.StopVMM()
	_ = fm.Wait(ctx)

	m.SnapshotsMu.Lock()
	m.Snapshots[key] = files
	m.SnapshotsMu.Unlock()

	return nil
}

// ensureSnapshot uses singleflight (keyed by shape) to guarantee exactly one
// snapshot build per unique (vcpu, mem) pair even under concurrent creates.
func (m *Manager) ensureSnapshot(key shapeKey) error {
	_, err, _ := m.SnapshotFlight.Do(key.String(), func() (any, error) {
		m.SnapshotsMu.Lock()
		s, ok := m.Snapshots[key]
		ready := ok && s.Ready
		m.SnapshotsMu.Unlock()
		if ready {
			return nil, nil
		}
		if err := m.createBaseSnapshot(key); err != nil {
			return nil, err
		}
		return nil, nil
	})
	return err
}

// createFromSnapshot restores a VM from the base snapshot for the given shape.
func (m *Manager) createFromSnapshot(id, name string, pn *PooledNet, overlayPath, socketPath string, key shapeKey, secretToken string, disks []proto.MMDSDisk) (*Sandbox, error) {
	m.SnapshotsMu.Lock()
	files, ok := m.Snapshots[key]
	m.SnapshotsMu.Unlock()
	if !ok || !files.Ready {
		return nil, fmt.Errorf("no snapshot for %s", key)
	}
	// Tamper check on the shared base.ext4 BEFORE handing it to
	// firecracker for /snapshot/load. A mismatch means a previous
	// slot-uid firecracker wrote to it (the only legitimate writer is
	// the prewarm itself, which we serialize and re-record after).
	// Mark the snapshot stale and trigger a re-prewarm in the
	// background so subsequent spawns of this shape resume normally.
	if err := verifyBaseExt4(files.BaseOverlay); err != nil {
		log.Errorf("[integrity] %s tampered: %v", key, err)
		m.SnapshotsMu.Lock()
		if s, ok2 := m.Snapshots[key]; ok2 {
			s.Ready = false
		}
		m.SnapshotsMu.Unlock()
		go func() {
			if reErr := m.ensureSnapshot(key); reErr != nil {
				log.Errorf("[integrity] %s re-prewarm failed: %v", key, reErr)
			}
		}()
		return nil, fmt.Errorf("shape temporarily unavailable (snapshot stale, re-prewarming): %w", err)
	}
	rootfsPath, ok := m.LookupRootfs(key.Rootfs)
	if !ok {
		return nil, fmt.Errorf("rootfs %q not in catalog", key.Rootfs)
	}
	// When per-slot UIDs are enabled, give the post-drop firecracker
	// ownership of the per-VM overlay (writable). Shared artifacts —
	// rootfs, vmlinux, initrd, AND the prewarmed snapshot files — are
	// expected to be world-readable: chmod 0644 at prewarm/install
	// time so every slot's firecracker can read them without chown.
	// Per-VM (paused-then-resumed) snapshot bundle files get chowned
	// in the resume staging path, not here.
	m.ChownForSlot(overlayPath, pn.VsockCID)

	prefix, _ := pn.IP.Mask.Size()

	// Per-VM vsock UDS path. Empty unless vsock transport is enabled.
	// Cherry-picked vsock_override (PR 3d642c5fd) in our patched
	// firecracker swaps the snapshot's baked path for this one at
	// /snapshot/load time, so many concurrent restores don't collide.
	var vsockUDS string
	if m.agentProbeTransport == "vsock" {
		vsockUDS = slotRuntimePath(id, "vsock.uds")
		_ = os.Remove(vsockUDS)
	}

	cfg := firecracker.Config{
		// ForwardSignals=[] disables the SDK's default SIGTERM/SIGINT
		// forwarding to the firecracker child. Without this, a graceful
		// serve restart (SIGTERM) would cascade into every VM, defeating
		// rehydrate. Nil means "use default" so we must pass an empty
		// (but non-nil) slice.
		ForwardSignals: []os.Signal{},
		SocketPath:     socketPath,
		MachineCfg: models.MachineConfiguration{
			VcpuCount:  firecracker.Int64(int64(key.VCPU)),
			MemSizeMib: firecracker.Int64(int64(key.MemMib)),
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
				PathOnHost:   firecracker.String(overlayPath),
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

	mmdsData := map[string]any{
		"id":       id,   // sandbox id
		"hostname": name, // user-facing VM name; agent Sethostname's it
		"network": map[string]any{
			"ip":      pn.IP.IP.String(),
			"prefix":  prefix,
			"gateway": pn.Gateway.String(),
			"dns":     m.vmDNS(pn),
			"mac":     pn.MAC,
		},
		// Per-VM shared secret. Agent reads from MMDS into process memory
		// and validates "AUTH <token>\n" prefix on every connection to its
		// :1024/:1025/:1026 listeners.
		"token": secretToken,
		// Signals the restored guest agent to leave phase-1 block, mount
		// /dev/vdb fresh, and start the exec listener.
		"phase": "live",
		// Wall-clock at the moment we restore. Snapshots bake the template
		// VM's clock into vmstate, so a restore on day N pops up with
		// day-N-7 time and breaks anything sigv4-signed (S3, AWS APIs)
		// with RequestTimeTooSkewed. The agent calls clock_settime() with
		// this value on every restore push it receives.
		"now_ns": time.Now().UnixNano(),
	}
	if len(disks) > 0 {
		mmdsData["disks"] = disks
	}

	// Disk size: best-effort stat of the overlay file (sparse size set by
	// mkfs). Falls back to the pool default if stat fails.
	diskMib := m.DiskSizeMB
	if fi, err := os.Stat(overlayPath); err == nil {
		diskMib = fi.Size() / (1024 * 1024)
	}

	ctx, cancel := context.WithCancel(context.Background())
	guestConsole := newGuestConsoleCapture(id)
	defer guestConsole.releaseParent()
	// When per-slot UIDs are enabled, build the firecracker cmd ourselves
	// so SysProcAttr.Credential drops privs at execve. cfg.VMID must be
	// set first because buildFirecrackerCmd mirrors the SDK's internal
	// "configureBuilder" path which inserts --id. id is the sandbox id.
	opts := []firecracker.Opt{
		firecracker.WithLogger(log.NewEntry(log.StandardLogger())),
		firecracker.WithSnapshot(files.MemFilePath, files.VmStatePath, func(sc *firecracker.SnapshotConfig) {
			sc.ResumeVM = true
		}),
	}
	uid := m.SlotUID(pn.VsockCID)
	cfg.VMID = id
	opts = append(opts, firecracker.WithProcessRunner(
		buildFirecrackerCmd(ctx, cfg, uid, uid, []uint32{m.KVMGID()}, m.seccompFilterPath, guestConsole.writer())))
	tNewMachine := time.Now()
	fm, err := firecracker.NewMachine(ctx, cfg, opts...)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create machine (snapshot): %w", err)
	}
	dNewMachine := time.Since(tNewMachine)

	// Pin firecracker to the boot lane right after StartVMM so the
	// CPU-heavy /snapshot/load + vCPU resume runs on dedicated cores
	// regardless of how busy the tenant lane is. No-op when lane
	// carving is disabled.
	fm.Handlers.FcInit = fm.Handlers.FcInit.AppendAfter(
		firecracker.StartVMMHandlerName, pinToBootLaneHandler())

	// UFFD path: start a page server on a unix socket and swap the SDK's
	// default LoadSnapshotHandler for one that PUTs /snapshot/load with
	// mem_backend: Uffd. Firecracker then connects to our socket, passes
	// its userfaultfd, and pages fault lazily out of the memfile instead
	// of being copied in eagerly.
	//
	// Enabled automatically for VMs ≥ 512 MiB. Below that, eager snapshot
	// load (~95ms for 256MB) is faster than the lazy per-fault round trips
	// during guest boot (~70ms added to agent readiness). At 1 GiB and
	// above the eager path saturates disk I/O under concurrent creates and
	// agent-ready latency explodes (~1.2s), so UFFD is a 9× win there.
	// Configure this with uffd: in host YAML or --uffd on the CLI.
	useUFFD := key.MemMib >= 512
	// Manager config (from --uffd / uffd: in YAML) takes precedence over
	// the auto-by-size default.
	switch m.uffdMode {
	case "off":
		useUFFD = false
	case "on":
		useUFFD = true
	}
	var uffdServer *UFFDServer
	var uffdSock string
	if useUFFD {
		uffdSock = slotRuntimePath(id, "uffd.sock")
		uffdServer, err = StartUFFDServer(uffdSock, files.MemFilePath)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("start uffd: %w", err)
		}
	}
	// slotRuntimePath calls above may have recreated the directory after a
	// failed attempt. Reassert ownership at the last possible point before the
	// unprivileged Firecracker process binds fc.sock/vsock.uds.
	m.ChownForSlot(SlotRuntimeDir(id), pn.VsockCID)
	// Override SDK's LoadSnapshotHandler. Three custom fields ride this
	// path: UFFD mem backend, vsock_override, and block_path_overrides.
	// The block override points overlayfs at this VM's per-size overlay
	// at load time — the prewarm snapshot's vmstate references the
	// shape's shared `base.ext4`, but we never want a tenant firecracker
	// to actually open that. With this override the post-load
	// UpdateGuestDrive PATCH below becomes redundant, and base.ext4
	// stops being tenant-readable (mode + ACL can tighten).
	fm.Handlers.FcInit = fm.Handlers.FcInit.Swap(firecracker.Handler{
		Name: firecracker.LoadSnapshotHandlerName,
		Fn: loadSnapshotFn(files.VmStatePath, files.MemFilePath, uffdSock, vsockUDS,
			map[string]string{"overlayfs": overlayPath}),
	})

	tStart := time.Now()
	if err := fm.Start(ctx); err != nil {
		// Start spawns firecracker AND runs the init handler chain
		// (LoadSnapshot etc.). When a later handler fails, the
		// firecracker process is alive but the SDK doesn't reap it.
		// If we just return here, the manager's fallback path spawns a
		// SECOND firecracker on the same API socket — both write to
		// the socket and fight over the netns/overlay, which makes
		// every subsequent exec hang.
		//
		// SIGKILL the firecracker process (fast — no wait for SIGTERM
		// to be observed) so the kernel releases tap0 / netns
		// references before the fallback cold-boot tries to attach.
		// Without this kill+confirm, cold-boot consistently fails with
		// "tap0 Resource busy" because the failed snapshot-restore fc
		// is still holding the tap fd when cold-boot calls open().
		if pid, perr := fm.PID(); perr == nil && pid > 0 {
			KillFirecrackerFast(pid)
		} else {
			_ = fm.StopVMM()
		}
		if uffdServer != nil {
			uffdServer.Close()
		}
		cancel()
		_ = os.Remove(socketPath)
		return nil, fmt.Errorf("restore snapshot: %w", err)
	}
	dStart := time.Since(tStart)

	// block_path_overrides on /snapshot/load already pointed the drive
	// at overlayPath (so base.ext4 stays untouched by tenants), but the
	// GUEST's view of disk geometry is reconstructed from vmstate's
	// saved config_space — i.e. the prewarm template's 512 MB capacity.
	// The PATCH below fires the virtio config-change interrupt that
	// makes the guest re-read the device size before the agent's
	// overlay-mount code runs. Without it, vdb shows the old size,
	// overlay mount fails, and userspace can't reach /bin.
	tUpdate := time.Now()
	updateCtx, updateCancel := context.WithTimeout(ctx, 5*time.Second)
	if err := fm.UpdateGuestDrive(updateCtx, "overlayfs", overlayPath); err != nil {
		updateCancel()
		log.Warnf("[sandbox] %s UpdateGuestDrive failed: %v (guest will see template disk size)", id, err)
	}
	updateCancel()
	dUpdate := time.Since(tUpdate)

	// Push fresh metadata: network config + phase:"live" to unblock phase 2.
	tMeta := time.Now()
	if err := fm.SetMetadata(ctx, mmdsData); err != nil {
		log.Warnf("[sandbox] %s SetMetadata (restore) failed: %v", id, err)
	}
	dMeta := time.Since(tMeta)

	log.Infof("[boot-trace] %s newMachine=%s start=%s updateDrive=%s setMeta=%s",
		id, dNewMachine.Round(time.Millisecond), dStart.Round(time.Millisecond),
		dUpdate.Round(time.Millisecond), dMeta.Round(time.Millisecond))

	return &Sandbox{
		ID:                 id,
		Name:               name,
		IP:                 pn.IP.IP.String(),
		ApiSocket:          socketPath,
		Machine:            fm,
		Net:                pn,
		OverlayPath:        overlayPath,
		VMStateOverlayPath: overlayPath, // freshly-baked path == active path
		Rootfs:             key.Rootfs,
		VCPU:               key.VCPU,
		MemMib:             key.MemMib,
		DiskMib:            diskMib,
		SecretToken:        secretToken,
		Disks:              disks,
		cancel:             cancel,
		Uffd:               uffdServer,
		VsockUDSPath:       vsockUDS,
		guestConsole:       guestConsole,
	}, nil
}

// loadSnapshotFn returns a handler that PUTs /snapshot/load with optional
// UFFD mem_backend, vsock_override, and/or block_path_overrides (all
// cherry-picked features from our firecracker fork, not in stock v1.15.1).
// The SDK's typed SnapshotLoadParams doesn't expose any of these fields,
// so we build the JSON body by hand and send it over the API socket
// directly.
//
//   - uffdSockPath != ""           → use UFFD mem backend instead of file-backed
//   - vsockUDSPath != ""           → override the snapshot's baked-in vsock UDS path
//     with a per-VM unique path (avoids EADDRINUSE
//     when many VMs restore the same prewarm snapshot
//     concurrently)
//   - blockPathOverrides non-empty → drive_id → host path map; replaces the
//     backing file path baked in vmstate at restore.
//     Used at fork resume to point "overlayfs" at the
//     fork's own paused-dir file instead of the
//     source's (whose path the vmstate carries by
//     accident of byte-identical R2 copy).
func loadSnapshotFn(snapshotPath, memFilePath, uffdSockPath, vsockUDSPath string, blockPathOverrides map[string]string) func(context.Context, *firecracker.Machine) error {
	return func(ctx context.Context, m *firecracker.Machine) error {
		var memBackend string
		if uffdSockPath != "" {
			memBackend = fmt.Sprintf(`"mem_backend":{"backend_type":"Uffd","backend_path":%q}`, uffdSockPath)
		} else {
			memBackend = fmt.Sprintf(`"mem_file_path":%q`, memFilePath)
		}
		vsockOverride := ""
		if vsockUDSPath != "" {
			vsockOverride = fmt.Sprintf(`,"vsock_override":{"uds_path":%q}`, vsockUDSPath)
		}
		blockOverride := ""
		if len(blockPathOverrides) > 0 {
			parts := make([]string, 0, len(blockPathOverrides))
			for id, p := range blockPathOverrides {
				parts = append(parts, fmt.Sprintf("%q:%q", id, p))
			}
			blockOverride = `,"block_path_overrides":{` + strings.Join(parts, ",") + `}`
		}
		body := fmt.Sprintf(
			`{"snapshot_path":%q,%s,"enable_diff_snapshots":false,"resume_vm":true%s%s}`,
			snapshotPath, memBackend, vsockOverride, blockOverride,
		)
		tr := &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", m.Cfg.SocketPath)
			},
			// Per-call Transport — DisableKeepAlives so the persistConn
			// readLoop/writeLoop goroutines don't outlive this scope.
			DisableKeepAlives: true,
		}
		client := &http.Client{Transport: tr}
		req, err := http.NewRequestWithContext(ctx, "PUT", "http://unix/snapshot/load", strings.NewReader(body))
		if err != nil {
			return fmt.Errorf("snapshot/load build req: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("snapshot/load: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode >= http.StatusMultipleChoices {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("snapshot/load HTTP %d: %s", resp.StatusCode, string(body))
		}
		return nil
	}
}

// createColdBoot creates a VM via full kernel boot with the requested shape.
func (m *Manager) createColdBoot(id string, pn *PooledNet, overlayPath, socketPath string, req CreateRequest) (*Sandbox, error) {
	rootfsPath, ok := m.LookupRootfs(req.Rootfs)
	if !ok {
		return nil, fmt.Errorf("rootfs %q not in catalog", req.Rootfs)
	}
	// Per-slot UID drop: hand the writable overlay to the post-drop
	// firecracker. Shared read-only artifacts (rootfs, vmlinux, initrd)
	// are world-readable via host-onboard chmod.
	m.ChownForSlot(overlayPath, pn.VsockCID)
	// No ip= arg: guest configures eth0 from MMDS so the snapshot has no IP
	// baked into guest kernel memory (fixes same-IP-on-restore bug).
	kernelArgs := "console=ttyS0 reboot=k panic=1 pci=off rdinit=/usr/local/bin/agent overlay_root=vdb"

	prefix, _ := pn.IP.Mask.Size()
	// Per-VM vsock UDS path. Random hex suffix to avoid collisions on
	// host restarts and slot reuse. Cleaned up in Manager.Destroy.
	vsockUDS := slotRuntimePath(id, "vsock.uds")
	_ = os.Remove(vsockUDS) // stale from prior incarnation if any

	cfg := firecracker.Config{
		// ForwardSignals=[] disables the SDK's default SIGTERM/SIGINT
		// forwarding to the firecracker child. Without this, a graceful
		// serve restart (SIGTERM) would cascade into every VM, defeating
		// rehydrate. Nil means "use default" so we must pass an empty
		// (but non-nil) slice.
		ForwardSignals:  []os.Signal{},
		SocketPath:      socketPath,
		KernelImagePath: m.KernelPath,
		InitrdPath:      m.InitrdPath,
		KernelArgs:      kernelArgs,
		MachineCfg: models.MachineConfiguration{
			VcpuCount:  firecracker.Int64(int64(req.VCPU)),
			MemSizeMib: firecracker.Int64(int64(req.MemMib)),
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
				PathOnHost:   firecracker.String(overlayPath),
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
		VsockDevices: []firecracker.VsockDevice{
			{ID: "vsock0", Path: vsockUDS, CID: pn.VsockCID},
		},
		NetNS: pn.NetNSPath,
	}

	mmdsData := map[string]any{
		"id":       id,       // sandbox id
		"hostname": req.Name, // user-facing VM name; agent Sethostname's it
		// Cold boot must release the guest agent from its snapshot-safe phase-1
		// wait just like snapshot restore does. Without this, readiness probing
		// sees the already-bound listener while exec remains queued forever.
		"phase": "live",
		"network": map[string]any{
			"ip":      pn.IP.IP.String(),
			"prefix":  prefix,
			"gateway": pn.Gateway.String(),
			"dns":     m.vmDNS(pn),
			"mac":     pn.MAC,
		},
		// Per-VM shared secret. See snapshot path above.
		"token":  req.SecretToken,
		"now_ns": time.Now().UnixNano(),
	}
	if len(req.Disks) > 0 {
		mmdsData["disks"] = req.Disks
	}

	ctx, cancel := context.WithCancel(context.Background())
	guestConsole := newGuestConsoleCapture(id)
	defer guestConsole.releaseParent()
	opts := []firecracker.Opt{firecracker.WithLogger(log.NewEntry(log.StandardLogger()))}
	uid := m.SlotUID(pn.VsockCID)
	cfg.VMID = id
	opts = append(opts, firecracker.WithProcessRunner(
		buildFirecrackerCmd(ctx, cfg, uid, uid, []uint32{m.KVMGID()}, m.seccompFilterPath, guestConsole.writer())))
	fm, err := firecracker.NewMachine(ctx, cfg, opts...)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create machine (cold): %w", err)
	}
	// PUT /cpu-config before InstanceStart. No-op when no template
	// configured. Snapshot-restore path skips this — restored vmstate
	// already has the templated CPUID baked in from the prewarm boot.
	fm.Handlers.FcInit = fm.Handlers.FcInit.AppendAfter(
		firecracker.StartVMMHandlerName, applyCPUTemplateHandler())
	// Pin firecracker to the boot lane after StartVMM (process up,
	// PID available) so /snapshot/load and cold-boot CPUID/vCPU init
	// run on dedicated cores. No-op when lane carving is disabled.
	fm.Handlers.FcInit = fm.Handlers.FcInit.AppendAfter(
		firecracker.StartVMMHandlerName, pinToBootLaneHandler())

	// Cold boot is also the snapshot failure fallback. That path can recreate
	// runtime/sb-* as root, so restore slot ownership immediately before launch.
	m.ChownForSlot(SlotRuntimeDir(id), pn.VsockCID)
	if err := fm.Start(ctx); err != nil {
		cancel()
		return nil, fmt.Errorf("start (cold): %w", err)
	}

	// Push MMDS metadata so the guest agent can read it during boot.
	if err := fm.SetMetadata(ctx, mmdsData); err != nil {
		log.Warnf("[sandbox] %s SetMetadata failed: %v", id, err)
	}

	return &Sandbox{
		ID:                 id,
		Name:               req.Name,
		IP:                 pn.IP.IP.String(),
		ApiSocket:          socketPath,
		Machine:            fm,
		Net:                pn,
		OverlayPath:        overlayPath,
		VMStateOverlayPath: overlayPath, // freshly-baked path == active path
		Rootfs:             req.Rootfs,
		VCPU:               req.VCPU,
		MemMib:             req.MemMib,
		DiskMib:            req.DiskMib,
		SecretToken:        req.SecretToken,
		Disks:              req.Disks,
		VsockUDSPath:       vsockUDS,
		cancel:             cancel,
		guestConsole:       guestConsole,
	}, nil
}
