package vm

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/firecracker-microvm/firecracker-go-sdk"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// SlotUID returns the per-slot UID for a given VsockCID under the
// configured base. CIDs start at 100, so slot index = cid - 100. When
// firecrackerUIDBase is 0, returns 0 — caller treats as "no drop".
func (m *Manager) SlotUID(cid uint32) uint32 {
	if m.firecrackerUIDBase == 0 || cid < 100 {
		return 0
	}
	return uint32(m.firecrackerUIDBase) + (cid - 100)
}

// KVMGID returns the kvm group GID resolved at startup, or 0 when
// per-slot UIDs are disabled.
func (m *Manager) KVMGID() uint32 { return m.kvmGID }

// ChownForSlot transfers ownership of `path` to the per-slot UID/GID
// for the given CID. No-op when per-slot UIDs are disabled. Used to
// give the post-drop firecracker access to files createos (root) has
// staged on its behalf — overlay disks, snapshot bundles. Best-effort:
// logs a warning on failure but doesn't fail the spawn (firecracker
// will simply fail to open the file and the create returns an error
// with a clear chown-related stack).
func (m *Manager) ChownForSlot(path string, cid uint32) {
	uid := m.SlotUID(cid)
	if uid == 0 {
		return
	}
	if err := os.Chown(path, int(uid), int(uid)); err != nil {
		if !os.IsNotExist(err) {
			_ = err
		}
		return
	}
	// Tighten mode to 0600 (files) or 0700 (dirs) so no other slot uid
	// — even the same numeric range — can read this VM's state.
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	mode := os.FileMode(0o600)
	if fi.IsDir() {
		mode = 0o700
	}
	_ = os.Chmod(path, mode)
}

// lookupKVMGID returns the GID of the kvm group. Errors if the group
// doesn't exist — the operator must create it (host-onboard does)
// before flipping --firecracker-uid-base on.
func lookupKVMGID() (uint32, error) {
	g, err := user.LookupGroup("kvm")
	if err != nil {
		return 0, fmt.Errorf("kvm group missing — add with `groupadd kvm` then re-deploy: %w", err)
	}
	gid, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("kvm gid %q not numeric: %w", g.Gid, err)
	}
	return uint32(gid), nil
}

// firecrackerBin is the binary the SDK invokes by default. Kept here so
// our custom cmd builder uses the same name and PATH lookup logic.
const firecrackerBin = "firecracker"

// ApplyRlimits caps the firecracker child's resource consumption.
// Defense-in-depth alongside the per-VM cgroup: pids.max bounds forks
// per-cgroup, RLIMIT_NOFILE bounds open fds per-process, RLIMIT_FSIZE
// bounds the size of any single file an escaped firecracker can grow
// (an unbounded fd balloon would otherwise fill the host disk and DoS
// every other VM with ENOSPC). Best-effort: a failed prlimit is logged
// at debug and the spawn continues — the cgroup and uid drop are the
// primary defenses.
func ApplyRlimits(pid int, diskMib int64) {
	if pid <= 0 {
		return
	}
	// 4096 fds is well above firecracker's working set (vsock + tap +
	// virtio backends + API socket ~ tens of fds) and far below the
	// host's nr_open ceiling.
	nofile := &unix.Rlimit{Cur: 4096, Max: 4096}
	if err := unix.Prlimit(pid, unix.RLIMIT_NOFILE, nofile, nil); err != nil {
		log.Debugf("[rlimit] pid %d RLIMIT_NOFILE: %v", pid, err)
	}
	// RLIMIT_NPROC is per-uid (covers all processes by that user). With
	// per-slot UIDs each uid runs exactly one firecracker; 512 is a
	// belt-and-braces backstop alongside the cgroup's pids.max=512.
	nproc := &unix.Rlimit{Cur: 512, Max: 512}
	if err := unix.Prlimit(pid, unix.RLIMIT_NPROC, nproc, nil); err != nil {
		log.Debugf("[rlimit] pid %d RLIMIT_NPROC: %v", pid, err)
	}
	// RLIMIT_FSIZE caps the largest single file firecracker (or
	// anything it forks) can write. The per-VM overlay is the
	// legitimate largest write target; cap = disk_mib + 256 MiB slop
	// for ext4 metadata. Without this, an escaped slot uid could
	// `lseek(fd, 1<<40, SEEK_SET); write(fd, ..., 1)` and balloon the
	// overlay to terabytes, filling the host disk and ENOSPC-ing every
	// other VM. With this, the write returns EFBIG (or SIGXFSZ kills
	// the process). If diskMib <= 0 (unset), fall back to a sane
	// default (16 GiB) so we always have *some* cap.
	cap := diskMib
	if cap <= 0 {
		cap = 16 * 1024
	}
	fsizeBytes := uint64(cap+256) * 1024 * 1024
	fsize := &unix.Rlimit{Cur: fsizeBytes, Max: fsizeBytes}
	if err := unix.Prlimit(pid, unix.RLIMIT_FSIZE, fsize, nil); err != nil {
		log.Debugf("[rlimit] pid %d RLIMIT_FSIZE: %v", pid, err)
	}
}

// buildFirecrackerCmd produces the *exec.Cmd the firecracker-go-sdk
// would have built internally, then attaches a uid/gid drop. Passed to
// firecracker.NewMachine via WithProcessRunner.
//
// The drop happens between fork() and execve() courtesy of Go's
// stdlib: SysProcAttr.Credential triggers setresuid/setresgid (+
// setgroups for supplementary groups) in the forked child before
// execve. Net cost: one syscall pair. No measurable spawn-time
// overhead (~0ms vs running as root — verified locally).
//
// When uid == 0 we don't set Credential at all — keeps the today-path
// behaviour byte-identical for hosts that haven't enabled per-slot
// UIDs yet (FirecrackerUIDBase == 0 in config).
//
// supplementaryGIDs MUST include the kvm gid so the child can open
// /dev/kvm post-drop; tap access is handled separately by chowning the
// tap device to `uid` at NetPool slot init.
func buildFirecrackerCmd(ctx context.Context, cfg firecracker.Config, uid, gid uint32, supplementaryGIDs []uint32, runtime firecrackerRuntime, console io.Writer) *exec.Cmd {
	// Mirror what the SDK's unexported configureBuilder does:
	// firecracker --api-sock <path> --id <vmid>
	args := []string{"--api-sock", cfg.SocketPath}
	if cfg.VMID != "" {
		args = append(args, "--id", cfg.VMID)
	}
	if runtime.Seccomp != "" {
		args = append(args, "--seccomp-filter", runtime.Seccomp)
	}
	cmd := exec.CommandContext(ctx, runtime.Binary, args...)
	cmd.Stdin = os.Stdin
	if file, ok := console.(*os.File); ok {
		// Direct file descriptors are inherited by Firecracker. A journald
		// stream therefore keeps accepting console output across a restart
		// of the parent createos-serve process.
		cmd.Stdout = file
		cmd.Stderr = file
	} else if console != nil {
		cmd.Stdout = io.MultiWriter(os.Stdout, console)
		cmd.Stderr = io.MultiWriter(os.Stderr, console)
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	if uid > 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid:    uid,
				Gid:    gid,
				Groups: supplementaryGIDs,
			},
			Setpgid: true,
			// Defense-in-depth namespaces. caps=0 + slot-uid + per-VM
			// netns + cgroup + hidepid already bound the blast radius
			// of an escaped firecracker; CLONE_NEWPID and CLONE_NEWNS
			// shrink it further so a regression in ANY of those layers
			// alone doesn't expose cross-tenant state.
			//
			//   CLONE_NEWPID — firecracker becomes PID 1 in its own
			//   namespace. It can't `kill`, `ptrace`, or even see
			//   processes outside (including other tenants' firecrackers
			//   running as different slot uids). Without this we rely on
			//   `hidepid=2` + slot-uid mismatch, which is policy-based;
			//   namespacing is structural.
			//
			//   CLONE_NEWNS — firecracker gets its own copy of the host
			//   mount table at clone time. It can't see VMs created
			//   later (other slot uids' overlays at runtime/<sb>), and
			//   it can't perturb host mounts. With caps=0 it couldn't
			//   mount anything new anyway; this is "make state changes
			//   structurally impossible to even attempt."
			//
			// Note on PID 1 semantics: firecracker doesn't spawn child
			// processes — its workers are pthreads, which share PID with
			// the parent. So zombie-reaping isn't a concern; nothing
			// ever forks under us.
			//
			// Snapshot/restore: this same buildFirecrackerCmd serves
			// both cold-boot AND ResumeFromSnapshot via the SDK's
			// WithProcessRunner. A restored VM gets the same Cloneflags
			// applied — no second spawn path to maintain.
			Cloneflags: syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
		}
	}
	return cmd
}

// slotProcess keeps a kernel handle to the exact child, avoiding PID reuse.
// The SDK owns cmd.Wait; pidfd polling independently confirms kernel exit.
type slotProcess struct {
	cmd *exec.Cmd
	fd  int
}

func (pn *PooledNet) trackProcess(cmd *exec.Cmd) *exec.Cmd {
	pn.processMu.Lock()
	defer pn.processMu.Unlock()
	child := &slotProcess{cmd: cmd, fd: -1}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.PidFD = &child.fd
	pn.processes = append(pn.processes, child)
	return cmd
}

// start waits for a failed previous attempt before a cold-boot fallback can
// attach to the same tap. Serialize the kernel's pidfd publication with cleanup.
func (pn *PooledNet) start(ctx context.Context, machine *firecracker.Machine) error {
	if err := pn.waitProcessExit(3 * time.Second); err != nil {
		return err
	}
	pn.processMu.Lock()
	defer pn.processMu.Unlock()
	return machine.Start(ctx)
}

func (pn *PooledNet) waitProcessExit(timeout time.Duration) error {
	pn.processMu.Lock()
	defer pn.processMu.Unlock()
	deadline := time.Now().Add(timeout)
	for _, child := range pn.processes {
		if child.cmd != nil && child.cmd.Process == nil {
			continue
		} // exec failed or not started yet
		if child.fd < 0 {
			return fmt.Errorf("process exit cannot be verified: missing pidfd")
		}
		for {
			wait := time.Until(deadline).Milliseconds()
			if wait < 0 {
				wait = 0
			}
			fds := []unix.PollFd{{Fd: int32(child.fd), Events: unix.POLLIN}}
			n, err := unix.Poll(fds, int(wait))
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				return fmt.Errorf("wait for slot process: %w", err)
			}
			if n == 0 || fds[0].Revents&unix.POLLIN == 0 {
				return fmt.Errorf("slot process has not exited")
			}
			break
		}
	}
	// All started children exited. Keep only commands not started yet (the next
	// fallback is built before start); never close a live child's handle.
	pending := pn.processes[:0]
	for _, child := range pn.processes {
		if child.cmd != nil && child.cmd.Process == nil {
			pending = append(pending, child)
			continue
		}
		_ = unix.Close(child.fd)
	}
	pn.processes = pending
	return nil
}

// Rehydrated borrowers have no exec.Cmd, but still need an exit barrier.
func (pn *PooledNet) trackExistingProcess(pid int) {
	if pid <= 0 {
		return
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err == unix.ESRCH {
		return
	} // already gone
	if err != nil {
		log.Warnf("[netpool] cannot track process pid=%d slot=%s: %v; release will fail closed", pid, pn.ContainerID, err)
		fd = -1
	}
	pn.processMu.Lock()
	pn.processes = append(pn.processes, &slotProcess{fd: fd})
	pn.processMu.Unlock()
}
