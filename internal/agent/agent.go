package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/NodeOps-app/createos-sandbox/internal/agent/childreaper"
	agentprocess "github.com/NodeOps-app/createos-sandbox/internal/agent/process"
	"github.com/NodeOps-app/createos-sandbox/internal/proto"
	"github.com/NodeOps-app/createos-sandbox/internal/requestctx"
)

const (
	agentPort       = 1024 // exec protocol (real, post-overlay)
	phase1ProbePort = 1023 // template-ready health probe (pre-overlay)
)

// phase2Ch is signalled by watchMMDS when the host pushes {"phase":"live"}
// in MMDS — which only happens on restore. The template VM never sees this
// signal, so it blocks at the snapshot point.
var phase2Ch = make(chan struct{}, 1)

// sandboxIDCh carries the per-VM sandbox id that the host pushes via MMDS
// alongside phase:"live". Phase 2 reads it once to set the hostname.
// Buffered so watchMMDS never blocks; latest write wins on collision.
var sandboxIDCh = make(chan string, 1)

// phase2DiskReady is set by phase 2 once setupOverlay has mounted the
// rootfs and chroot'd. watchMMDS only calls applyDisks after this flips
// — before that, the filesystem is the initrd's tmpfs and `s3fs` isn't
// installed there. atomic.Bool because the watchMMDS goroutine reads it
// at ~500 Hz.
var phase2DiskReady atomic.Bool

// Run runs the guest agent. It is normally invoked as PID 1 inside the VM.
// The read-only rootfs is mounted before the template snapshot. Each
// restored VM mounts its private writable /dev/vdb fresh, giving it the
// correct size automatically (no resize2fs dance).
func Run() {
	if len(os.Args) == 2 && os.Args[1] == "--warmup-rootfs" {
		if err := warmImage("/lower"); err != nil {
			// Never log image-controlled names or parser input.
			fmt.Fprintln(os.Stderr, "agent: invalid or unreadable image warmup ignored")
		}
		return
	}
	// ─── Phase 1: pre-overlay setup (runs in the template; frozen in snapshot)
	mustMount("proc", "/proc", "proc", 0, "")
	mustMount("sysfs", "/sys", "sysfs", 0, "")
	mustMount("devtmpfs", "/dev", "devtmpfs", 0, "")

	// Sysrq lockdown attempt (kept for documentation): the only
	// reliable way to disable /proc/sysrq-trigger is to rebuild the
	// guest kernel without CONFIG_MAGIC_SYSRQ. From userspace:
	//   - kernel.sysrq=0 sysctl only gates the keyboard SysRq combo;
	//     it has no effect on /proc/sysrq-trigger writes.
	//   - bind-mounting /dev/null over /proc/sysrq-trigger silently
	//     fails (procfs rejects mount-overlay on its files).
	//   - chmod 0 on /proc/sysrq-trigger gets reset back to 0200 by
	//     procfs on the next open.
	// We still set the sysctl so the keyboard path is closed, even
	// though the proc trigger remains live. Tracked: needs kernel
	// rebuild for full mitigation. Self-DoS only, no cross-tenant
	// impact (each guest has its own kernel).
	_ = os.WriteFile("/proc/sys/kernel/sysrq", []byte("0\n"), 0o644)

	syscall.Sethostname([]byte("fc-vm"))
	execQuiet("/bin/busybox", "ip", "link", "set", "lo", "up")

	if err := configureNetworkFromMMDS(); err != nil {
		fmt.Fprintf(os.Stderr, "agent: network config from MMDS failed: %v\n", err)
	}

	if parseCmdlineArg("overlay_root") != "" {
		// Keep only immutable image state in the reusable snapshot. Writable
		// disk setup and per-sandbox changes still happen in phase 2.
		os.MkdirAll("/lower", 0755)
		if err := syscall.Mount("/dev/vda", "/lower", "ext4", syscall.MS_RDONLY, ""); err != nil {
			fmt.Fprintln(os.Stderr, "agent: cannot mount read-only rootfs")
			select {} // Do not advertise template readiness without its rootfs.
		}
		prepareWarmup()
	}

	// Background watchers — goroutines survive the snapshot and keep running
	// on restore. watchMMDS also fires phase2Ch when it sees phase:"live".
	go watchMMDS()
	go childreaper.Run()

	// Phase-1 probe listener on 1023. Host's createBaseSnapshot pings this to
	// know the template has reached the snapshot point. Stays open across the
	// snapshot — restored VMs just ignore it.
	probeL := startPhase1Probe()

	// Bind the exec + file listeners NOW so they're captured in the snapshot.
	// Restored VMs respond to TCP SYNs immediately from the kernel accept
	// queue — the host's waitForAgent probe succeeds without waiting for
	// phase-2 overlay setup. Real exec/file requests queue in the backlog
	// until the accept loops start below.
	execL, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", agentPort))
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent: bind exec listener: %v\n", err)
		select {}
	}
	filesL, err := bindFiles()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent: bind file listener: %v\n", err)
		select {}
	}
	tunnelL, err := bindTunnel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent: bind tunnel listener: %v\n", err)
		select {}
	}
	ptyL, err := bindPTY()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent: bind pty listener: %v\n", err)
		select {}
	}
	processL, err := bindProcesses()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent: bind process listener: %v\n", err)
		select {}
	}
	// Vsock probe — phase-1 bind so the accept queue survives snapshot.
	// Used only by the host's waitForAgent when opted into vsock probing;
	// silent no-op if the guest kernel lacks vsock support.
	startVsockProbe()

	startSelfSignal()

	// Block here until the host pushes phase:"live" via MMDS. The TEMPLATE
	// never reaches past this select — that's exactly the snapshot boundary.
	<-phase2Ch

	if probeL != nil {
		_ = probeL.Close()
	}

	// Hostname is owned entirely by watchMMDS, which applies the
	// user-facing VM name from the MMDS `hostname` field (always pushed
	// by the host on every create/restore). We deliberately do NOT set
	// the hostname here — phase 2 races watchMMDS, and setting it to the
	// sandbox id would clobber the name the watcher already applied.
	// Drain sandboxIDCh so watchMMDS's buffered send never leaks.
	select {
	case <-sandboxIDCh:
	default:
	}

	// ─── Phase 2: post-restore setup (runs fresh on every restored VM)
	overlayRoot := parseCmdlineArg("overlay_root")
	if overlayRoot != "" {
		setupOverlay(overlayRoot) // mounts /dev/vdb fresh → correct size
	}

	// Restore directory checkpoint mounts before starting services or hooks.
	if err := guestCheckpoints.initialize(); err != nil {
		fmt.Fprintf(os.Stderr, "agent: directory checkpoint recovery failed: %v\n", err)
		// Treat this like a rootfs mount failure. Do not leave a listener
		// accepting TCP while silently exposing an older directory view.
		os.Exit(1)
	}

	// Container-runtime environment setup, done once at boot so Docker and
	// k3s work with no per-tool configuration:
	//   - cgroup v2 unified hierarchy at /sys/fs/cgroup
	//   - /var/lib/{docker,containerd,rancher} on the raw per-VM ext4
	//     (overlay-on-overlay is rejected by the kernel)
	//   - OpenRC runtime state dir (so `curl … k3s | sh` → rc-service works)
	mountCgroup2()
	bindContainerDataDirs()
	initOpenRCRuntime()
	processManager, err := agentprocess.NewManager(agentprocess.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent: initialize process manager: %v\n", err)
		select {}
	}

	// /etc/hosts. Docker truncates this file at image-commit time (treats
	// it as a runtime bind-mount placeholder), so any RUN that populates
	// it during build is lost when the image is baked into an ext4. Write
	// the standard loopback aliases here — must happen AFTER the chroot
	// inside setupOverlay so we land on the rootfs's /etc/hosts, not the
	// initrd's. Things that resolve "localhost" (kubectl, k3s, docker,
	// npm, pytest, ...) need this.
	_ = os.WriteFile("/etc/hosts",
		[]byte("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\nfe00::0\tip6-localnet\nff00::0\tip6-mcastprefix\nff02::1\tip6-allnodes\nff02::2\tip6-allrouters\n"),
		0644)

	// Rewrite /etc/resolv.conf inside the rootfs. The phase-1 applyNetwork
	// call landed in the initramfs's /etc, which is gone after chroot. Also,
	// some rootfses (devbox) ship resolv.conf as a symlink to /proc/net/pnp
	// (kernel ip-autoconfig) — writing through the symlink hits a read-only
	// proc file, so the overlay DNS stub (169.254.20.10) never reaches the
	// resolver. Remove the symlink first, then write a real file from the
	// current MMDS doc.
	if doc, err := fetchMMDS(300 * time.Millisecond); err == nil && len(doc.Network.DNS) > 0 {
		var b bytes.Buffer
		for _, ns := range doc.Network.DNS {
			fmt.Fprintf(&b, "nameserver %s\n", ns)
		}
		_ = os.Remove("/etc/resolv.conf")
		_ = os.WriteFile("/etc/resolv.conf", b.Bytes(), 0644)
	}

	os.Setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	os.Setenv("HOME", "/root")
	os.Setenv("TERM", "linux")

	// Enable RPS (Receive Packet Steering) on eth0 so a single virtio
	// queue's softirq work spreads across all guest vCPUs. Firecracker's
	// virtio-net is hardcoded to 1 RX/TX queue (multi-queue isn't
	// supported), which on multi-vCPU shapes leaves single-stream
	// downloads CPU-bound at ~25 MB/s — one CPU does softirq, the other
	// does TCP recv, and TCP backs off. RPS in software gives us most
	// of the win that --mq-queues=N would give us in hardware.
	//
	// Setting rps_cpus to a bitmap of all online CPUs is safe: on 1-vCPU
	// shapes it's a no-op (only CPU 0 to dispatch to); on 2+ vCPU shapes
	// it lifts single-stream throughput from ~25 → ~50–80 MB/s.
	enableRPS()

	// Run user-supplied post-resume hooks. This is the matching half of
	// the host's pre-pause hook trigger: pre-pause.d scripts tear down
	// userspace daemons (s3fs, rclone) that hold remote sockets across
	// the snapshot boundary, post-resume.d scripts re-establish them on
	// the new host's network. Hooks run in alphabetical order; failures
	// are logged but never block the agent — exec listener has to come
	// up regardless so the operator can still reach the sandbox to fix
	// whatever broke.
	runPostResumeHooks()

	serveFilesOn(filesL)
	go serveTunnelOn(tunnelL)
	go servePTYOn(ptyL)
	serveProcessesOn(processL, processManager)
	// Phase-2 self-signal surface: /run/self FIFO. The HTTP listener on
	// :1029 is bound in phase 1 for snapshot survival; the FIFO needs the
	// post-pivot /run tmpfs so it's created here.
	go serveSelfFifo()
	// Rootfs is mounted, PATH is set, hooks have run. From here it's
	// safe for watchMMDS to drive applyDisks (which needs `s3fs` on the
	// filesystem). Until this flip, watchMMDS skips applyDisks.
	phase2DiskReady.Store(true)
	// Slow disk-apply retry loop. watchMMDS runs the fast path on every
	// MMDS change; this catches "MMDS unchanged but earlier mount
	// failed" and retries every 30 s independently of the adaptive MMDS polling interval.
	go runDiskApplyLoop()
	// Maintain long-running wall-clock accuracy with four tiny public SNTP
	// exchanges per day. This is asynchronous and never delays readiness.
	startPublicTimeSync()

	fmt.Println("agent: ready")
	for {
		conn, err := execL.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent: accept error: %v\n", err)
			continue
		}
		go handleAgentConn(conn)
	}
}

// startPhase1Probe opens a minimal TCP listener on phase1ProbePort. It accepts
// and immediately closes — just enough for the host to know the template is
// in phase 1 and safe to snapshot.
func startPhase1Probe() net.Listener {
	l, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", phase1ProbePort))
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent: phase1 probe listen failed: %v\n", err)
		return nil
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return l
}

type mmdsNetCfg struct {
	IP      string   `json:"ip"`
	Prefix  int      `json:"prefix"`
	Gateway string   `json:"gateway"`
	DNS     []string `json:"dns"`
	MAC     string   `json:"mac"`
}

type mmdsDoc struct {
	Network     mmdsNetCfg       `json:"network"`
	Phase       string           `json:"phase"`         // "live" post-restore; empty in template
	ID          string           `json:"id"`            // sandbox id from the host
	Hostname    string           `json:"hostname"`      // user-facing VM name; agent Sethostname's it
	Token       string           `json:"token"`         // per-VM shared secret; gates the agent services
	NowNS       int64            `json:"now_ns"`        // host wall-clock at push; agent calls clock_settime
	ClaimedAtMs int64            `json:"claimed_at_ms"` // set by pool-claim-kick; guest relaxes MMDS poll cap 5min after this
	Disks       []proto.MMDSDisk `json:"disks"`         // attached disks; mounted by applyDisks
}

var (
	bbIP      = "/bin/busybox"
	currentIP = ""
)

func ipArgs(args ...string) []string { return append([]string{"ip"}, args...) }

// fetchMMDS does one HTTP GET to the MMDS, returning the decoded doc or error.
func fetchMMDS(timeout time.Duration) (mmdsDoc, error) {
	client := &http.Client{Timeout: timeout}
	req, _ := http.NewRequest("GET", "http://169.254.169.254/", nil)
	req.Header.Set("Accept", "application/json")
	var doc mmdsDoc
	resp, err := client.Do(req)
	if err != nil {
		return doc, err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&doc)
	return doc, err
}

// applyNetwork applies a fetched mmds doc to eth0, replacing existing config.
// Uses raw AF_NETLINK RTNETLINK syscalls (stdlib only) to avoid the fork+exec
// cost of busybox — ~30–90 ms saved on every snapshot restore vs shelling
// out to `ip addr / ip route` four times.
func applyNetwork(doc mmdsDoc) error {
	// Set eth0 MAC first if provided. Snapshot-restored VMs come up with the
	// template's baked-in virtio MAC, not the slot's allocated MAC. The host
	// BPF policy rewrites the destination MAC of redirected frames to the
	// slot's MAC, so eth0 must match or virtio drops the frame.
	if doc.Network.MAC != "" {
		if err := netlinkSetMAC("eth0", doc.Network.MAC); err != nil {
			fmt.Fprintf(os.Stderr, "agent: set MAC %s on eth0: %v\n", doc.Network.MAC, err)
			// non-fatal: continue with IP/gw — cold-boot VMs already have the
			// right MAC from firecracker virtio config.
		}
	}
	if err := netlinkApply(doc.Network.IP, doc.Network.Prefix, doc.Network.Gateway); err != nil {
		return fmt.Errorf("netlink apply (addr=%s/%d gw=%s): %w",
			doc.Network.IP, doc.Network.Prefix, doc.Network.Gateway, err)
	}
	if len(doc.Network.DNS) > 0 {
		var b bytes.Buffer
		for _, ns := range doc.Network.DNS {
			fmt.Fprintf(&b, "nameserver %s\n", ns)
		}
		// devbox rootfs ships /etc/resolv.conf as a symlink to /proc/net/pnp
		// (kernel ip-autoconfig). Writing through the symlink hits the
		// read-only proc file and the DNS server list we just got from MMDS
		// — including the overlay stub at 169.254.20.10 — is silently lost.
		// Remove the symlink first so we land on a real file.
		_ = os.Remove("/etc/resolv.conf")
		_ = os.WriteFile("/etc/resolv.conf", b.Bytes(), 0644)
	}
	currentIP = doc.Network.IP
	// Prime the host's ARP cache by sending a single UDP packet to the
	// gateway. Kernel emits an ARP request before sending, so the host
	// learns our (possibly new) MAC without waiting for its own ARP on
	// the first inbound SYN. Stdlib-only; no fork+execve unlike the
	// previous `busybox ping`.
	go func(gw string) {
		if conn, err := net.Dial("udp", gw+":9"); err == nil {
			_, _ = conn.Write([]byte{0}) // port 9 (discard) — no response expected
			_ = conn.Close()
		}
	}(doc.Network.Gateway)
	fmt.Printf("agent[%s]: configured eth0 %s/%d gw %s\n", time.Now().Format("15:04:05.000"),
		doc.Network.IP, doc.Network.Prefix, doc.Network.Gateway)
	return nil
}

// configureNetworkFromMMDS brings eth0 up, fetches network config from the
// Firecracker MMDS, and applies it. Retries briefly because the host pushes
// metadata around the same time the guest boots.
func configureNetworkFromMMDS() error {
	execQuiet(bbIP, ipArgs("link", "set", "eth0", "up")...)
	execQuiet(bbIP, ipArgs("route", "add", "169.254.169.254", "dev", "eth0")...)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		doc, err := fetchMMDS(500 * time.Millisecond)
		if err == nil && doc.Network.IP != "" {
			return applyNetwork(doc)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("MMDS returned no network config within deadline")
}

// MMDS polling starts at 2 ms and backs off on unchanged documents. The
// initial cap is 20 ms; watchMMDS raises it to 200 ms five minutes after claim.
const (
	mmdsPollMin = 2 * time.Millisecond
	mmdsPollMax = 20 * time.Millisecond
)

// watchMMDS applies host-provided network, token, hostname, clock, and disk
// updates and unblocks phase 2 when the host publishes phase:"live".
func watchMMDS() {
	phase2Sent := false
	lastAppliedNowNS := int64(0)
	lastAppliedHostname := ""
	etcHostnameWritten := false
	var lastDoc mmdsDoc
	haveLastDoc := false
	interval := mmdsPollMin
	// Relax the polling cap five minutes after claim. Changes reset the
	// interval only once observed, so detection still depends on polling.
	var claimedAtMs int64
	pollMax := mmdsPollMax
	const relaxAfter = 5 * time.Minute
	const relaxedPollMax = 200 * time.Millisecond
	for {
		time.Sleep(interval)
		// Snapshots preserve routes. Avoid spawning ip on every poll;
		// retry the MMDS route only after a fetch failure below.
		doc, err := fetchMMDS(300 * time.Millisecond)
		if err != nil {
			// Recover from "route vanished" (shouldn't normally happen
			// post-snapshot): re-add the link-local route, then retry.
			execQuiet(bbIP, ipArgs("route", "add", "169.254.169.254", "dev", "eth0")...)
			continue
		}
		if doc.Network.IP != "" && doc.Network.IP != currentIP {
			if err := applyNetwork(doc); err != nil {
				fmt.Fprintf(os.Stderr, "agent: re-apply network failed: %v\n", err)
			}
		}
		// Apply the host's current secret, including a new identity when
		// restoring a full snapshot into a different sandbox.
		if doc.Token != "" {
			setToken(doc.Token)
		}
		// Apply the user-facing VM name as the guest hostname. MMDS is
		// sticky and this loop runs ~500x/sec, so dedup the Sethostname
		// syscall on the last value we acted on (mirrors the now_ns clock
		// logic above). Survives resume: a resume push with the same name
		// is a no-op.
		if doc.Hostname != "" {
			if doc.Hostname != lastAppliedHostname {
				lastAppliedHostname = doc.Hostname
				etcHostnameWritten = false // new name → rewrite the file
				if err := syscall.Sethostname([]byte(doc.Hostname)); err != nil {
					fmt.Fprintf(os.Stderr, "agent: sethostname(%q): %v\n", doc.Hostname, err)
				}
			}
			// The /etc/hostname write is retried every tick until it
			// succeeds: watchMMDS starts in phase 1, before the writable
			// overlay is mounted, so the first attempts hit a read-only
			// rootfs. Retrying converges once phase 2 mounts the overlay.
			if !etcHostnameWritten {
				if err := os.WriteFile("/etc/hostname", []byte(doc.Hostname+"\n"), 0o644); err == nil {
					etcHostnameWritten = true
				}
			}
		}
		// Apply host's wall-clock once per fresh push. MMDS is sticky —
		// the `now_ns` we read here is whatever the host PUT'd at restore
		// (or whatever the previous restore wrote, if no new push since)
		// and never changes on its own. Without dedup, we'd re-clobber
		// the system clock back to the restore moment on every poll and
		// freeze guest time. lastAppliedNowNS holds the last value we've
		// already acted on; we only fire on a new value.
		if doc.NowNS > 0 && doc.NowNS != lastAppliedNowNS {
			isResume := lastAppliedNowNS != 0
			lastAppliedNowNS = doc.NowNS
			drift := time.Duration(doc.NowNS - time.Now().UnixNano())
			if drift < 0 {
				drift = -drift
			}
			if drift > 2*time.Second {
				setSystemClockNS(doc.NowNS)
			}
			// On a resume (we've seen a NowNS before), phase 2 won't
			// re-run, but the user's post-resume.d hooks need to refire
			// to remount FUSE filesystems, reconnect daemons, etc.
			if isResume {
				go runPostResumeHooks()
				// The pre-pause hook unmounted every createos disk, but
				// applyDisks's content-hash cache still thinks they're
				// mounted. Reset it so the next watchMMDS tick reruns
				// the mount loop with the same disks set.
				resetDisksApplyCache()
			}
		}
		if !phase2Sent && doc.Phase == "live" {
			phase2Sent = true
			// Carry the id alongside the phase signal so phase 2 can set
			// hostname without doing its own MMDS fetch (which races with
			// the host's PATCH and times out under load).
			select {
			case sandboxIDCh <- doc.ID:
			default:
			}
			select {
			case phase2Ch <- struct{}{}:
			default:
			}
		}
		// Disk reconciliation. Only runs after phase 2's setupOverlay has
		// finished mounting the rootfs — applyDisks needs `s3fs` and its
		// libraries to exist on the filesystem, and during phase 1 we're
		// still in the initrd's tmpfs root. phase2DiskReady is set by
		// phase 2 after the overlay mount + chroot completes.
		if phase2DiskReady.Load() {
			applyDisks(doc.Disks)
		}
		// Adaptive interval: if the doc is identical to the last one we
		// saw, double the sleep up to pollMax. An observed change resets
		// the interval to the 2 ms floor.
		// Latch the claim timestamp and, once 5 minutes have passed since
		// claim, permanently relax the poll cap. Latched only-once so a
		// later MMDS mutation that carries claimed_at_ms=0 doesn't yo-yo
		// the interval back to aggressive.
		if claimedAtMs == 0 && doc.ClaimedAtMs > 0 {
			claimedAtMs = doc.ClaimedAtMs
		}
		if pollMax == mmdsPollMax && claimedAtMs > 0 &&
			time.Since(time.UnixMilli(claimedAtMs)) > relaxAfter {
			pollMax = relaxedPollMax
		}
		if haveLastDoc && mmdsDocEqual(doc, lastDoc) {
			interval *= 2
			if interval > pollMax {
				interval = pollMax
			}
		} else {
			interval = mmdsPollMin
		}
		lastDoc = doc
		haveLastDoc = true
	}
}

// mmdsDocEqual reports whether two MMDS docs would drive identical
// actions in watchMMDS. Compares the fields the loop actually reacts
// to (network, phase, id, hostname, token, now_ns, disks); other
// fields don't exist so the check is total.
func mmdsDocEqual(a, b mmdsDoc) bool {
	if a.Phase != b.Phase || a.ID != b.ID || a.Hostname != b.Hostname ||
		a.Token != b.Token || a.NowNS != b.NowNS {
		return false
	}
	if a.Network.IP != b.Network.IP || a.Network.Prefix != b.Network.Prefix ||
		a.Network.Gateway != b.Network.Gateway || a.Network.MAC != b.Network.MAC {
		return false
	}
	if len(a.Network.DNS) != len(b.Network.DNS) {
		return false
	}
	for i := range a.Network.DNS {
		if a.Network.DNS[i] != b.Network.DNS[i] {
			return false
		}
	}
	if len(a.Disks) != len(b.Disks) {
		return false
	}
	for i := range a.Disks {
		if a.Disks[i] != b.Disks[i] {
			return false
		}
	}
	return true
}

// setSystemClockNS sets CLOCK_REALTIME to the given absolute Unix
// nanoseconds via clock_settime(2). Stdlib only — kept agent-stdlib-clean
// (`make check-agent`).
//
// Called from watchMMDS when the host's pushed `now_ns` differs from ours
// by more than 2s. Almost always fires once on snapshot restore, then
// stays quiet because pushes are idempotent and the second tick's drift
// is small.
func setSystemClockNS(nsec int64) {
	ts := syscall.Timespec{Sec: nsec / 1_000_000_000, Nsec: nsec % 1_000_000_000}
	// CLOCK_REALTIME = 0 on Linux. syscall package doesn't expose
	// clock_settime, so use the raw syscall.
	const SYS_CLOCK_SETTIME = 227
	const CLOCK_REALTIME = 0
	if _, _, errno := syscall.Syscall(SYS_CLOCK_SETTIME, CLOCK_REALTIME,
		uintptr(unsafe.Pointer(&ts)), 0); errno != 0 {
		fmt.Fprintf(os.Stderr, "agent: clock_settime failed: %v\n", errno)
		return
	}
	fmt.Printf("agent[%s]: set system clock from MMDS\n",
		time.Now().Format("15:04:05.000"))
}

// enableRPS sets the receive-packet-steering bitmap for every RX queue
// of every non-loopback netdev to "all online CPUs", letting the kernel
// fan out softirq processing for a single hardware queue across all
// vCPUs. Effect on multi-vCPU sandboxes: ~2× single-stream download
// throughput. On 1-vCPU sandboxes it's a no-op.
//
// Done by writing a hex bitmap into /sys/class/net/<dev>/queues/rx-N/rps_cpus.
// Best-effort: any /sys write failure is logged and ignored — the
// kernel keeps its default of "no RPS" and we move on.
//
// Important: the bitmap MUST NOT have bits set for CPUs that don't
// exist. The kernel returns -EIO from store_rps_map when the cpumask
// includes any out-of-range CPU. So we read /proc/cpuinfo to count
// online CPUs and build exactly that many bits.
func enableRPS() {
	n := onlineCPUs()
	if n <= 0 {
		return
	}
	// Build a hex bitmap with the low n bits set. n=1 → "1", n=2 → "3",
	// n=4 → "f", n=8 → "ff". Format with up to 16 hex chars (64 bits)
	// is safer than fixed width — kernel parses any length.
	mask := (uint64(1) << n) - 1
	bitmap := fmt.Sprintf("%x", mask)

	netRoot := "/sys/class/net"
	entries, err := os.ReadDir(netRoot)
	if err != nil {
		return
	}
	for _, ent := range entries {
		name := ent.Name()
		if name == "lo" {
			continue
		}
		queuesDir := netRoot + "/" + name + "/queues"
		qs, err := os.ReadDir(queuesDir)
		if err != nil {
			continue
		}
		for _, q := range qs {
			if !strings.HasPrefix(q.Name(), "rx-") {
				continue
			}
			path := queuesDir + "/" + q.Name() + "/rps_cpus"
			if err := os.WriteFile(path, []byte(bitmap), 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "agent: rps_cpus=%s on %s: %v\n", bitmap, path, err)
			}
		}
	}
	fmt.Printf("agent[%s]: RPS enabled on all RX queues (cpus=%d, mask=0x%s)\n",
		time.Now().Format("15:04:05.000"), n, bitmap)
}

// onlineCPUs returns the count of online CPUs in the guest. Reads
// /sys/devices/system/cpu/online which the kernel keeps as a range
// list like "0-1" or "0".
func onlineCPUs() int {
	data, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(data))
	// Format examples: "0", "0-1", "0-3", "0,2-3" (rare).
	// We only handle the simple cases — sandboxes always have a
	// contiguous CPU set today.
	count := 0
	for _, part := range strings.Split(s, ",") {
		if strings.Contains(part, "-") {
			fields := strings.SplitN(part, "-", 2)
			var lo, hi int
			fmt.Sscanf(fields[0], "%d", &lo)
			fmt.Sscanf(fields[1], "%d", &hi)
			count += hi - lo + 1
		} else if part != "" {
			count++
		}
	}
	return count
}

// runPostResumeHooks executes every executable file in
// /etc/createos/post-resume.d/ in lexicographic order. Each hook gets
// 30s before SIGKILL — long enough for s3fs/rclone to mount, short
// enough that a buggy hook doesn't stall every spawn forever. The dir
// is allowed to not exist (no hooks installed = nothing to do).
func runPostResumeHooks() {
	const dir = "/etc/createos/post-resume.d"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // dir absent or unreadable — fine, no hooks installed
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := dir + "/" + e.Name()
		st, err := os.Stat(path)
		if err != nil || st.Mode()&0o111 == 0 {
			continue // not executable
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, path)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "agent: post-resume hook %s: %v\n", path, err)
		}
		cancel()
	}
}

func mustMount(source, target, fstype string, flags uintptr, data string) {
	os.MkdirAll(target, 0755)
	if err := syscall.Mount(source, target, fstype, flags, data); err != nil {
		fmt.Fprintf(os.Stderr, "mount %s on %s: %v\n", fstype, target, err)
	}
}

// mountCgroup2 mounts the cgroup-v2 unified hierarchy at /sys/fs/cgroup.
// Container runtimes (Docker, containerd, k3s/kubelet) all need it.
// Idempotent: EBUSY (already mounted, e.g. on a resumed VM) is swallowed.
func mountCgroup2() {
	os.MkdirAll("/sys/fs/cgroup", 0755)
	if err := syscall.Mount("cgroup2", "/sys/fs/cgroup", "cgroup2", 0, ""); err != nil {
		if err != syscall.EBUSY {
			fmt.Fprintf(os.Stderr, "agent: mount cgroup2: %v\n", err)
		}
	}
}

// bindContainerDataDirs bind-mounts the container-runtime data directories
// onto the raw per-VM ext4 (exposed at /.fc-overlay). The guest root is an
// overlayfs; containerd's overlay snapshotter cannot stack another
// overlayfs on top of it (overlay-on-overlay → EINVAL), so Docker and k3s
// both fail at first container-create unless their data lives on a plain
// filesystem. Doing this at boot means `docker run` and `curl … k3s | sh`
// work with zero per-tool configuration.
func bindContainerDataDirs() {
	if _, err := os.Stat("/.fc-overlay"); err != nil {
		return // no raw disk exposed — nothing to bind
	}
	for _, d := range []string{"docker", "containerd", "rancher"} {
		src := "/.fc-overlay/_" + d
		dst := "/var/lib/" + d
		os.MkdirAll(src, 0711)
		os.MkdirAll(dst, 0711)
		if err := syscall.Mount(src, dst, "", syscall.MS_BIND, ""); err != nil {
			fmt.Fprintf(os.Stderr, "agent: bind %s → %s: %v\n", src, dst, err)
		}
	}
}

// initOpenRCRuntime sets up OpenRC's runtime state directory. fc-agent is
// PID 1 (not OpenRC), so OpenRC never runs its own sysinit — without
// /run/openrc its service state machine is broken and `rc-service X start`
// gets stuck in a phantom "already starting" state. The k3s installer
// drives services through `rc-service`, so this matters: creating the
// state dirs + softlevel marker is the standard way to use OpenRC in a
// non-PID-1 / container context. No-op when OpenRC isn't installed.
func initOpenRCRuntime() {
	if _, err := os.Stat("/sbin/openrc-run"); err != nil {
		return // OpenRC not present in this rootfs
	}
	for _, d := range []string{
		"started", "starting", "stopping", "inactive", "failed",
		"hotplugged", "exclusive", "daemons", "options", "wasinactive",
	} {
		os.MkdirAll("/run/openrc/"+d, 0755)
	}
	// softlevel marker → OpenRC treats the system as booted at the
	// default runlevel, so rc-service operates instead of warning/wedging.
	if f, err := os.Create("/run/openrc/softlevel"); err == nil {
		f.Close()
	}
}

func parseCmdlineArg(key string) string {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}
	for _, arg := range strings.Fields(string(data)) {
		if strings.HasPrefix(arg, key+"=") {
			return strings.TrimPrefix(arg, key+"=")
		}
	}
	return ""
}

func setupOverlay(overlayRoot string) {
	// Mount writable layer
	if overlayRoot == "ram" {
		os.MkdirAll("/overlay", 0755)
		syscall.Mount("tmpfs", "/overlay", "tmpfs", 0, "")
	} else {
		os.MkdirAll("/overlay", 0755)
		if err := syscall.Mount("/dev/"+overlayRoot, "/overlay", "ext4", 0, ""); err != nil {
			fmt.Fprintf(os.Stderr, "mount overlay device: %v\n", err)
			return
		}
	}

	os.MkdirAll("/overlay/upper", 0755)
	os.MkdirAll("/overlay/work", 0755)

	// /lower is already mounted read-only and survives snapshot restore.

	// Create merged overlay view
	os.MkdirAll("/merged", 0755)
	opts := "lowerdir=/lower,upperdir=/overlay/upper,workdir=/overlay/work"
	if err := syscall.Mount("overlay", "/merged", "overlay", syscall.MS_NOATIME, opts); err != nil {
		fmt.Fprintf(os.Stderr, "mount overlay: %v\n", err)
		return
	}
	fmt.Println("agent: overlay mounted")

	// Prepare new root with essential mountpoints
	os.MkdirAll("/merged/proc", 0755)
	os.MkdirAll("/merged/sys", 0755)
	os.MkdirAll("/merged/dev", 0755)
	os.MkdirAll("/merged/tmp", 0755)
	os.MkdirAll("/merged/run", 0755)
	os.MkdirAll("/merged/oldroot", 0755)

	// Bind-mount the /overlay ext4 mountpoint inside the chroot so resize2fs
	// (invoked post-chroot) can find /dev/vdb's mount in /proc/mounts and use
	// the online-resize ioctl. Without this, the /overlay mount is hidden by
	// chroot and resize2fs falls back to opening /dev/vdb directly (which
	// fails with EBUSY because overlayfs holds the device).
	// Use a top-level path; /run, /tmp, /dev, /proc, /sys all get remounted
	// after chroot and would shadow a bind here.
	os.MkdirAll("/merged/.fc-overlay", 0700)
	if err := syscall.Mount("/overlay", "/merged/.fc-overlay", "", syscall.MS_BIND, ""); err != nil {
		fmt.Fprintf(os.Stderr, "bind-mount /overlay: %v\n", err)
	}

	// Copy busybox into overlay so watchMMDS can still reconfigure network
	// after chroot (rootfs may not have iproute2 or busybox installed).
	if data, err := os.ReadFile("/bin/busybox"); err == nil {
		os.MkdirAll("/merged/bin", 0755)
		_ = os.WriteFile("/merged/bin/busybox", data, 0755)
	}

	// Proper switch_root: MS_MOVE the overlay to be the mount
	// namespace root, THEN chroot into it.
	//
	// A bare chroot("/merged") only changes this process's fs->root —
	// it does NOT change the mount namespace's root mount
	// (mnt_ns->root), which would stay pointing at the initrd. That
	// breaks setns(CLONE_NEWNS): joining a container's mount namespace
	// (docker exec / kubectl exec / nsenter -m) relocates the joining
	// process's root via the mount-namespace topology, and a
	// chroot-only root is invisible to that machinery — the exec'd
	// process lands in an empty root ("executable file not found").
	//
	// mount(".", "/", MS_MOVE) makes the overlay the real namespace
	// root. This is exactly what util-linux switch_root does;
	// pivot_root can't be used here because the current root is the
	// initramfs.
	if err := syscall.Chdir("/merged"); err != nil {
		fmt.Fprintf(os.Stderr, "chdir /merged: %v\n", err)
		return
	}
	if err := syscall.Mount(".", "/", "", syscall.MS_MOVE, ""); err != nil {
		fmt.Fprintf(os.Stderr, "switch_root MS_MOVE: %v\n", err)
		return
	}
	if err := syscall.Chroot("."); err != nil {
		fmt.Fprintf(os.Stderr, "chroot: %v\n", err)
		return
	}
	fmt.Println("agent: switch_root done")
	syscall.Chdir("/")

	// Mount fresh filesystems in chroot
	mustMount("proc", "/proc", "proc", 0, "")
	mustMount("sysfs", "/sys", "sysfs", 0, "")
	mustMount("devtmpfs", "/dev", "devtmpfs", 0, "")
	// devtmpfs provides device nodes but not the conventional descriptor
	// links created by a normal init system. Shell process substitution and
	// tools that open /dev/std{in,out,err} rely on these links.
	_ = os.Symlink("/proc/self/fd", "/dev/fd")
	_ = os.Symlink("/proc/self/fd/0", "/dev/stdin")
	_ = os.Symlink("/proc/self/fd/1", "/dev/stdout")
	_ = os.Symlink("/proc/self/fd/2", "/dev/stderr")
	mustMount("tmpfs", "/dev/shm", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV,
		"mode=1777,size=256m")
	// /tmp intentionally lives on the root overlay (backed by /dev/vdb,
	// full disk_mib worth of space) instead of a tmpfs. Large writes
	// (bun install ~2.5 GB, build caches) used to hit ENOSPC on the
	// half-of-RAM tmpfs cap; disk-backed /tmp makes the sandbox's
	// advertised disk actually usable by /tmp.
	mustMount("tmpfs", "/run", "tmpfs", 0, "")
	// /dev/pts (devpts) is required for openpty() — without it any
	// pty-requesting session (sshd, script, docker exec, etc.) fails
	// with "PTY allocation request failed". devtmpfs alone only
	// provides the static /dev entries and /dev/ptmx without the
	// backing /dev/pts directory.
	os.MkdirAll("/dev/pts", 0755)
	mustMount("devpts", "/dev/pts", "devpts", 0, "mode=620,ptmxmode=666")
}

func execQuiet(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Run()
}

func exitCodeFromWaitErr(err error, pid int) (int, bool) {
	status, ok := childreaper.TakeStatus(err, pid)
	if !ok {
		return 0, false
	}
	return status.ExitStatus(), true
}

func handleAgentConn(conn net.Conn) {
	defer conn.Close()

	reader := authenticateConn(conn)
	if reader == nil {
		// authenticateConn already closed the conn; do not write a body —
		// no response is the only safe failure mode (avoids token oracle).
		return
	}

	// Normal exec JSON still follows the existing path. Checkpoint RPCs use
	// an explicit prefix on the same authenticated connection, not a shell command.
	if first, _ := reader.Peek(1); len(first) == 1 && first[0] == proto.CheckpointRequestPrefix[0] {
		handleCheckpointConn(conn, reader)
		return
	}

	line, err := reader.ReadBytes('\n')
	if err != nil {
		writeJSON(conn, proto.ExecResponse{ExitCode: -1, Error: fmt.Sprintf("read error: %v", err)})
		return
	}

	var req proto.ExecRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, proto.ExecResponse{ExitCode: -1, Error: fmt.Sprintf("json error: %v", err)})
		return
	}

	if req.Stream {
		handleStreamingExec(conn, req)
		return
	}

	// Execute in a private cgroup so cancellation stops descendants too. Cap each output
	// buffer at 1 MiB so a runaway command (`yes`, etc.) can't OOM
	// the agent — agent is PID 1, so its death takes the VM with it.
	// Truncation emits a sentinel suffix; the exit code still flows.
	// Connection closure or the runtime ceiling cancels the command, with
	// SIGTERM followed by cgroup-wide SIGKILL after the grace period.
	clientCtx, stop := requestctx.WithDisconnect(context.Background(), conn)
	defer stop()
	ctx, cancel := context.WithTimeout(clientCtx, execTimeoutBuffered)
	defer cancel()
	stdout := &capBuffer{max: maxExecOutputBytes}
	stderr := &capBuffer{max: maxExecOutputBytes}
	cmd := exec.CommandContext(ctx, req.Cmd, req.Args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if req.Stdin != "" {
		cmd.Stdin = boundedStdin(req.Stdin)
	}
	cleanup, err := agentprocess.BindExecCommand(cmd)
	if err != nil {
		writeJSON(conn, proto.ExecResponse{ExitCode: -1, Error: err.Error()})
		return
	}
	defer cleanup()
	// Merge the host-injected env-var map into the agent's inherited
	// environment. Inheriting first guarantees PATH/HOME/TERM (set in
	// phase 2) reach the child; appending after means later entries —
	// the user's vars — win on duplicates, exactly the os/exec contract.
	if len(req.Env) > 0 {
		env := os.Environ()
		for k, v := range req.Env {
			env = append(env, k+"="+v)
		}
		cmd.Env = env
	}

	exitCode := 0
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else if cmd.Process != nil {
			if ec, ok := exitCodeFromWaitErr(err, cmd.Process.Pid); ok {
				exitCode = ec
			} else {
				writeJSON(conn, proto.ExecResponse{ExitCode: -1, Error: err.Error()})
				return
			}
		} else {
			writeJSON(conn, proto.ExecResponse{ExitCode: -1, Error: err.Error()})
			return
		}
	}
	if cmd.Process != nil {
		childreaper.Forget(cmd.Process.Pid)
	}

	writeJSON(conn, proto.ExecResponse{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
	})
}

// handleStreamingExec runs the command and emits one NDJSON event per
// stdout/stderr chunk. A 5s heartbeat keeps the stream observable; socket
// closure cancels silent commands without waiting for a failed write.
// Cancellation terminates the command's cgroup with SIGTERM → SIGKILL grace.
//
// Stdout and stderr are read from separate pipes as output arrives.
// Both readers and the heartbeat serialize JSON writes through one mutex
// so their events cannot interleave on the connection.
func handleStreamingExec(conn net.Conn, req proto.ExecRequest) {
	// Both client disconnect and the runtime ceiling terminate the command
	// and its descendants. Heartbeats remain useful to stream consumers.
	clientCtx, stopClient := requestctx.WithDisconnect(context.Background(), conn)
	defer stopClient()
	ctx, cancel := context.WithTimeout(clientCtx, execTimeoutStreaming)
	defer cancel()
	cmd := exec.CommandContext(ctx, req.Cmd, req.Args...)
	cleanup, err := agentprocess.BindExecCommand(cmd)
	if err != nil {
		emitExecEvent(conn, nil, proto.ExecStreamEvent{Error: err.Error()})
		return
	}
	defer cleanup()
	if len(req.Env) > 0 {
		env := os.Environ()
		for k, v := range req.Env {
			env = append(env, k+"="+v)
		}
		cmd.Env = env
	}
	if req.Stdin != "" {
		cmd.Stdin = boundedStdin(req.Stdin)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		emitExecEvent(conn, nil, proto.ExecStreamEvent{Error: "stdout pipe: " + err.Error()})
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		emitExecEvent(conn, nil, proto.ExecStreamEvent{Error: "stderr pipe: " + err.Error()})
		return
	}
	if err := cmd.Start(); err != nil {
		emitExecEvent(conn, nil, proto.ExecStreamEvent{Error: "start: " + err.Error()})
		return
	}

	// writeMu serialises emissions so a heartbeat never splits an event.
	var writeMu sync.Mutex
	stop := make(chan struct{})
	kill := cancel

	// Writer helper. Returns false on conn write failure → caller should
	// trigger kill + bail. Locks writeMu so HB cannot interleave.
	emit := func(ev proto.ExecStreamEvent) bool {
		writeMu.Lock()
		defer writeMu.Unlock()
		ok := emitExecEvent(conn, &writeMu /* already held */, ev)
		return ok
	}
	_ = emit // pleaser for unused-warning paths

	// Pipe pumper — reads up to 4 KiB at a time and emits Out/Err events.
	// Smaller chunks would mean more events per second; 4 KiB matches
	// io.Copy default and keeps per-event overhead low.
	pump := func(r io.Reader, kind string) {
		buf := make([]byte, 4096)
		for {
			n, rerr := r.Read(buf)
			if n > 0 {
				ev := proto.ExecStreamEvent{}
				if kind == "out" {
					ev.Stdout = string(buf[:n])
				} else {
					ev.Stderr = string(buf[:n])
				}
				if !emit(ev) {
					kill()
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}

	var pumpWg sync.WaitGroup
	pumpWg.Add(2)
	go func() { defer pumpWg.Done(); pump(stdout, "out") }()
	go func() { defer pumpWg.Done(); pump(stderr, "err") }()

	// Heartbeat loop — fires every 5s. Doubles as a peer-alive probe:
	// if emit returns false the conn is broken and we kill the cmd.
	hbDone := make(chan struct{})
	go func() {
		defer close(hbDone)
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if !emit(proto.ExecStreamEvent{HB: true}) {
					kill()
					return
				}
			}
		}
	}()

	pumpWg.Wait()
	werr := cmd.Wait()
	close(stop)
	<-hbDone

	exit := 0
	if werr != nil {
		if ee, ok := werr.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else if cmd.Process != nil {
			if ec, ok := exitCodeFromWaitErr(werr, cmd.Process.Pid); ok {
				exit = ec
			} else {
				emit(proto.ExecStreamEvent{Error: werr.Error()})
			}
		} else {
			emit(proto.ExecStreamEvent{Error: werr.Error()})
		}
	}
	if cmd.Process != nil {
		childreaper.Forget(cmd.Process.Pid)
	}
	emit(proto.ExecStreamEvent{ExitCode: &exit})
}

// emitExecEvent writes a single NDJSON line. Returns false on write
// failure so the caller can stop. The mu argument is the writeMu the
// caller already holds — accepted only as a contract reminder; the
// actual lock is taken by the caller.
func emitExecEvent(conn net.Conn, _ *sync.Mutex, ev proto.ExecStreamEvent) bool {
	data, err := json.Marshal(ev)
	if err != nil {
		return false
	}
	data = append(data, '\n')
	_, werr := conn.Write(data)
	return werr == nil
}

// streamExecEventReader is exposed to the host package via the proto
// shape; the agent just emits NDJSON. Defining it here keeps bufio
// referenced in the import block for callers that need it.
var _ = bufio.NewReader

func writeJSON(w io.Writer, v any) {
	data, _ := json.Marshal(v)
	data = append(data, '\n')
	w.Write(data)
}

// maxExecOutputBytes caps stdout/stderr buffers per exec response.
// Agent runs as PID 1; runaway output would OOM the kernel and kill
// the VM. 1 MiB is enough for realistic dev workflows; anything
// bigger should use streaming exec.
const maxExecOutputBytes = 1 << 20

// maxExecInputBytes caps the size of stdin in a single exec request. Stdin
// is parsed as part of the JSON body, so an attacker (or a buggy caller)
// could otherwise force the agent to allocate an arbitrarily large
// contiguous string. Agent is PID 1 — OOM kills the VM. 10 MiB matches the
// orders-of-magnitude rule of thumb: stdout/stderr cap at 1 MiB, stdin gets
// 10× headroom for legitimate "pipe in a file" usage but is still bounded.
const maxExecInputBytes = 10 << 20

// execTimeoutBuffered caps a buffered command's wall-clock runtime at one
// hour. The deadline or client disconnect cancels the command and terminates
// its cgroup. Output buffers have separate byte limits; this timeout does not
// limit the number of concurrent exec requests.
const execTimeoutBuffered = 1 * time.Hour

// execTimeoutStreaming is the ceiling on a streaming (`createos-cli exec --stream`)
// command. Streaming exec is the long-running flavor (tail -f, build
// watches). Connection closure cancels the command directly; this
// timeout also bounds commands whose clients remain connected.
const execTimeoutStreaming = 1 * time.Hour

// boundedStdin returns an io.Reader over s that exposes at most
// maxExecInputBytes. Truncates silently — the request was already parsed
// at this point, so this is purely defense in depth against an oversized
// Stdin field slipping past higher-layer caps.
func boundedStdin(s string) io.Reader {
	if len(s) > maxExecInputBytes {
		s = s[:maxExecInputBytes]
	}
	return strings.NewReader(s)
}

// capBuffer is an io.Writer with a hard byte cap. Past the cap, it
// silently discards input but tracks the total so the consumer can
// detect truncation. Stdlib only.
type capBuffer struct {
	buf       []byte
	max       int
	truncated bool
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if len(c.buf) >= c.max {
		c.truncated = true
		return len(p), nil
	}
	room := c.max - len(c.buf)
	if room < len(p) {
		c.buf = append(c.buf, p[:room]...)
		c.truncated = true
		return len(p), nil
	}
	c.buf = append(c.buf, p...)
	return len(p), nil
}

func (c *capBuffer) String() string {
	if !c.truncated {
		return string(c.buf)
	}
	return string(c.buf) + "\n[truncated — output exceeded 1 MiB; use streaming exec for larger outputs]\n"
}
