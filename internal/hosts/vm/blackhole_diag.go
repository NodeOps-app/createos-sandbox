package vm

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
)

// blackholeDiagDir is where SYN-blackhole diagnostics land. Operator-
// readable; rotates only via operator action.
const blackholeDiagDir = "/var/log/createos/blackhole"

// captureBlackholeDiag is fired from the agent-not-ready path in
// Manager.Create. Best-effort: writes a 1s pcap of the failing slot's
// host veth plus iptables-save snapshots, so the next 1% failure
// produces packet-level evidence instead of a 5s shrug.
//
// Total wall budget ~1.2s. Caller already paid 5s waiting for the agent,
// so adding 1.2s before SIGTERM is in the noise.
func captureBlackholeDiag(sbID string, vmIP string, containerID string) {
	if err := os.MkdirAll(blackholeDiagDir, 0o755); err != nil {
		log.Warnf("[blackhole] mkdir %s: %v", blackholeDiagDir, err)
		return
	}
	ts := time.Now().UTC().Format("20060102T150405Z")
	prefix := filepath.Join(blackholeDiagDir, fmt.Sprintf("%s-%s", ts, sbID))

	veth, err := HostVethFor(vmIP)
	if err != nil {
		log.Warnf("[blackhole] %s: HostVethFor(%s): %v (slot=%s)", sbID, vmIP, err, containerID)
		return
	}

	// Snapshot iptables — captures any leaked rules from the prior
	// tenant of this IP. Cheap (~5ms) and the most likely culprit
	// after we've ruled out ARP/UFFD.
	for _, table := range []string{"filter", "nat", "mangle"} {
		out, err := exec.Command("iptables-save", "-t", table).Output()
		if err == nil {
			_ = os.WriteFile(prefix+".iptables-"+table+".txt", out, 0o644)
		}
	}

	// 1s pcap on the host-side veth. Captures both directions of any
	// SYN traffic — confirms whether SYNs reach the guest at all.
	pcap := prefix + ".pcap"
	cmd := exec.Command("tcpdump",
		"-i", veth,
		"-w", pcap,
		"-G", "1", "-W", "1",
		"-n", "-Z", "root",
	)
	if err := cmd.Start(); err != nil {
		log.Warnf("[blackhole] %s: tcpdump start on %s: %v", sbID, veth, err)
		return
	}

	// Give pcap ~150ms to attach to the iface, then dial a few SYNs
	// of our own so the capture has known stimulus packets.
	time.Sleep(150 * time.Millisecond)
	addr := net.JoinHostPort(vmIP, strconv.Itoa(agentPort))
	for i := 0; i < 4; i++ {
		d := net.Dialer{Timeout: 50 * time.Millisecond}
		c, derr := d.Dial("tcp", addr)
		if derr == nil {
			_ = c.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Tcpdump rolls every -G seconds; wait for the first roll.
	_ = cmd.Wait()

	log.Warnf("[blackhole] captured diag for %s (slot=%s ip=%s veth=%s) → %s.{pcap,iptables-*.txt}",
		sbID, containerID, vmIP, veth, prefix)
}
