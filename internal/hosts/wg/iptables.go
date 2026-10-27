package wg

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Enforce installs (in one iptables-restore --noflush transaction):
//
//	INPUT -p udp --dport <wgPort> -s <peer.endpoint.ip>/32 -j ACCEPT (per peer)
//	INPUT -p udp --dport <wgPort> -j DROP                            (catchall)
//	INPUT -i <iface> -j ACCEPT                                       (decrypted overlay)
//
// WG decrypts straight to raw IP on wg-hosts ingress; the per-VM /31 routes
// carry it the rest of the way.
//
// Idempotent: rebuilt on every reconcile tick from the same peer list. We
// route the rules through a per-createos chain (FC-WG-INPUT) so we can
// flush+rebuild without disturbing other rules in INPUT.
func Enforce(iface string, wgPort int, peers []Peer) error {
	const chain = "FC-WG-INPUT"

	var b strings.Builder
	b.WriteString("*filter\n")
	// (Re)create the chain. ":CHAIN - [0:0]" both declares and flushes.
	b.WriteString(":" + chain + " - [0:0]\n")

	// Per-peer ACCEPTs on the WG port.
	wgPortStr := strconv.Itoa(wgPort)
	for _, p := range peers {
		if p.Endpoint == nil || p.Endpoint.IP == nil {
			continue
		}
		fmt.Fprintf(&b, "-A %s -p udp --dport %s -s %s/32 -j ACCEPT\n",
			chain, wgPortStr, p.Endpoint.IP.String())
	}
	// Catchall DROP on the WG port.
	fmt.Fprintf(&b, "-A %s -p udp --dport %s -j DROP\n", chain, wgPortStr)
	// Accept any decrypted packet that emerged from the WG tunnel — the
	// AllowedIPs ingress check inside WG plus fc_wg_ingress BPF already
	// gate by source IP and tenant VNI.
	fmt.Fprintf(&b, "-A %s -i %s -j ACCEPT\n", chain, iface)

	b.WriteString("COMMIT\n")

	if err := iptRestore(b.String()); err != nil {
		return fmt.Errorf("install wg INPUT rules: %w", err)
	}

	// Ensure INPUT jumps to our chain. Idempotent: -C first, -I only if missing.
	jump := []string{"INPUT", "-j", chain, "-m", "comment", "--comment", "createos-wg-mesh"}
	if exec.Command("iptables", append([]string{"-C"}, jump...)...).Run() != nil {
		if out, err := exec.Command("iptables", append([]string{"-I"}, jump...)...).CombinedOutput(); err != nil {
			return fmt.Errorf("install INPUT jump: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// iptRestore pipes a multi-line script through `iptables-restore --noflush`
// so the whole rule set lands in one xt_lock acquisition.
func iptRestore(script string) error {
	cmd := exec.Command("iptables-restore", "--noflush", "-w", "2")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables-restore: %w\nscript:\n%s\noutput: %s",
			err, script, strings.TrimSpace(string(out)))
	}
	return nil
}
