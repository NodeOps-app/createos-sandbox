package vm

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// iptRestore pipes a multi-line script to `iptables-restore --noflush` so an
// entire rule set lands in a single xt_lock acquisition.
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

// ProxyHTTPPort and ProxyHTTPSPort are the ports the transparent proxy listens on.
// Egress rules direct HTTP/HTTPS traffic here for domain-based filtering.
const (
	ProxyHTTPPort  = 8081
	ProxyHTTPSPort = 8443
)

// agentTimeServerIPs are infrastructure egress, not tenant policy. The guest
// PID-1 agent sends one SNTP packet to one of these Cloudflare anycast
// endpoints every six hours. Keep this list identical to publicTimeServers in
// internal/agent/time_sync.go. Only UDP/123 is exempted; no other traffic to
// these addresses bypasses a sandbox's allowlist.
var agentTimeServerIPs = []string{"162.159.200.1", "162.159.200.123"}

// HostVethFor returns the host-side veth interface name for the given VM IP.
// This is the interface in the root netns whose peer is in the VM's netns —
// the natural attach point for iptables rules.
//
// Direct netlink route-get (RTM_GETROUTE) instead of fork+exec'ing `ip route
// get` — under burst, the shell-out competes with kernel for fork-bomb-style
// task creation and dominates the tNet phase (~10-100 ms variance). Native
// netlink is one syscall round-trip, sub-millisecond.
func HostVethFor(vmIP string) (string, error) {
	ip := net.ParseIP(vmIP)
	if ip == nil {
		return "", fmt.Errorf("invalid VM IP %q", vmIP)
	}
	routes, err := netlink.RouteGet(ip)
	if err != nil {
		return "", fmt.Errorf("route get %s: %w", vmIP, err)
	}
	if len(routes) == 0 || routes[0].LinkIndex == 0 {
		return "", fmt.Errorf("no route to %s", vmIP)
	}
	link, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return "", fmt.Errorf("link by index %d: %w", routes[0].LinkIndex, err)
	}
	return link.Attrs().Name, nil
}

// sandboxChain returns the iptables chain name for a given sandbox ID.
// Chain names are limited to 28 chars in iptables; with ULID-shaped ids
// (sb-<26-char-ulid>), we hash to a 12-char digest so "fc-<hash>" fits
// comfortably. Same hash function as veth naming for consistency.
func sandboxChain(id string) string {
	return EgressChainPrefix + shortHash(id)
}

// sandboxDNSChain gates access to the node-local recursive resolver. Traffic
// to 169.254.20.10 is local to the host and traverses INPUT, not FORWARD, so
// it cannot be controlled by sandboxChain alone.
func sandboxDNSChain(id string) string {
	return "fcdns-" + shortHash(id)
}

// buildEgressRuleChunks produces the per-VM nat- and filter-table rule
// chunks for one egress install — *without* the surrounding
// "*nat … COMMIT *filter … COMMIT" wrappers. Returns ("", "") when the
// install should be a no-op (allow-all or empty rules).
//
// Extracted so both InstallEgress (single VM, single transaction) and
// the install batcher (N VMs, one combined transaction) can share the
// rule-building logic without copying it.
func buildEgressRuleChunks(id, vmIP, veth string, rules []string) (natChunk, filterChunk string, ok bool) {
	if len(rules) == 0 {
		return "", "", true // allow-all: nothing to install
	}
	parsed, parseOK := parseEgressRules(rules)
	if !parseOK {
		log.Warnf("[egress] sandbox %s has invalid rules; refusing policy install", id)
		return "", "", false
	}
	if parsed.allowAll {
		return "", "", true
	}
	chain := sandboxChain(id)
	var nat, filter strings.Builder
	nat.WriteString(":" + chain + " - [0:0]\n")
	filter.WriteString(":" + chain + " - [0:0]\n")

	// Always-exempt: VM's own /31 pair + the exact Firecracker MMDS
	// address. Do not exempt all of 169.254/16: it also contains the host's
	// recursive DNS stub (169.254.20.10), which would give an IP-only
	// restrictive policy a public DNS egress channel. Domain policies add a
	// narrow DNS :53 exemption below when resolution is actually required.
	if _, vmNet, err := net.ParseCIDR(vmIP + "/31"); err == nil {
		fmt.Fprintf(&filter, "-A %s -d %s -j ACCEPT\n", chain, vmNet.String())
	}
	fmt.Fprintf(&filter, "-A %s -d 169.254.169.254/32 -j ACCEPT\n", chain)
	for _, serverIP := range agentTimeServerIPs {
		fmt.Fprintf(&filter, "-A %s -d %s -p udp --dport 123 -j ACCEPT\n", chain, serverIP)
	}

	// The DNS stub is a host-local socket, so packets to it bypass the
	// FORWARD hook used by the normal egress chain. An IP-only restrictive
	// policy does not need recursive DNS; block the stub in INPUT to prevent
	// it becoming a public DNS exfiltration channel. Domain policies need the
	// resolver and receive the explicit :53 allowance below.
	if len(parsed.domains) == 0 {
		dnsChain := sandboxDNSChain(id)
		filter.WriteString(":" + dnsChain + " - [0:0]\n")
		fmt.Fprintf(&filter, "-A %s -p tcp --dport 53 -j REJECT --reject-with tcp-reset\n", dnsChain)
		fmt.Fprintf(&filter, "-A %s -p udp --dport 53 -j REJECT --reject-with icmp-port-unreachable\n", dnsChain)
		fmt.Fprintf(&filter, "-A %s -j REJECT --reject-with icmp-admin-prohibited\n", dnsChain)
		fmt.Fprintf(&filter, "-I INPUT -i %s -d 169.254.20.10/32 -j %s\n", veth, dnsChain)
	}

	// HARD peer-VM isolation: placed BEFORE any user ACCEPT.
	if vmSubnet != "" {
		fmt.Fprintf(&filter, "-A %s -d %s -j DROP\n", chain, vmSubnet)
	}

	for _, r := range parsed.ips {
		if r.port > 0 {
			fmt.Fprintf(&filter, "-A %s -d %s -p tcp --dport %d -j ACCEPT\n", chain, r.dst, r.port)
			fmt.Fprintf(&filter, "-A %s -d %s -p udp --dport %d -j ACCEPT\n", chain, r.dst, r.port)
		} else {
			fmt.Fprintf(&filter, "-A %s -d %s -j ACCEPT\n", chain, r.dst)
		}
	}

	if len(parsed.domains) > 0 {
		for _, resolver := range []string{"169.254.20.10", "1.1.1.1", "8.8.8.8"} {
			fmt.Fprintf(&filter, "-A %s -d %s -p udp --dport 53 -j ACCEPT\n", chain, resolver)
			fmt.Fprintf(&filter, "-A %s -d %s -p tcp --dport 53 -j ACCEPT\n", chain, resolver)
		}
		fmt.Fprintf(&nat, "-A %s -p tcp --dport 80 -j REDIRECT --to-port %d\n", chain, ProxyHTTPPort)
		fmt.Fprintf(&nat, "-A %s -p tcp --dport 443 -j REDIRECT --to-port %d\n", chain, ProxyHTTPSPort)
		fmt.Fprintf(&filter, "-A %s -p tcp --dport 80 -j ACCEPT\n", chain)
		fmt.Fprintf(&filter, "-A %s -p tcp --dport 443 -j ACCEPT\n", chain)
	}

	// A sandbox already knows it has an egress policy, so silently dropping
	// denied internet traffic only makes clients wait for their full timeout.
	// Preserve silent DROP for peer-VM isolation above, but fail terminal
	// internet denials immediately with a protocol-appropriate response.
	fmt.Fprintf(&filter, "-A %s -p tcp -j REJECT --reject-with tcp-reset\n", chain)
	fmt.Fprintf(&filter, "-A %s -j REJECT --reject-with icmp-admin-prohibited\n", chain)
	fmt.Fprintf(&nat, "-I PREROUTING -i %s -j %s\n", veth, chain)
	fmt.Fprintf(&filter, "-I FORWARD -i %s -j %s\n", veth, chain)
	return nat.String(), filter.String(), true
}

// InstallEgress creates a per-sandbox iptables chain that enforces the rules.
// Empty rules = allow-all (no rules installed, traffic passes untouched).
// Non-empty rules = allowlist; anything not matching is DROPped.
//
// Implementation: builds the entire rule set as an iptables-restore script
// and applies it in ONE transaction (one fork+exec, one xt_lock acquisition,
// atomic from the kernel's perspective). The previous loop-based version
// did 9-12 separate `iptables -A …` execs per VM — each grabbing the
// global xt_lock for ~10-30ms — which dominated sequential spawn latency
// (~+250ms per spawn at peak). Batching cuts that to ~10-20ms.
func InstallEgress(id, vmIP, veth string, rules []string) error {
	natChunk, filterChunk, ok := buildEgressRuleChunks(id, vmIP, veth, rules)
	if !ok {
		return fmt.Errorf("invalid egress rules")
	}
	if natChunk == "" && filterChunk == "" {
		// allow-all: make sure no stale chain is left
		// behind from a prior install with the same id. New VMs have
		// unique ids so this is a no-op in practice; pause/resume
		// reuses the id, hence the cleanup.
		RemoveSandboxIPTables(id, veth)
		return nil
	}
	// Pre-clear any stale jump rules pointing at the old chain so the
	// new jumps don't end up duplicated. Idempotent + single-txn.
	RemoveSandboxIPTables(id, veth)
	script := "*nat\n" + natChunk + "COMMIT\n*filter\n" + filterChunk + "COMMIT\n"
	if err := iptRestore(script); err != nil {
		return fmt.Errorf("install egress: %w", err)
	}
	log.Infof("[egress] installed chain %s for %s (veth=%s, %d rules)", sandboxChain(id), id, veth, len(rules))
	return nil
}

// RemoveSandboxIPTables tears down BOTH the egress chain (nat + filter) and
// the meter chain (filter) for a sandbox in a single iptables-restore
// transaction. One xt_lock acquisition instead of two — halves the destroy
// critical path under concurrent teardown.
//
// Safe when either/both chains are missing (meter only exists when the VM
// actually ran, egress only when rules were non-empty). The existence probe
// is the fastest read-only op, and the script is built from whichever
// chains exist.
func RemoveSandboxIPTables(id, veth string) {
	_ = removeSandboxIPTables(id, veth)
}

// removeSandboxIPTables is the checked form used when a dirty slot must stay
// quarantined until every sandbox-specific chain has actually been removed.
func removeSandboxIPTables(id, veth string) error {
	egressChain := sandboxChain(id)
	dnsChain := sandboxDNSChain(id)
	bwChain := "fcbw-" + shortHash(id)
	bwInChain := "fcbwin-" + shortHash(id)
	hasNatEgress, err := chainExists("nat", egressChain)
	if err != nil {
		return err
	}
	hasFilterEgress, err := chainExists("filter", egressChain)
	if err != nil {
		return err
	}
	hasDNS, err := chainExists("filter", dnsChain)
	if err != nil {
		return err
	}
	hasMeter, err := chainExists("filter", bwChain)
	if err != nil {
		return err
	}
	hasInMeter, err := chainExists("filter", bwInChain)
	if err != nil {
		return err
	}
	if !hasNatEgress && !hasFilterEgress && !hasDNS && !hasMeter && !hasInMeter {
		return nil
	}
	var sb strings.Builder
	if hasNatEgress {
		fmt.Fprintf(&sb, "*nat\n-D PREROUTING -i %s -j %s\n-F %s\n-X %s\nCOMMIT\n",
			veth, egressChain, egressChain, egressChain)
	}
	sb.WriteString("*filter\n")
	if hasFilterEgress {
		fmt.Fprintf(&sb, "-D FORWARD -i %s -j %s\n-F %s\n-X %s\n",
			veth, egressChain, egressChain, egressChain)
	}
	if hasDNS {
		fmt.Fprintf(&sb, "-D INPUT -i %s -d 169.254.20.10/32 -j %s\n-F %s\n-X %s\n",
			veth, dnsChain, dnsChain, dnsChain)
	}
	if hasMeter {
		fmt.Fprintf(&sb, "-D FORWARD -i %s -j %s\n-F %s\n-X %s\n",
			veth, bwChain, bwChain, bwChain)
	}
	if hasInMeter {
		fmt.Fprintf(&sb, "-D INPUT  -i %s -p tcp --sport 1026 -j %s\n", veth, bwInChain)
		fmt.Fprintf(&sb, "-D OUTPUT -o %s -p tcp --dport 1026 -j %s\n", veth, bwInChain)
		fmt.Fprintf(&sb, "-F %s\n-X %s\n", bwInChain, bwInChain)
	}
	sb.WriteString("COMMIT\n")
	if err := iptRestore(sb.String()); err != nil {
		return fmt.Errorf("remove sandbox iptables: %w", err)
	}
	return nil
}

// removeIfaceSandboxIPTables removes fc-owned chains referenced by one veth
// without requiring the sandbox ID. This is the restart-safe fallback for a
// quarantined slot: the netns/veth marker survives a process restart, while
// the in-memory sandboxID attached to the quarantine does not.
func removeIfaceSandboxIPTables(veth string) error {
	for _, table := range []string{"filter", "nat"} {
		cmd := exec.Command("iptables-save", "-t", table)
		out, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("inspect %s rules for veth %s: %w", table, veth, err)
		}
		var deletes []string
		chains := make(map[string]struct{})
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[0] != "-A" || !ruleReferencesIface(fields, veth) {
				continue
			}
			target := ruleJumpTarget(fields)
			if !isSandboxChain(target) {
				continue
			}
			fields[0] = "-D"
			deletes = append(deletes, strings.Join(fields, " "))
			chains[target] = struct{}{}
		}
		if len(deletes) == 0 {
			continue
		}
		var script strings.Builder
		fmt.Fprintf(&script, "*%s\n", table)
		for _, rule := range deletes {
			script.WriteString(rule + "\n")
		}
		for chain := range chains {
			fmt.Fprintf(&script, "-F %s\n-X %s\n", chain, chain)
		}
		script.WriteString("COMMIT\n")
		if err := iptRestore(script.String()); err != nil {
			return fmt.Errorf("remove %s rules for veth %s: %w", table, veth, err)
		}
	}
	return nil
}

func ruleReferencesIface(fields []string, veth string) bool {
	for i := 0; i+1 < len(fields); i++ {
		if (fields[i] == "-i" || fields[i] == "-o") && fields[i+1] == veth {
			return true
		}
	}
	return false
}

func ruleJumpTarget(fields []string) string {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "-j" {
			return fields[i+1]
		}
	}
	return ""
}

func isSandboxChain(chain string) bool {
	for _, prefix := range []string{"fc-", "fcdns-", "fcbw-", "fcbwin-"} {
		if strings.HasPrefix(chain, prefix) {
			return true
		}
	}
	return false
}

// RemoveEgress tears down the per-sandbox chain and the jump rules pointing to it.
//
// Uses a single iptables-restore transaction across nat + filter so destroy
// acquires xt_lock exactly once instead of six times. Under 50-wide parallel
// destroy the difference is ~30 seconds of kernel-lock serialisation.
//
// Safe on chains that never existed: we probe for the nat-side chain first
// (one fast read-only op) and no-op the whole teardown if it's missing. The
// two chains are installed together in InstallEgress, so either both exist
// or neither does.
func RemoveEgress(id, veth string) {
	_ = removeEgress(id, veth)
}

// removeEgress is the checked form used by live policy updates. Destroy and
// rehydrate retain best-effort RemoveEgress semantics, but a user-requested
// restricted→allow-all transition must not report success if teardown failed.
func removeEgress(id, veth string) error {
	chain := sandboxChain(id)
	dnsChain := sandboxDNSChain(id)
	hasNatEgress, err := chainExists("nat", chain)
	if err != nil {
		return err
	}
	hasFilterEgress, err := chainExists("filter", chain)
	if err != nil {
		return err
	}
	hasDNS, err := chainExists("filter", dnsChain)
	if err != nil {
		return err
	}
	if !hasNatEgress && !hasFilterEgress && !hasDNS {
		return nil
	}
	var script strings.Builder
	if hasNatEgress {
		fmt.Fprintf(&script, "*nat\n-D PREROUTING -i %s -j %s\n-F %s\n-X %s\nCOMMIT\n",
			veth, chain, chain, chain)
	}
	script.WriteString("*filter\n")
	if hasFilterEgress {
		fmt.Fprintf(&script, "-D FORWARD -i %s -j %s\n-F %s\n-X %s\n",
			veth, chain, chain, chain)
	}
	if hasDNS {
		fmt.Fprintf(&script, "-D INPUT -i %s -d 169.254.20.10/32 -j %s\n-F %s\n-X %s\n",
			veth, dnsChain, dnsChain, dnsChain)
	}
	script.WriteString("COMMIT\n")
	if err := iptRestore(script.String()); err != nil {
		return fmt.Errorf("remove egress: %w", err)
	}
	return nil
}

// ReplaceEgress replaces the policy of an already-restricted sandbox without
// first detaching its canonical chains. The FORWARD/PREROUTING jumps remain
// live while iptables-restore prepares the replacement and switch atomically
// at COMMIT. If restore fails, the old chain contents and jumps remain active.
func ReplaceEgress(id, vmIP, veth string, oldRules, newRules []string) error {
	oldParsed, oldOK := parseEgressRules(oldRules)
	newParsed, newOK := parseEgressRules(newRules)
	if !newOK {
		return fmt.Errorf("invalid egress rules")
	}
	oldRestricted := len(oldRules) > 0 && oldOK && !oldParsed.allowAll
	newRestricted := len(newRules) > 0 && !newParsed.allowAll

	// No old chain exists, so a failed install preserves the existing
	// allow-all policy. This is not the dangerous restricted→unrestricted
	// transition fixed below.
	if !oldRestricted {
		return InstallEgress(id, vmIP, veth, newRules)
	}
	if !newRestricted {
		return removeEgress(id, veth)
	}

	natChunk, filterChunk, ok := buildEgressReplacementChunks(id, vmIP, veth, oldParsed, newRules)
	if !ok {
		return fmt.Errorf("invalid egress rules")
	}

	applyTable := func(table, chunk string) error {
		return iptRestore("*" + table + "\n" + chunk + "COMMIT\n")
	}
	rollback := func(table string) error {
		rollbackNat, rollbackFilter, rollbackOK := buildEgressReplacementChunks(
			id, vmIP, veth, newParsed, oldRules,
		)
		if !rollbackOK {
			return fmt.Errorf("build %s rollback", table)
		}
		if table == "nat" {
			return applyTable(table, rollbackNat)
		}
		return applyTable(table, rollbackFilter)
	}

	// iptables-restore commits each table at its COMMIT marker; a later table
	// failure does not undo an earlier commit. When removing domain proxying,
	// install the restrictive filter first so direct :80/:443 traffic can
	// never escape between commits. For every other transition, switch NAT
	// first so newly broad filter rules can only reach the trusted proxy.
	filterFirst := len(oldParsed.domains) > 0 && len(newParsed.domains) == 0
	firstTable, firstChunk := "nat", natChunk
	secondTable, secondChunk := "filter", filterChunk
	if filterFirst {
		firstTable, firstChunk = "filter", filterChunk
		secondTable, secondChunk = "nat", natChunk
	}
	if err := applyTable(firstTable, firstChunk); err != nil {
		return fmt.Errorf("replace egress %s: %w", firstTable, err)
	}
	if err := applyTable(secondTable, secondChunk); err != nil {
		if rollbackErr := rollback(firstTable); rollbackErr != nil {
			return fmt.Errorf("replace egress %s: %w (rollback %s failed: %v)",
				secondTable, err, firstTable, rollbackErr)
		}
		return fmt.Errorf("replace egress %s: %w", secondTable, err)
	}
	chain := sandboxChain(id)
	log.Infof("[egress] replaced chain %s for %s (veth=%s, %d rules)", chain, id, veth, len(newRules))
	return nil
}

// buildEgressReplacementChunks rewrites the install chunks for an existing
// restricted sandbox. Its output contains no duplicate canonical jumps and
// accounts for creation/removal/reuse of the node-local DNS guard chain.
func buildEgressReplacementChunks(id, vmIP, veth string, current parsedRules, targetRules []string) (natChunk, filterChunk string, ok bool) {
	natChunk, filterChunk, ok = buildEgressRuleChunks(id, vmIP, veth, targetRules)
	if !ok {
		return "", "", false
	}
	chain := sandboxChain(id)
	dnsChain := sandboxDNSChain(id)
	natChunk = strings.Replace(natChunk, ":"+chain+" - [0:0]\n", "-F "+chain+"\n", 1)
	natChunk = strings.ReplaceAll(natChunk, fmt.Sprintf("-I PREROUTING -i %s -j %s\n", veth, chain), "")
	filterChunk = strings.Replace(filterChunk, ":"+chain+" - [0:0]\n", "-F "+chain+"\n", 1)
	filterChunk = strings.ReplaceAll(filterChunk, fmt.Sprintf("-I FORWARD -i %s -j %s\n", veth, chain), "")

	target, _ := parseEgressRules(targetRules)
	currentHasDNSGuard := len(current.domains) == 0
	targetHasDNSGuard := len(target.domains) == 0
	switch {
	case currentHasDNSGuard && targetHasDNSGuard:
		filterChunk = strings.Replace(filterChunk, ":"+dnsChain+" - [0:0]\n", "-F "+dnsChain+"\n", 1)
		filterChunk = strings.ReplaceAll(filterChunk,
			fmt.Sprintf("-I INPUT -i %s -d 169.254.20.10/32 -j %s\n", veth, dnsChain), "")
	case currentHasDNSGuard && !targetHasDNSGuard:
		filterChunk += fmt.Sprintf("-D INPUT -i %s -d 169.254.20.10/32 -j %s\n-F %s\n-X %s\n",
			veth, dnsChain, dnsChain, dnsChain)
		// !currentHasDNSGuard && targetHasDNSGuard deliberately keeps the
		// declaration and INPUT jump emitted by buildEgressRuleChunks.
	}
	return natChunk, filterChunk, true
}

func runIPT(args ...string) error {
	// Prepend -w so we queue on xt_lock instead of racing with concurrent
	// spawns. 2s is plenty for anything short of total kernel deadlock.
	full := append([]string{"-w", "2"}, args...)
	cmd := exec.Command("iptables", full...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

type parsedRules struct {
	domains  []string // proxy-side matching
	ips      []ipRule // kernel-side matching
	allowAll bool
}

type ipRule struct {
	dst  string // IP or CIDR (iptables accepts both)
	port int    // 0 = any
}

func parseEgressRules(rules []string) (parsedRules, bool) {
	p := parsedRules{}
	for _, raw := range rules {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if s == "*" {
			p.allowAll = true
			continue
		}
		host, portStr := s, ""
		if idx := strings.LastIndex(s, ":"); idx > 0 && !strings.Contains(s[idx+1:], "/") {
			// "host:port" — but avoid splitting "192.0.2.30/24" or IPv6 (not handled here)
			host, portStr = s[:idx], s[idx+1:]
		}
		port := 0
		if portStr != "" {
			n, err := strconv.Atoi(portStr)
			if err != nil || n < 0 || n > 65535 {
				return parsedRules{}, false
			}
			port = n
		}

		// Is this an IP or a CIDR?
		if ip := net.ParseIP(host); ip != nil {
			p.ips = append(p.ips, ipRule{dst: ip.String(), port: port})
			continue
		}
		if _, _, err := net.ParseCIDR(host); err == nil {
			p.ips = append(p.ips, ipRule{dst: host, port: port})
			continue
		}
		// Must be a domain name (or pattern).
		p.domains = append(p.domains, s)
	}
	return p, true
}
