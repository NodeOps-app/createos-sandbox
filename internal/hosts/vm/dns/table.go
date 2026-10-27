// Package dns provides the overlay DNS stub that resolves sandbox names
// within the fc.local zone. It is intentionally small — only A records,
// only the name forms below, and only for VMs the local host can see
// via the network reconciler's view of sandbox_networks.
//
// Resolved names:
//
//	<sandbox_id>.fc.local          → VM IP (any network membership)
//	<name>.fc.local                → VM IP (by user-facing VM name)
//	<name>.<net_name>.fc.local     → VM IP (scoped to that network)
//
// The table is populated by the reconciler on every tick. The DNS server
// reads it under a read lock, so ticks and queries don't block each other.
//
// Cross-tenant safety: VM names and network names are unique only PER
// USER, not globally — two tenants can each have a VM "app" in a network
// "net". The table is therefore keyed by VNI (globally unique), never by
// network name. A query's network-name component is resolved to a VNI
// *within the requester's own membership* (where names are unambiguous),
// so one tenant can never resolve another tenant's VM.
package dns

import (
	"strconv"
	"sync"
)

// Table is the shared name→IP mapping populated by the network reconciler.
type Table struct {
	mu sync.RWMutex

	// sbID → IP, e.g. "01abc" → "10.0.4.6". Keys lowercased to match
	// DNS QNAME (the server lowercases on parse).
	bySandboxID map[string]string

	// "<vni>/<name>" → IP, e.g. "5/web-1" → "10.0.4.6". Keyed by VNI
	// (globally unique) + the user-facing VM name (lowercased). NOT by
	// network name — network names collide across tenants.
	byName map[string]string

	// VM-IP → (lowercased network name → VNI) for the networks that VM
	// joined. Used to scope name resolution: a query for
	// "<name>.<net>.fc.local" resolves <net> to a VNI only within the
	// requester's own memberships, then looks up "<vni>/<name>".
	srcNets map[string]map[string]int
}

// NameKey builds the byName key for a (vni, name) pair.
func NameKey(vni int, name string) string {
	return strconv.Itoa(vni) + "/" + name
}

// NewTable returns an empty DNS table.
func NewTable() *Table {
	return &Table{
		bySandboxID: make(map[string]string),
		byName:      make(map[string]string),
		srcNets:     make(map[string]map[string]int),
	}
}

// Update atomically replaces the table content with the given snapshot.
// Called by the network reconciler on every tick. byName is keyed by
// "<vni>/<name>" (see nameKey); srcNets maps VM IP → (network name → VNI).
func (t *Table) Update(bySandboxID, byName map[string]string, srcNets map[string]map[string]int) {
	t.mu.Lock()
	t.bySandboxID = bySandboxID
	t.byName = byName
	t.srcNets = srcNets
	t.mu.Unlock()
}

// LookupSandbox returns the IP for a sandbox ID, gated by VNI
// intersection between the requester (srcIP) and the target VM. Returns
// "" (NXDOMAIN) when the requester and target share no networks.
//
// The intersection check mirrors LookupBareName / LookupName: caller's
// network set is t.srcNets[srcIP], target's is t.srcNets[target_ip].
// If either side has no membership entry (caller not on the overlay,
// target not in any network), the lookup fails closed. The BPF data
// plane would have dropped the resulting packet anyway, but gating
// DNS too keeps sandbox-ID existence from leaking across tenants.
func (t *Table) LookupSandbox(sbID, srcIP string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	targetIP, ok := t.bySandboxID[sbID]
	if !ok || targetIP == "" {
		return ""
	}
	srcSet, srcOK := t.srcNets[srcIP]
	dstSet, dstOK := t.srcNets[targetIP]
	if !srcOK || !dstOK {
		return ""
	}
	// Intersect the VNI sets (values of the network-name → VNI maps).
	// Build a small set from the smaller side, scan the larger.
	if len(srcSet) > len(dstSet) {
		srcSet, dstSet = dstSet, srcSet
	}
	seen := make(map[int]struct{}, len(srcSet))
	for _, vni := range srcSet {
		seen[vni] = struct{}{}
	}
	for _, vni := range dstSet {
		if _, ok := seen[vni]; ok {
			return targetIP
		}
	}
	return ""
}

// LookupName returns the IP for "<name>.<networkName>" iff srcIP is a
// member of a network it knows by that name. The network name is resolved
// to a VNI within the requester's own memberships, so a tenant can only
// ever reach VMs in its own networks — cross-tenant queries return ""
// (NXDOMAIN) even when another tenant has an identically named network.
func (t *Table) LookupName(name, networkName, srcIP string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	set, ok := t.srcNets[srcIP]
	if !ok {
		// Unknown source (not a tracked overlay VM) — refuse name resolution.
		return ""
	}
	vni, in := set[networkName]
	if !in {
		return "" // requester not in a network by that name
	}
	return t.byName[NameKey(vni, name)]
}

// LookupBareName resolves "<name>.fc.local" — the network-unqualified
// form. It only succeeds when the name resolves within one of the
// networks the requester (srcIP) itself belongs to; names in other
// tenants' networks stay NXDOMAIN. If the same name exists in multiple
// of the requester's networks the first match wins.
func (t *Table) LookupBareName(name, srcIP string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	set, ok := t.srcNets[srcIP]
	if !ok {
		// Unknown source (not a tracked overlay VM) — refuse resolution.
		return ""
	}
	for _, vni := range set {
		if ip := t.byName[NameKey(vni, name)]; ip != "" {
			return ip
		}
	}
	return ""
}
