package vm

// ┌──────────────────────────────────────────────────────────────┐
// │ Slot N=7                                                     │
// ├──────────────────────────────────────────────────────────────┤
// │  Netns name:      fcp7        (no hash — just the counter)   │
// │                   /var/run/netns/fcp7                        │
// │                                                              │
// │  Host-side veth:  fcp7        (no hash — same counter)       │
// │  in root netns                                               │
// │                                                              │
// │  Peer veth:       fcq<12-hex> (transient, ~1ms)              │
// │  briefly in root  → moved into the netns                     │
// │                   → renamed to "veth0"                       │
// │                                                              │
// │  Inside netns:    veth0   tap0   lo                          │
// └──────────────────────────────────────────────────────────────┘

import "fmt"

// naming.go is the single source of truth for every createos-specific
// name we put on the host: netns, interface, iptables chain, BPF map.
// Keeping them here lets one grep find every place a name is produced
// and prevents drift between code that creates a thing and code that
// looks it up later.
//
// Conventions:
//   - Linux interface names cap at IFNAMSIZ (15 chars).
//     Slot host veth ("fcp"+N) and transient peer ("fcq"+12-hex) both fit.
//   - iptables chain names cap at 28 chars; we always hash sandbox ids
//     before composing chain names.
//   - eBPF map/program names use underscores (kernel + bpftool convention).
//   - Other names use hyphens.

// ─── Netns ────────────────────────────────────────────────────────────

// NetnsPrefix names the slot's netns: <prefix><N> e.g. "fcp7".
// Same textual form as the host-side veth (VethHostPrefix+N) — they
// live in different kernel namespaces (filesystem entry under
// /var/run/netns/ vs netlink interface) so there's no actual collision.
const NetnsPrefix = "fcp"

// NetnsPathRoot is the dir the kernel mounts named netns files into.
const NetnsPathRoot = "/var/run/netns/"

// NetnsName returns the slot's netns name (e.g. "fcp7").
func NetnsName(n int) string { return fmt.Sprintf("%s%d", NetnsPrefix, n) }

// NetnsPath returns the on-disk path of the slot's netns
// (e.g. "/var/run/netns/fcp7").
func NetnsPath(n int) string { return NetnsPathRoot + NetnsName(n) }

// ─── Interface names (root netns) ─────────────────────────────────────

// VethHostPrefix is the host-side veth name's prefix. The full name
// is "fcp"+N — see VethNameFor (lives in network.go as vethNameFor).
const VethHostPrefix = "fcp"

// VethPeerPrefix is the transient peer veth name's prefix in root netns.
// The peer is moved into the slot's netns immediately and renamed to
// "veth0", so this name only exists for ~1ms during slot creation.
const VethPeerPrefix = "fcq"

// WGHostsDevName is the per-host WireGuard mesh device. Cross-host overlay
// traffic flows through this kernel WG interface — encrypted, authenticated,
// per-peer source-IP enforced via AllowedIPs.
const WGHostsDevName = "wg-hosts"

// ─── Interface names (inside the slot's netns) ────────────────────────

// VethGuestName is the peer's name after it's moved into the slot
// netns and renamed. Stable across slot lifetime.
const VethGuestName = "veth0"

// TapDevName is the tap device firecracker attaches to.
const TapDevName = "tap0"

// ─── In-VM identity ───────────────────────────────────────────────────

// GuestBootHostname is the hostname the agent sets early in phase-1.
// Overridden later via MMDS when control pushes the user-facing name.
const GuestBootHostname = "fc-vm"

// ─── iptables chains ──────────────────────────────────────────────────

// EgressChainPrefix prefixes per-sandbox egress allowlist chains:
// "fc-"+shortHash(sandboxID). Composed in sandboxChain (egress.go).
const EgressChainPrefix = "fc-"

// ─── BPF (pin paths + map names + program names) ──────────────────────

// BPFPinDir is the root pinning dir for every map and program we own.
// All children live under this single directory so a single rmtree
// reaps everything.
const BPFPinDir = "/sys/fs/bpf/createos"

// BPF meter map names — keyed by hash(sandboxID).
const (
	BPFMapIfaceToSID   = "fc_iface_to_sid"
	BPFMapEgressBytes  = "fc_egress_bytes"
	BPFMapIngressBytes = "fc_ingress_bytes"
	BPFMapCapFlags     = "fc_cap_flags"
	BPFMapSIDToGw      = "fc_sid_to_gw"
	BPFMapHostIPs      = "fc_host_ips"
)

// BPF meter program names (TCX, attached per-veth).
const (
	BPFProgMeterEgress  = "fc_meter_egress"
	BPFProgMeterIngress = "fc_meter_ingress"
)

// BPF policy map names. Four reconciler-written, one once-at-startup.
//
// Pair-allow-list model (option C): the reconciler enumerates which
// (src, dst) pairs of VMs share at least one overlay network and writes
// one entry per allowed pair. BPF lookup per packet is a single hash
// probe; the bitmap-intersect model with its 512-VNI cap is gone.
//
// Two pair maps for two trust contexts:
//   - fc_iface_pair  — src identity is unspoofable ifindex; used at
//     VM→host veth ingress (fc_veth_policy) where the
//     packet's src_ip can be guest-controlled.
//   - fc_vmip_pair   — src identity is src_ip; used at fc_wg_ingress
//     (WG's AllowedIPs already clamped src) and at
//     fc_veth_deliver (earlier hop already validated).
//
// Two ancillary maps:
//   - fc_known_vmips — set of VM IPs we manage; distinguishes
//     "VM endpoint" from "host gateway / external" so
//     external traffic is allowed through.
//   - fc_iface_to_ip — ifindex → expected_src_ip; explicit anti-spoof
//     check at fc_veth_policy independent of rp_filter.
const (
	BPFMapIfacePair  = "fc_iface_pair"  // (local_ifindex, dst_vmip) → 1
	BPFMapVMIPPair   = "fc_vmip_pair"   // (src_vmip, dst_vmip) → 1
	BPFMapKnownVMIPs = "fc_known_vmips" // vmip → 1 (this IP is a managed VM)
	BPFMapIfaceToIP  = "fc_iface_to_ip" // ifindex → expected src_ip (anti-spoof)
	BPFMapVMSubnet   = "fc_vm_subnet"   // this host's /22 (overlay-vs-internet prefilter)
)

// BPF policy program names (TC classifier).
const (
	BPFProgVethPolicy  = "fc_veth_policy"
	BPFProgVethDeliver = "fc_veth_deliver"
	BPFProgWGIngress   = "fc_wg_ingress"
)
