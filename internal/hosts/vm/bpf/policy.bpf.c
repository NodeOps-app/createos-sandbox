// SPDX-License-Identifier: GPL-2.0
//
// policy.bpf.c — overlay tenant-isolation programs (pair-allow-list model).
//
// Three TC classifier programs:
//
//   fc_veth_policy   host-veth INGRESS (VM → host).  src=ifindex (unspoofable),
//                    dst=packet's dst_ip.  Anti-spoofs guest-supplied src_ip
//                    via fc_iface_to_ip, then probes fc_iface_pair for
//                    (ifindex, dst_ip).
//   fc_veth_deliver  host-veth EGRESS (host → VM).   Defense in depth on the
//                    delivery side.  src=src_ip (already validated by an
//                    earlier hop), dst=ifindex's VM.  Probes fc_vmip_pair.
//   fc_wg_ingress    wg-hosts INGRESS (decrypted cross-host).  src=src_ip
//                    (clamped by WG AllowedIPs), dst=dst_ip.  Probes
//                    fc_vmip_pair.
//
// Maps owned by the Go reconciler:
//
//   fc_iface_pair    (ifindex u32, dst_ip u32) → u8
//   fc_vmip_pair     (src_ip  u32, dst_ip u32) → u8
//   fc_known_vmips   ip      u32              → u8
//   fc_iface_to_ip   ifindex u32              → u32 expected_src_ip
//   fc_vm_subnet     0                        → {network u32, mask u32}
//
// Per-packet cost: 1-3 hash probes.  No bitmap math, no VNI knowledge in
// BPF.  Networks-per-region cap matches the design (16M VNIs, 24-bit).

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define CREATEOS_BPF_MAX_VMS 65536
#define CREATEOS_BPF_MAX_PAIRS (1 << 20)  // 1M allowed pairs per map

// Agent listener ports inside every VM. The host dials these on VM_IP
// from the host netns; no other VM should ever be able to reach them.
// Keep in sync with internal/agent/*.go (agentPort, filePort, tunnelPort,
// ptyPort, processPort).
#define CREATEOS_AGENT_PORT_LO 1024
#define CREATEOS_AGENT_PORT_HI 1028

// ------- shared policy maps (created by Go, opened by name) -------

// (ifindex, dst_ip) → 1 — used by fc_veth_policy. ifindex is unspoofable;
// guest can't change which veth the host puts it behind.
struct pair_key {
    __u32 a;   // ifindex (iface_pair) or src_ip (vmip_pair)
    __u32 b;   // dst_ip
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CREATEOS_BPF_MAX_PAIRS);
    __type(key, struct pair_key);
    __type(value, __u8);
} fc_iface_pair SEC(".maps");

// (src_ip, dst_ip) → 1 — used by fc_wg_ingress and fc_veth_deliver, both
// of which receive packets whose source has already been validated by an
// earlier hop (WG AllowedIPs or fc_veth_policy).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CREATEOS_BPF_MAX_PAIRS);
    __type(key, struct pair_key);
    __type(value, __u8);
} fc_vmip_pair SEC(".maps");

// ip → 1 — set of IPs we recognise as VMs. Used to distinguish "VM
// endpoint" from "host gateway / external" so legitimate external
// traffic is allowed through.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CREATEOS_BPF_MAX_VMS);
    __type(key, __u32);
    __type(value, __u8);
} fc_known_vmips SEC(".maps");

// ifindex → expected src_ip — anti-spoof bind at fc_veth_policy. Stored
// in network byte order to match packet view. Independent layer from
// rp_filter.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CREATEOS_BPF_MAX_VMS);
    __type(key, __u32);
    __type(value, __u32);
} fc_iface_to_ip SEC(".maps");

// ------- per-host config maps (written once at startup by Go) -------

struct vm_subnet {
    __u32 network; // network order
    __u32 mask;    // network order
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct vm_subnet);
} fc_vm_subnet SEC(".maps");

// ------- helpers -------

// is_vm_ip reports whether ip (network order) falls inside this host's
// VM /22. Used by fc_veth_policy to short-circuit "destination is
// clearly external" without a map lookup. Best-effort: returns 0 on
// missing config (allow lookup path).
static __always_inline int is_vm_ip(__u32 ip) {
    __u32 idx = 0;
    struct vm_subnet *s = bpf_map_lookup_elem(&fc_vm_subnet, &idx);
    if (!s)
        return 0;
    return (ip & s->mask) == (s->network & s->mask);
}

// parse_ipv4_eth parses an L2 frame (Ethernet + IP). Used on veth
// ingress/egress where the skb has an Ethernet header. Returns -1 on
// error.
static __always_inline int parse_ipv4_eth(struct __sk_buff *skb,
                                          __u32 *src, __u32 *dst) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    *src = ip->saddr;
    *dst = ip->daddr;
    return 0;
}

// tcp_dst_port_eth returns the TCP destination port (host byte order)
// from an L2 frame, or 0 if not TCP / parse failure.
static __always_inline __u16 tcp_dst_port_eth(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;
    if (ip->protocol != IPPROTO_TCP)
        return 0;

    __u32 ihl_bytes = ip->ihl * 4;
    if (ihl_bytes < sizeof(struct iphdr))
        return 0;

    struct tcphdr *tcp = (void *)ip + ihl_bytes;
    if ((void *)(tcp + 1) > data_end)
        return 0;

    return bpf_ntohs(tcp->dest);
}

// parse_ipv4_l3 parses a bare IP frame (no Ethernet header). Used on
// wg-hosts ingress — WG decrypts to L3-only packets, no MACs. Returns
// -1 on error.
static __always_inline int parse_ipv4_l3(struct __sk_buff *skb,
                                         __u32 *src, __u32 *dst) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end)
        return -1;
    if (ip->version != 4)
        return -1;

    *src = ip->saddr;
    *dst = ip->daddr;
    return 0;
}

// ------- programs -------

// fc_veth_policy: attached to host-veth INGRESS (VM → host).
//
// Trust: source identity comes from skb->ifindex (kernel-assigned, VM
// cannot change which veth it's behind). dst is the packet's dst_ip
// (what the kernel will route to). guest-supplied src_ip is verified
// against fc_iface_to_ip first — packets where src_ip ≠ the expected
// IP for this ifindex are dropped (anti-spoof, independent of rp_filter).
//
// If dst is not a known VM (external internet, host gateway), allow
// through; the per-VM egress chain handles allowlist filtering.
//
// If dst IS a known VM, require (ifindex, dst_ip) ∈ fc_iface_pair.
SEC("classifier/fc_veth_policy")
int fc_veth_policy(struct __sk_buff *skb) {
    __u32 ifidx = skb->ifindex;

    __u32 src_ip, dst_ip;
    if (parse_ipv4_eth(skb, &src_ip, &dst_ip) < 0)
        return TC_ACT_OK;

    // 1. Anti-spoof: src_ip must match the IP we expect from this veth.
    //    Allow lookup miss — the iface may not be a managed VM (host
    //    sidecar process, dev box). Strict drop only when there's a
    //    binding AND it disagrees.
    __u32 *expected = bpf_map_lookup_elem(&fc_iface_to_ip, &ifidx);
    if (expected && *expected != src_ip)
        return TC_ACT_SHOT;

    // 2. Is destination a managed VM?
    __u8 *dst_known = bpf_map_lookup_elem(&fc_known_vmips, &dst_ip);
    if (!dst_known) {
        // Not a VM — internet / host gateway / agent path. Allow.
        return TC_ACT_OK;
    }

    // 3. Pair allow-list lookup. (ifindex, dst_ip) present → allow.
    struct pair_key k = { .a = ifidx, .b = dst_ip };
    if (bpf_map_lookup_elem(&fc_iface_pair, &k))
        return TC_ACT_OK;

    return TC_ACT_SHOT;
}

// fc_veth_deliver: attached to host-veth EGRESS (host → VM).
//
// Defense in depth on the delivery side. By the time a packet reaches
// here, src_ip has already been validated:
//
//   * Same-host VM-to-VM: src passed fc_veth_policy (ifindex check)
//   * Cross-host VM-to-VM: src passed fc_wg_ingress (WG AllowedIPs)
//   * Host gateway → VM:  not in fc_known_vmips, allowed through
//
// We re-verify (src_ip, dst_ip) is in fc_vmip_pair to catch a stale
// fc_iface_pair miss or an IP-reuse race during slot recycling.
SEC("classifier/fc_veth_deliver")
int fc_veth_deliver(struct __sk_buff *skb) {
    __u32 src_ip, dst_ip;
    if (parse_ipv4_eth(skb, &src_ip, &dst_ip) < 0)
        return TC_ACT_OK;

    // Is src a managed VM? If not, this is host-gateway / external →
    // allow (the dst veth's egress chain handles per-VM allowlists).
    __u8 *src_known = bpf_map_lookup_elem(&fc_known_vmips, &src_ip);
    if (!src_known)
        return TC_ACT_OK;

    // Src IS another overlay VM. Hard-deny access to the agent's
    // privileged listener ports (1024 exec, 1025 files, 1026 tunnel,
    // 1027 PTY, 1028 managed processes) regardless of pair membership —
    // those ports are
    // host↔agent only and must never be reachable from a peer VM, even
    // one in the same tenant network.
    __u16 dport = tcp_dst_port_eth(skb);
    if (dport >= CREATEOS_AGENT_PORT_LO && dport <= CREATEOS_AGENT_PORT_HI)
        return TC_ACT_SHOT;

    // Pair lookup. Allowed pair → ok, missing → drop.
    struct pair_key k = { .a = src_ip, .b = dst_ip };
    if (bpf_map_lookup_elem(&fc_vmip_pair, &k))
        return TC_ACT_OK;

    return TC_ACT_SHOT;
}

// fc_wg_ingress: attached to wg-hosts INGRESS (decrypted cross-host
// packets).
//
// WG already authenticated the peer host and checked the source IP is
// within that peer's claimed AllowedIPs. We additionally verify
// (src_vmip, dst_vmip) is in fc_vmip_pair — the receiver-side
// re-verify guarantees a compromised peer can't spoof memberships its
// real local state doesn't authorise.
SEC("classifier/fc_wg_ingress")
int fc_wg_ingress(struct __sk_buff *skb) {
    // wg-hosts is a TUN device — no Ethernet header on the skb, just
    // IP.
    __u32 src_ip, dst_ip;
    if (parse_ipv4_l3(skb, &src_ip, &dst_ip) < 0)
        return TC_ACT_SHOT;

    struct pair_key k = { .a = src_ip, .b = dst_ip };
    if (bpf_map_lookup_elem(&fc_vmip_pair, &k))
        return TC_ACT_OK;

    return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
