// Bandwidth meter for createos — replaces the iptables fcbw-* / fcbwin-*
// chains with a TC clsact-attached BPF program shared across all VMs.
//
// One pair of programs (egress + ingress) loaded ONCE, attached per host
// veth. Per-VM identification: a sandbox key map keyed by interface index.
// Userspace registers `iface_to_sid[ifindex] = sandbox_key` on Manager.Create
// and removes the entry on Destroy.
//
// Counters live in per-CPU hashes keyed by sandbox_key. Userspace sums
// across CPUs every 5s, persists to Postgres. Cap enforcement is via
// fc_cap_flags[sandbox_key] = 1 → drop.

#include <linux/bpf.h>
#include <linux/in.h>         /* IPPROTO_TCP */
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define CREATEOS_BPF_MAX_VMS 4096

// Control-path ports inside the guest agent (see CLAUDE.md §"Host → Guest
// communication"). These are host→VM RPC sockets and must NEVER be dropped
// by the bandwidth cap — capping them strands `createos-cli exec`/files/tunnel on
// any quota-exhausted sandbox. The meter still counts these bytes; only the
// DROP decision is exempted.
#define CREATEOS_AGENT_EXEC_PORT   1024
#define CREATEOS_AGENT_FILES_PORT  1025
#define CREATEOS_AGENT_TUNNEL_PORT 1026
#define CREATEOS_AGENT_PTY_PORT    1027
#define CREATEOS_AGENT_PROCESS_PORT 1028

// fc_host_ips is a small array map of host-side IPv4 addresses that
// are valid control-path destinations. Populated by userspace at BPF
// load time: index 0 = the host's primary IP (where the API server
// binds, where liveness probes originate from). The per-VM veth
// gateway is handled separately via gw_ip.
//
// We need both: requests originating from the host's API server land
// on the VM with src=primary_host_ip, so the VM's reply has
// dst=primary_host_ip — NOT the veth gateway. Without this map, every
// agent reply (exec, files, tunnel, PTY) would be dropped while the
// VM is capped, breaking the very channels you need to recharge.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);  // one primary + headroom for additional bind addresses
    __type(key, __u32);
    __type(value, __u32);    // IPv4 in network byte order, 0 = unset
} fc_host_ips SEC(".maps");

// is_control_path returns 1 if the skb is TCP, has a control-path port
// (sport OR dport ∈ {1024..1028}), AND its destination IPv4 equals
// either the host-veth gateway for this sandbox OR a registered host
// IP. The dst-IP gate is what distinguishes a legit agent reply
// (sport=1024, dst=host) from a bypass attempt like `curl evil.com:1024`
// (dport=1024, dst≠host). gw_ip is the per-sandbox gateway as set by
// userspace; passing it in avoids a second map lookup inside the
// caller. Non-IPv4 / non-TCP / malformed → 0.
static __always_inline int is_control_path(struct __sk_buff *skb, __u32 gw_ip) {
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
    // Anchor: dst IP must be either the per-VM veth gateway or one of
    // the registered host IPs. Defeats the dport-based bypass (a user
    // inside the VM can pick any dport but can't redirect to a host IP).
    int dst_ok = (gw_ip && ip->daddr == gw_ip);
    if (!dst_ok) {
        __u32 i0 = 0, i1 = 1, i2 = 2, i3 = 3;
        __u32 *h;
        h = bpf_map_lookup_elem(&fc_host_ips, &i0);
        if (h && *h && ip->daddr == *h) dst_ok = 1;
        if (!dst_ok) {
            h = bpf_map_lookup_elem(&fc_host_ips, &i1);
            if (h && *h && ip->daddr == *h) dst_ok = 1;
        }
        if (!dst_ok) {
            h = bpf_map_lookup_elem(&fc_host_ips, &i2);
            if (h && *h && ip->daddr == *h) dst_ok = 1;
        }
        if (!dst_ok) {
            h = bpf_map_lookup_elem(&fc_host_ips, &i3);
            if (h && *h && ip->daddr == *h) dst_ok = 1;
        }
    }
    if (!dst_ok)
        return 0;

    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(struct iphdr))
        return 0;
    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void *)(tcp + 1) > (void *)data_end)
        return 0;

    __u16 sport = bpf_ntohs(tcp->source);
    __u16 dport = bpf_ntohs(tcp->dest);
    if (sport >= CREATEOS_AGENT_EXEC_PORT && sport <= CREATEOS_AGENT_PROCESS_PORT)
        return 1;
    if (dport >= CREATEOS_AGENT_EXEC_PORT && dport <= CREATEOS_AGENT_PROCESS_PORT)
        return 1;
    return 0;
}

// ifindex → sandbox key. Populated by userspace at attach time.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CREATEOS_BPF_MAX_VMS);
    __type(key, __u32);    // veth ifindex
    __type(value, __u32);  // sandbox key (host-side hash of sandbox id)
} fc_iface_to_sid SEC(".maps");

// Per-CPU egress byte counter (VM-initiated traffic).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, CREATEOS_BPF_MAX_VMS);
    __type(key, __u32);
    __type(value, __u64);
} fc_egress_bytes SEC(".maps");

// Per-CPU ingress byte counter (host→VM, observation only).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, CREATEOS_BPF_MAX_VMS);
    __type(key, __u32);
    __type(value, __u64);
} fc_ingress_bytes SEC(".maps");

// Cap flag — set by userspace when usage >= quota; program drops.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CREATEOS_BPF_MAX_VMS);
    __type(key, __u32);
    __type(value, __u32);  // 0 allow, 1 drop
} fc_cap_flags SEC(".maps");

// Per-sandbox host-veth gateway IP (network byte order). Populated by
// userspace at Manager.Create / rehydrate; used by is_control_path() to
// anchor the cap-exemption to "destined for the host," defeating the
// dport-based bypass.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CREATEOS_BPF_MAX_VMS);
    __type(key, __u32);
    __type(value, __u32);
} fc_sid_to_gw SEC(".maps");

// Egress meter: attached to host-veth's INGRESS hook. Packets entering
// the host stack from the VM (= "VM-initiated egress" in createos billing
// terms) traverse here.
SEC("classifier/fc_meter_egress")
int fc_meter_egress(struct __sk_buff *skb) {
    __u32 ifidx = skb->ifindex;
    __u32 *sid = bpf_map_lookup_elem(&fc_iface_to_sid, &ifidx);
    if (!sid) {
        return TC_ACT_UNSPEC;  // not metered; let TCX chain continue to policy
    }
    __u32 key = *sid;

    __u32 *flag = bpf_map_lookup_elem(&fc_cap_flags, &key);
    if (flag && *flag) {
        // Cap is engaged — drop VM-initiated egress, but always let the
        // host↔agent control path (TCP :1024 exec, :1025 files, :1026
        // tunnel, :1027 PTY, :1028 managed processes) through, gated on
        // dst-IP == registered host gateway
        // so `curl evil.com:1024` can't bypass the cap.
        __u32 *gw = bpf_map_lookup_elem(&fc_sid_to_gw, &key);
        __u32 gw_ip = gw ? *gw : 0;
        if (!is_control_path(skb, gw_ip)) {
            return TC_ACT_SHOT;
        }
    }

    __u64 add = skb->len;
    __u64 *cur = bpf_map_lookup_elem(&fc_egress_bytes, &key);
    if (cur) {
        __sync_fetch_and_add(cur, add);
    } else {
        bpf_map_update_elem(&fc_egress_bytes, &key, &add, BPF_NOEXIST);
    }
    return TC_ACT_UNSPEC;  // continue TCX chain (policy program runs next)
}

// Ingress meter: attached to host-veth's EGRESS hook. Host-originated
// traffic destined for the VM. Observation-only — no cap.
SEC("classifier/fc_meter_ingress")
int fc_meter_ingress(struct __sk_buff *skb) {
    __u32 ifidx = skb->ifindex;
    __u32 *sid = bpf_map_lookup_elem(&fc_iface_to_sid, &ifidx);
    if (!sid) {
        return TC_ACT_UNSPEC;
    }
    __u32 key = *sid;

    __u64 add = skb->len;
    __u64 *cur = bpf_map_lookup_elem(&fc_ingress_bytes, &key);
    if (cur) {
        __sync_fetch_and_add(cur, add);
    } else {
        bpf_map_update_elem(&fc_ingress_bytes, &key, &add, BPF_NOEXIST);
    }
    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
