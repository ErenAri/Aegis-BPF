// SPDX-License-Identifier: GPL-2.0
/* EXPERIMENT (#323, phase 2): in-kernel flow aggregation, audit-only.
 *
 * Phase 1 (experiments/cgroup-skb/) established that per-packet export is not a
 * viable product architecture. This tests the follow-on hypothesis: that
 * aggregating in the kernel and exporting low-rate summaries turns the same
 * packet stream into something affordable and workload-attributed.
 *
 * Still enforces nothing. Both programs return 1 on every path; there is no
 * `return 0` in this file, which is checkable by grep on purpose.
 *
 * Schema decisions that differ from the obvious starting point, each of which
 * is measured rather than assumed (see FINDINGS.md):
 *
 *   - The local port is NOT in the key. A client's source port is ephemeral, so
 *     including it makes every connection a new flow and the map grows with
 *     connection count rather than with behaviour. Keying on the REMOTE
 *     endpoint collapses "1000 connections to one service" into one entry while
 *     preserving exactly the thing the behaviour signals need: how many
 *     distinct peers a workload talks to. A separate counter records how many
 *     distinct 5-tuples were seen, so the cost of that choice is visible rather
 *     than hidden.
 *
 *   - There is no `ack` counter. ACK is set on essentially every packet of an
 *     established connection, so counting it would restate `packets` in a
 *     second field and invite someone to read meaning into it.
 *
 *   - Nothing here is called a retransmission. Without sequence-state tracking
 *     this program cannot prove a retransmit, so the fields say what they
 *     actually count: syn_count, rst_count, fin_count.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP   0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#define DIR_INGRESS 0
#define DIR_EGRESS  1

#define PARSE_OK           0
#define PARSE_UNSUP_L3     1
#define PARSE_UNSUP_L4     2
#define PARSE_TRUNCATED    3
#define PARSE_FRAGMENT     4
#define PARSE_V6_EXT       5

/* Key: workload + peer. Deliberately no local port -- see header. */
struct flow_key {
    __u64 cgroup_id;
    __u8  remote_addr[16];   /* peer: dst on egress, src on ingress */
    __u16 remote_port;
    __u8  direction;
    __u8  family;            /* 4 or 6 */
    __u8  protocol;          /* IPPROTO_TCP / IPPROTO_UDP */
    __u8  _pad[3];
};

struct flow_value {
    __u64 packets;
    __u64 bytes;
    __u64 syn_count;      /* SYN seen; NOT "connections" and NOT retransmits */
    __u64 rst_count;
    __u64 fin_count;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u64 parse_errors;
};

/* LRU so the map is bounded by construction: an attacker generating cardinality
 * evicts old flows rather than growing memory without limit. Evictions are not
 * silent -- userspace reads the occupancy and the miss counters. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
    __uint(max_entries, 65536);
} flows SEC(".maps");

#define CNT_INGRESS_PKT   0
#define CNT_EGRESS_PKT    1
#define CNT_NEW_FLOW      2
#define CNT_UPDATE        3
#define CNT_PARSE_ERR     4
#define CNT_MAP_FULL      5
#define CNT_TUPLE5_NEW    6   /* what keying on the 5-tuple WOULD have cost */
#define CNT_MAX           7

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, CNT_MAX);
} counters SEC(".maps");

/* Shadow map used ONLY to measure the cardinality that a 5-tuple key would
 * produce. It is not part of the proposed design; it exists so the schema
 * decision above rests on a measured number. */
struct tuple5_key {
    __u64 cgroup_id;
    __u8  remote_addr[16];
    __u16 remote_port;
    __u16 local_port;
    __u8  direction;
    __u8  family;
    __u8  protocol;
    __u8  _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct tuple5_key);
    __type(value, __u64);
    __uint(max_entries, 262144);
} tuple5_shadow SEC(".maps");

/* 0 = aggregate only, 1 = also maintain the 5-tuple shadow map. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} cfg SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *c = bpf_map_lookup_elem(&counters, &idx);
    if (c)
        (*c)++;
}

static __always_inline __u32 shadow_enabled(void)
{
    __u32 k = 0;
    __u32 *v = bpf_map_lookup_elem(&cfg, &k);
    return v ? *v : 0;
}

static __always_inline int read_net(struct __sk_buff *skb, __u32 off, void *dst, __u32 len)
{
    return bpf_skb_load_bytes_relative(skb, off, dst, len, BPF_HDR_START_NET);
}

struct parsed {
    __u8  remote_addr[16];
    __u8  local_addr[16];
    __u16 remote_port;
    __u16 local_port;
    __u8  family;
    __u8  protocol;
    __u8  status;
    __u8  syn, rst, fin;
};

/* TCP flags, read only to count SYN/RST/FIN. No sequence numbers are read and
 * no connection state is kept: this is not conntrack. */
static __always_inline void read_tcp_flags(struct __sk_buff *skb, __u32 l4_off, struct parsed *p)
{
    __u8 flags;
    /* offset 13 in the TCP header holds the flag byte */
    if (read_net(skb, l4_off + 13, &flags, sizeof(flags)))
        return;
    p->syn = !!(flags & 0x02);
    p->rst = !!(flags & 0x04);
    p->fin = !!(flags & 0x01);
}

static __always_inline bool read_ports(struct __sk_buff *skb, __u32 l4_off, __u8 proto,
                                       struct parsed *p)
{
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
        p->status = PARSE_UNSUP_L4;
        return false;
    }
    __be16 ports[2];
    if (read_net(skb, l4_off, &ports, sizeof(ports))) {
        p->status = PARSE_TRUNCATED;
        return false;
    }
    p->local_port  = bpf_ntohs(ports[0]);   /* src of this packet */
    p->remote_port = bpf_ntohs(ports[1]);   /* dst of this packet */
    p->protocol = proto;
    if (proto == IPPROTO_TCP)
        read_tcp_flags(skb, l4_off, p);
    return true;
}

static __always_inline void parse_v4(struct __sk_buff *skb, struct parsed *p)
{
    struct iphdr iph;
    if (read_net(skb, 0, &iph, sizeof(iph))) { p->status = PARSE_TRUNCATED; return; }
    p->family = 4;
    __builtin_memcpy(p->local_addr, &iph.saddr, 4);
    __builtin_memcpy(p->remote_addr, &iph.daddr, 4);
    if (bpf_ntohs(iph.frag_off) & 0x1fff) { p->status = PARSE_FRAGMENT; return; }
    __u32 ihl = iph.ihl;
    if (ihl < 5 || ihl > 15) { p->status = PARSE_TRUNCATED; return; }
    (void)read_ports(skb, ihl * 4, iph.protocol, p);
}

static __always_inline void parse_v6(struct __sk_buff *skb, struct parsed *p)
{
    struct ipv6hdr ip6;
    if (read_net(skb, 0, &ip6, sizeof(ip6))) { p->status = PARSE_TRUNCATED; return; }
    p->family = 6;
    __builtin_memcpy(p->local_addr, &ip6.saddr, 16);
    __builtin_memcpy(p->remote_addr, &ip6.daddr, 16);
    __u8 nh = ip6.nexthdr;
    if (nh == IPPROTO_TCP || nh == IPPROTO_UDP) {
        (void)read_ports(skb, sizeof(struct ipv6hdr), nh, p);
        return;
    }
    /* Extension chains are not walked; a partial walk that silently stops is
     * how parsers start lying. */
    p->status = PARSE_V6_EXT;
}

static __always_inline int observe(struct __sk_buff *skb, __u8 direction)
{
    bump(direction == DIR_INGRESS ? CNT_INGRESS_PKT : CNT_EGRESS_PKT);

    struct parsed p = {};
    p.status = PARSE_OK;

    switch (skb->protocol) {
    case bpf_htons(ETH_P_IP):   parse_v4(skb, &p); break;
    case bpf_htons(ETH_P_IPV6): parse_v6(skb, &p); break;
    default: p.status = PARSE_UNSUP_L3; break;
    }

    struct flow_key k = {};
    /* Identity comes from the skb's cgroup, never from the current task.
     * Phase 1 measured bpf_get_current_cgroup_id() wrong for 95.8% of ingress
     * packets, because ingress runs in softirq where "current" is whatever was
     * interrupted. */
    k.cgroup_id = bpf_skb_cgroup_id(skb);
    k.direction = direction;
    k.family = p.family;
    k.protocol = p.protocol;

    /* "Remote" means the peer, which flips with direction: on ingress the
     * packet's source is the peer. Getting this backwards would make ingress
     * and egress flows for one conversation look like different peers. */
    if (direction == DIR_EGRESS) {
        __builtin_memcpy(k.remote_addr, p.remote_addr, 16);
        k.remote_port = p.remote_port;
    } else {
        __builtin_memcpy(k.remote_addr, p.local_addr, 16);
        k.remote_port = p.local_port;
    }

    __u64 now = bpf_ktime_get_ns();
    struct flow_value *v = bpf_map_lookup_elem(&flows, &k);
    if (v) {
        v->packets++;
        v->bytes += skb->len;
        v->last_seen_ns = now;
        if (p.status != PARSE_OK) v->parse_errors++;
        v->syn_count += p.syn;
        v->rst_count += p.rst;
        v->fin_count += p.fin;
        bump(CNT_UPDATE);
    } else {
        struct flow_value nv = {};
        nv.packets = 1;
        nv.bytes = skb->len;
        nv.first_seen_ns = now;
        nv.last_seen_ns = now;
        nv.parse_errors = (p.status != PARSE_OK);
        nv.syn_count = p.syn;
        nv.rst_count = p.rst;
        nv.fin_count = p.fin;
        if (bpf_map_update_elem(&flows, &k, &nv, BPF_ANY))
            bump(CNT_MAP_FULL);
        else
            bump(CNT_NEW_FLOW);
    }

    if (p.status != PARSE_OK)
        bump(CNT_PARSE_ERR);

    /* Measurement-only: what a 5-tuple key would have cost in cardinality. */
    if (shadow_enabled() && p.status == PARSE_OK) {
        struct tuple5_key t = {};
        t.cgroup_id = k.cgroup_id;
        __builtin_memcpy(t.remote_addr, k.remote_addr, 16);
        t.remote_port = k.remote_port;
        t.local_port = (direction == DIR_EGRESS) ? p.local_port : p.remote_port;
        t.direction = direction;
        t.family = p.family;
        t.protocol = p.protocol;
        __u64 one = 1;
        if (!bpf_map_lookup_elem(&tuple5_shadow, &t)) {
            if (!bpf_map_update_elem(&tuple5_shadow, &t, &one, BPF_ANY))
                bump(CNT_TUPLE5_NEW);
        }
    }

    return 1;
}

SEC("cgroup_skb/ingress")
int aegis_flow_ingress(struct __sk_buff *skb) { return observe(skb, DIR_INGRESS); }

SEC("cgroup_skb/egress")
int aegis_flow_egress(struct __sk_buff *skb) { return observe(skb, DIR_EGRESS); }

char LICENSE[] SEC("license") = "GPL";
