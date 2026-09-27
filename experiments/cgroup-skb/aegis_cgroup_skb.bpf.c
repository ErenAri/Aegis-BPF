// SPDX-License-Identifier: GPL-2.0
/* EXPERIMENT (#323): audit-only cgroup_skb observation.
 *
 * This is NOT part of the agent. It is a standalone object, built and loaded
 * only by experiments/cgroup-skb/, so it can be deleted without touching a
 * single production consumer. It shares no map, ring buffer or event type with
 * aegis.bpf.o.
 *
 * It enforces nothing. Both programs return 1 (pass) on every path, including
 * every error path. There is deliberately no code here that can return 0.
 *
 * The question it exists to answer is not "can we see packets" -- obviously we
 * can -- but "does a packet-context hook preserve the workload identity Aegis
 * already relies on". So every event carries BOTH candidate identities:
 *
 *   skb_cgid     bpf_skb_cgroup_id(skb)      -- identity of the socket's cgroup
 *   current_cgid bpf_get_current_cgroup_id() -- identity of the running task
 *
 * The LSM hooks use the second one. It is meaningful in process context
 * (connect/sendmsg) and meaningless in softirq (ingress), where "current" is
 * whatever task happened to be interrupted. Emitting both lets the experiment
 * measure that divergence instead of assuming it.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* vmlinux.h does not carry the uapi ethertype/protocol numbers. */
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

#define AEGIS_SKB_DIR_INGRESS 0
#define AEGIS_SKB_DIR_EGRESS  1

/* Why a packet could not be described. Reported rather than guessed at. */
#define AEGIS_SKB_OK              0
#define AEGIS_SKB_UNSUP_L3        1  /* not IPv4/IPv6 (ARP, VLAN-encapsulated, ...) */
#define AEGIS_SKB_UNSUP_L4        2  /* not TCP/UDP (ICMP, SCTP, ESP, ...) */
#define AEGIS_SKB_TRUNCATED       3  /* header did not fit in the linear area */
#define AEGIS_SKB_FRAGMENT        4  /* non-first fragment: no L4 header present */
#define AEGIS_SKB_V6_EXT_CHAIN    5  /* IPv6 extension chain not resolved to L4 */

struct aegis_skb_event {
    __u64 ts_ns;
    __u64 skb_cgid;      /* bpf_skb_cgroup_id() */
    __u64 current_cgid;  /* bpf_get_current_cgroup_id() */
    __u32 ifindex;
    __u32 len;
    __u8  direction;
    __u8  family;        /* 4 or 6, 0 when unknown */
    __u8  protocol;      /* IPPROTO_TCP / IPPROTO_UDP, 0 when unknown */
    __u8  parse_status;  /* AEGIS_SKB_* */
    __u16 sport;
    __u16 dport;
    __u8  saddr[16];
    __u8  daddr[16];
};

/* Prototype ring buffer, entirely separate from the agent's `events`. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} skb_events SEC(".maps");

/* Counters, so amplification can be measured even with emission switched off.
 * Index: 0 ingress seen, 1 egress seen, 2 emitted, 3 unparsed, 4 ringbuf full.
 */
#define CNT_INGRESS   0
#define CNT_EGRESS    1
#define CNT_EMITTED   2
#define CNT_UNPARSED  3
#define CNT_DROPPED   4
#define CNT_MAX       5

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, CNT_MAX);
} skb_counters SEC(".maps");

/* Emission mode, set from userspace so hook cost and observability cost can be
 * measured separately (B11): 0 = count only, 1 = emit events. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} skb_cfg SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *c = bpf_map_lookup_elem(&skb_counters, &idx);
    if (c)
        (*c)++;
}

static __always_inline __u32 emit_enabled(void)
{
    __u32 k = 0;
    __u32 *v = bpf_map_lookup_elem(&skb_cfg, &k);
    return v ? *v : 0;
}

/* Read from the network header rather than doing pointer arithmetic on
 * skb->data. bpf_skb_load_bytes_relative() knows where L3 starts for this hook
 * and refuses to read past the linear area, so a truncated packet returns an
 * error instead of being silently misread. Verifier memory safety is not the
 * same thing as reading the right bytes. */
static __always_inline int read_net(struct __sk_buff *skb, __u32 off, void *dst, __u32 len)
{
    return bpf_skb_load_bytes_relative(skb, off, dst, len, BPF_HDR_START_NET);
}

/* Returns true when ports were read. Deliberately bool rather than an int
 * status: this file's headline property is that no path returns 0 (the BPF
 * "drop" verdict), and a helper returning 0-for-success would make that
 * property impossible to check by grep. */
static __always_inline bool parse_l4_ports(struct __sk_buff *skb, __u32 l4_off, __u8 proto,
                                           struct aegis_skb_event *e)
{
    /* TCP and UDP both carry source then destination port in the first four
     * bytes; nothing deeper is read, and no payload is ever touched. */
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
        e->parse_status = AEGIS_SKB_UNSUP_L4;
        return false;
    }
    __be16 ports[2];
    if (read_net(skb, l4_off, &ports, sizeof(ports))) {
        e->parse_status = AEGIS_SKB_TRUNCATED;
        return false;
    }
    e->sport = bpf_ntohs(ports[0]);
    e->dport = bpf_ntohs(ports[1]);
    e->protocol = proto;
    return true;
}

static __always_inline void parse_ipv4(struct __sk_buff *skb, struct aegis_skb_event *e)
{
    struct iphdr iph;
    if (read_net(skb, 0, &iph, sizeof(iph))) {
        e->parse_status = AEGIS_SKB_TRUNCATED;
        return;
    }
    e->family = 4;
    __builtin_memcpy(e->saddr, &iph.saddr, 4);
    __builtin_memcpy(e->daddr, &iph.daddr, 4);

    /* A non-first fragment carries no L4 header. Reading "ports" there would
     * produce payload bytes dressed up as port numbers. */
    if (bpf_ntohs(iph.frag_off) & 0x1fff) {
        e->parse_status = AEGIS_SKB_FRAGMENT;
        return;
    }

    /* ihl is attacker-influenced; clamp it before using it as an offset. */
    __u32 ihl = iph.ihl;
    if (ihl < 5 || ihl > 15) {
        e->parse_status = AEGIS_SKB_TRUNCATED;
        return;
    }
    (void)parse_l4_ports(skb, ihl * 4, iph.protocol, e);
}

static __always_inline void parse_ipv6(struct __sk_buff *skb, struct aegis_skb_event *e)
{
    struct ipv6hdr ip6;
    if (read_net(skb, 0, &ip6, sizeof(ip6))) {
        e->parse_status = AEGIS_SKB_TRUNCATED;
        return;
    }
    e->family = 6;
    __builtin_memcpy(e->saddr, &ip6.saddr, 16);
    __builtin_memcpy(e->daddr, &ip6.daddr, 16);

    __u8 nexthdr = ip6.nexthdr;
    if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP) {
        (void)parse_l4_ports(skb, sizeof(struct ipv6hdr), nexthdr, e);
        return;
    }

    /* Extension headers are deliberately NOT walked. A bounded walk would be
     * possible, but this experiment does not need L4 ports for such packets,
     * and a partial walk that silently stops is how parsers start lying. The
     * event says the chain was not resolved and the address pair still stands.
     */
    e->parse_status = AEGIS_SKB_V6_EXT_CHAIN;
}

static __always_inline int observe(struct __sk_buff *skb, __u8 direction)
{
    bump(direction == AEGIS_SKB_DIR_INGRESS ? CNT_INGRESS : CNT_EGRESS);

    struct aegis_skb_event stack_e = {};
    stack_e.direction = direction;
    stack_e.ts_ns = bpf_ktime_get_ns();
    stack_e.len = skb->len;
    stack_e.ifindex = skb->ifindex;
    stack_e.skb_cgid = bpf_skb_cgroup_id(skb);
    stack_e.current_cgid = bpf_get_current_cgroup_id();
    stack_e.parse_status = AEGIS_SKB_OK;

    switch (skb->protocol) {
    case bpf_htons(ETH_P_IP):
        parse_ipv4(skb, &stack_e);
        break;
    case bpf_htons(ETH_P_IPV6):
        parse_ipv6(skb, &stack_e);
        break;
    default:
        /* ARP, VLAN-tagged frames, anything else: recorded as unsupported
         * rather than forced into an IPv4 shape. */
        stack_e.parse_status = AEGIS_SKB_UNSUP_L3;
        break;
    }

    if (stack_e.parse_status != AEGIS_SKB_OK)
        bump(CNT_UNPARSED);

    if (!emit_enabled())
        return 1;

    struct aegis_skb_event *e = bpf_ringbuf_reserve(&skb_events, sizeof(*e), 0);
    if (!e) {
        bump(CNT_DROPPED);
        return 1;
    }
    __builtin_memcpy(e, &stack_e, sizeof(*e));
    bpf_ringbuf_submit(e, 0);
    bump(CNT_EMITTED);
    return 1;
}

SEC("cgroup_skb/ingress")
int aegis_skb_ingress(struct __sk_buff *skb)
{
    return observe(skb, AEGIS_SKB_DIR_INGRESS);
}

SEC("cgroup_skb/egress")
int aegis_skb_egress(struct __sk_buff *skb)
{
    return observe(skb, AEGIS_SKB_DIR_EGRESS);
}

char LICENSE[] SEC("license") = "GPL";
