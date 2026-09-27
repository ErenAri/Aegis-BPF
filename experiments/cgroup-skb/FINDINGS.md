# `cgroup_skb` audit experiment — findings (#323)

Kernel `7.0.0-28-generic`, x86_64, libbpf 1.3.0. Every number below was measured
on that host with the code in this directory; nothing is extrapolated.

## Summary

`cgroup_skb` **does** preserve workload identity — but not through the mechanism
Aegis currently uses, and it produces events in a completely different volume
regime from the existing hooks. It sees real traffic the LSM layer cannot see,
and almost all of that traffic is uninteresting.

---

## 1. Identity (B4) — the decisive result

Every event records two candidate identities:

- `skb_cgid` = `bpf_skb_cgroup_id(skb)` — the socket's cgroup
- `current_cgid` = `bpf_get_current_cgroup_id()` — the running task's cgroup,
  **the one the existing LSM hooks use**

32 MiB bidirectional TCP transfer, client inside the test cgroup, server outside
it. 784 packets:

| | packets | `current_cgid` wrong |
|---|---|---|
| ingress | 620 | **594 (95.8%)** |
| egress | 164 | 17 (10.4%) |

- `skb_cgid`: **1 distinct value** across all 784 packets — always the correct cgroup.
- `current_cgid`: 2 distinct values.

**Reading.** On ingress the hook runs in softirq, where "current" is whatever
task happened to be interrupted. The 4.2% of ingress packets that matched did so
by luck, not by mechanism. Egress is mostly in process context, so it mostly
agrees — but 10.4% is still wrong, which is enough to make it unusable as an
identity source.

So workload identity at this hook is available and reliable, but **only** via
`bpf_skb_cgroup_id()` plus the attach point. Any design that reused the LSM
hooks' identity approach here would silently mis-attribute most ingress traffic.

## 2. Coverage (B5)

Measured per workload:

| workload | cgroup_skb packets | ingress | egress | bytes |
|---|---|---|---|---|
| short TCP connection | 2 | 1 | 1 | 100 |
| refused TCP connect | 2 | 1 | 1 | 100 |
| 50× UDP sendto | 50 | 0 | 50 | 4,600 |
| DNS-like UDP query | 1 | 0 | 1 | 60 |
| 32 MiB TCP download | 784 | 620 | 164 | 33,595,216 |

What `cgroup_skb` sees that the LSM socket hooks structurally cannot:

- **Inbound packets with no syscall behind them.** A SYN to a closed port, an
  RST, a retransmit. `lsm/socket_accept` fires when the application calls
  `accept()`; nothing fires for a connection that is never accepted.
- **Per-packet volume and timing** for an established flow. The LSM hooks see
  `connect()` once; they cannot distinguish a 1 KB request from a 32 MiB
  download.
- **Traffic from a cgroup with no cooperating process context**, for the same
  softirq reason that breaks `current_cgid`.

What it duplicates: the connection-establishment facts — 5-tuple, direction,
family, protocol — which `socket_connect` / `socket_bind` / `socket_sendmsg`
already provide **with full process identity** (pid, ppid, comm, start_time)
that `cgroup_skb` cannot supply at all.

## 3. Event amplification (B12)

This is the finding that constrains everything else.

The existing LSM network hooks emit **only on a deny decision** — all 13 emit
sites sit on deny paths. Allowed traffic produces **zero** events today.

| workload | LSM events (allowed traffic) | cgroup_skb events |
|---|---|---|
| short TCP connection | 0 | 2 |
| 50× UDP sendto | 0 | 50 |
| 32 MiB download | 0 | **784** |

The amplification factor against allowed traffic is not a ratio, it is a change
of kind: from nothing to one event per packet. Even against a hypothetical
"emit on every connection" baseline, the 32 MiB transfer is 784:1.

784 packets for 33.6 MB is ~43 KB/packet, which is loopback GSO — a physical NIC
at 1500 byte MTU would produce roughly **20×** that for the same bytes.

Per-packet export is therefore not operationally realistic at this hook without
counters, sampling, or flow aggregation. The prototype already demonstrates the
counters-only mode (`--emit 0`), which is why the hook cost and the export cost
are measured separately.

## 4. Packet parsing (B6, B15)

The parser refuses to guess. Measured outcomes:

| input | `parse_status` |
|---|---|
| TCP/UDP over IPv4, UDP over IPv6 | `ok` |
| ICMP | `unsup_l4` |
| IPv4 with no L4 bytes present | `truncated` |
| non-IP ethertype | `unsup_l3` |
| IPv6 with an extension header | `v6_ext_chain` |
| IPv4 non-first fragment | `fragment` |

No packet was ever coerced into a shape it did not have; **zero** events carried
fabricated ports.

Safety measures: reads go through `bpf_skb_load_bytes_relative(BPF_HDR_START_NET)`
rather than pointer arithmetic on `skb->data`, so a short packet returns an error
instead of being misread; `ihl` is clamped before being used as an offset;
non-first fragments are rejected before any L4 read, since port-shaped bytes
there are payload.

**Honest gap:** the `fragment` path is implemented and reasoned about but **not
empirically exercised** — raw fragments sent on loopback were reassembled by
netfilter defrag before reaching the hook. Same for VLAN, which is not visible
at this attach point. Those two rows are code review, not measurement.

IPv6 extension chains are deliberately **not** walked. A bounded walk is
possible, but a partial walk that silently stops is how parsers start lying; the
event reports the chain was unresolved and the address pair still stands.

## 5. Attachment and coexistence (B8, B9)

- Attaches only to an explicitly named cgroup. There is no root-attach path.
- `BPF_F_ALLOW_MULTI` via `bpf_prog_attach`, not a `bpf_link`: a link attaches
  exclusively unless the whole chain agrees, and evicting a CNI's cgroup program
  would be far worse than failing to attach.
- Explicit `bpf_prog_detach2` on exit — `prog_attach` outlives the process.
- Capability probe (`--check`) loads without attaching and reports unsupported
  rather than falling back to another hook type.

**Coexistence proven, not assumed.** With an incumbent `cgroup_skb/ingress`
program already attached `multi`, all three programs were live simultaneously:

```
ID      AttachType            AttachFlags  Name
149784  cgroup_inet_ingress   multi        other_ingress
149808  cgroup_inet_ingress   multi        aegis_skb_ingress
149809  cgroup_inet_egress    multi        aegis_skb_egress
```

and after the prototype detached, the incumbent remained.

## 6. Enforcement semantics, if this were ever promoted (B13)

The prototype enforces nothing, but the difference matters for any future
decision:

| | current LSM | hypothetical cgroup_skb drop |
|---|---|---|
| application sees | `connect()` → `-EPERM`, immediately | packet vanishes |
| failure mode | explicit, attributable, logged with process identity | timeout, retry, half-open socket |
| debuggability | the app reports the error it got | looks like network loss |

Aegis's current answer is strictly better as a *security control*: it is
synchronous, it names the syscall, and the application learns why. A packet drop
is indistinguishable from a bad network, which is a poor property for a control
an operator has to reason about during an incident.

## 7. Interaction with the atomic policy system (B14)

None, by construction. The prototype reads no policy map, never resolves
`active_slot`, and holds no reference to a policy generation. It cannot
reintroduce a multi-generation read because it never reads a generation.

Per B7, no socket-direction map (`deny_port`, `deny_ip_port_*`) is reinterpreted
as packet direction. `port_key.direction` means socket-operation semantics
(egress/connect, bind, both); packet ingress/egress is a different concept and is
kept in a separate field in a separate event type.

## 8. Security review (B15)

New attack surface introduced by packet parsing:

| risk | mitigation / status |
|---|---|
| out-of-bounds read | `bpf_skb_load_bytes_relative` + verifier; no `data`/`data_end` arithmetic |
| attacker-controlled `ihl` used as offset | clamped to 5..15 before use |
| payload read as L4 header on fragments | non-first fragments rejected before L4 read |
| IPv6 extension chain confusion | chain not walked; reported unresolved |
| **event amplification as CPU/ringbuf DoS** | **real and unmitigated in the prototype** — see below |
| attach scope | explicit cgroup only; no root attach |

**The amplification risk is the serious one.** A hostile workload that emits
high-PPS traffic directly controls the event rate of a hook attached to its own
cgroup. In the prototype the ring buffer absorbs this until it fills, then drops
(counted). A production design would need rate limiting or aggregation *in the
kernel program*, not in userspace, or the attacker sets the telemetry budget.


## 9. Performance (B11)

### What could and could not be measured

Three attempts at TCP-throughput measurement produced unusable data, and the
reason is worth recording so nobody repeats it: **loopback TCP has a variable
packet count.** GSO coalescing shifts with load, so the hook fires a different
number of times per sample and the measurement is dominated by the kernel's
framing decisions rather than by hook cost. A 15-round run reported
`emit=0` as **29% faster than baseline**, which is impossible and is the clearest
possible sign the method was wrong.

The usable method holds the packet count **exactly fixed**: N `sendto()` calls
produce exactly N egress packets through the hook, every run. What is then
measured is the cost of N hook invocations.

200,000 UDP packets per sample, 9 rounds, conditions interleaved round-robin:

| condition | ns/packet (median) | min | max | vs baseline |
|---|---|---|---|---|
| baseline (nothing attached) | 3074 | 1502 | 5411 | — |
| attached, counters only (`emit=0`) | 3338 | 1460 | 5451 | +264 |
| attached, one event per packet (`emit=1`) | 3552 | 1958 | 5235 | +478 |

Within-condition spread is still 2.7–3.7×, so the unpaired comparison proves
nothing (Mann-Whitney z = +0.04 and +0.57). The conditions were interleaved, so
the **paired** comparison is the valid one:

| comparison | median delta | rounds slower | sign test |
|---|---|---|---|
| `emit=0` − baseline | **+40 ns** | 5/9 | p = 0.50 — **chance** |
| `emit=1` − baseline | **+420 ns** | **8/9** | **p = 0.02 — signal** |
| `emit=1` − `emit=0` | +294 ns | — | — |

### Reading

- **The hook itself is cheap.** Running `cgroup_skb` with counters only is
  *indistinguishable from not running it* on this host — 5 of 9 rounds slower is
  a coin flip. This does not prove the cost is zero; it proves it is below a
  noise floor of roughly ±100 ns/packet.
- **The export is what costs.** One ring-buffer event per packet is ~420 ns/packet
  and is slower in 8 of 9 rounds (p = 0.02). Against a ~3 µs baseline that is
  roughly **14%**, and it is the only effect this measurement can actually resolve.

That split is the architecturally useful part, and it matches the amplification
finding: observation at this hook is affordable, **per-packet export is not**.

### Honest limits

This is one laptop, over loopback, with a 2.7–3.7× spread. These numbers support
the *ordering* and the *hook-vs-export split*, and nothing finer. A production
decision would need a quiet host with a physical NIC, a fixed offered load, and
CPU accounting per softirq — none of which this experiment had. No claim is made
here about throughput or about behaviour at high PPS.

---

## 10. Recommendation

### KEEP AS OPTIONAL OBSERVABILITY

Not "promote to product design", and not "do not add".

**Why not PROMOTE.** The case for promotion would have to be that `cgroup_skb`
gives Aegis something it needs and cannot otherwise get. It does give something
genuinely new — inbound packets with no syscall behind them, and per-flow volume
— but that is *network* telemetry, not the runtime-security signal Aegis is
built around. Everything it says about connection establishment, the LSM hooks
already say, **with full process identity** (pid, ppid, comm, start_time) that
this hook cannot supply at all. And as an enforcement plane it is strictly worse
than what exists: `connect() -> -EPERM` is synchronous, attributable and
debuggable; a vanished packet is indistinguishable from a bad network.

**Why not DO NOT ADD.** It is not pure duplication. A SYN to a closed port, an
RST, a retransmit, traffic from a cgroup with no cooperating process context —
the LSM layer structurally cannot see any of it, because there is no syscall to
hook. For a customer asking "what is this workload actually talking to, and how
much", that gap is real.

**So: optional observability, off by default.** Specifically:

1. **Identity must come from `bpf_skb_cgroup_id()` plus the attach point.**
   Never from `bpf_get_current_cgroup_id()`, which is wrong for 95.8% of ingress
   packets. This is the single most important constraint on any future design.
2. **Counters and flow aggregation in-kernel, not per-packet export.** The
   measurement says the hook is affordable and the export is not, and a hostile
   workload otherwise sets its own telemetry budget by generating packets.
3. **Never the root cgroup**, and always `BPF_F_ALLOW_MULTI`.
4. **No enforcement at this hook**, and no reuse of the socket-direction maps —
   `port_key.direction` means socket-operation semantics and packet direction is
   a different concept.

### What would change this verdict

Promotion would need a concrete customer requirement that the LSM hooks cannot
meet — egress volume accounting per workload, or detection of inbound scanning
that never reaches `accept()`. Absent that, this is a capability worth having
designed and not yet worth having shipped.

## 11. B18 — direct answers

1. **What NEW thing does cgroup_skb give Aegis?** Packets with no syscall behind
   them (SYN to a closed port, RST, retransmits) and per-flow byte/packet volume.
   The LSM layer cannot see these because there is no syscall to hook.
2. **What does it duplicate?** Connection-establishment facts — 5-tuple,
   direction, family, protocol — which the socket hooks already provide, and
   provide *better*, because they carry process identity.
3. **Does it preserve workload identity reliably?** Yes via
   `bpf_skb_cgroup_id()` — one distinct, correct value across all 784 packets.
   **No** via the mechanism the LSM hooks use: `bpf_get_current_cgroup_id()` was
   wrong for **95.8%** of ingress packets.
4. **Does it work on veth/container traffic?** Identity is taken from the cgroup,
   not the interface, so it is namespace- and veth-independent by construction.
   Measured here on loopback and host cgroups; **not** measured on a real
   container or Kubernetes nested cgroup — that remains untested.
5. **Does it see traffic the current LSM layer cannot?** Yes — see (1).
6. **Event amplification factor?** Against today's behaviour it is not a ratio
   but a change of kind: allowed traffic currently produces **zero** events, and
   this produced **784** for one 32 MiB transfer. Loopback GSO flatters that by
   roughly 20× versus a 1500-byte MTU.
7. **Performance cost?** Hook alone: **indistinguishable from zero** on this host
   (+40 ns/packet median, 5/9 rounds, p = 0.50). Per-packet export: **~420
   ns/packet**, 8/9 rounds slower, p = 0.02 — about 14% of a ~3 µs baseline.
   One laptop, loopback, 2.7–3.7× spread; supports the split, nothing finer.
8. **Can it coexist with existing cgroup BPF users?** Yes, proven — incumbent
   plus both prototype programs live simultaneously under `ALLOW_MULTI`, and the
   incumbent survived the prototype's detach.
9. **Would enforcement be better or worse than current LSM enforcement?**
   **Worse.** `-EPERM` is synchronous, names the syscall, and the application
   learns why. A dropped packet looks like network loss — a poor property for a
   control an operator must reason about during an incident.
10. **Should Aegis ship it?** **Not now.** Keep as optional, off-by-default
    observability, gated behind the constraints in §10. Revisit if a concrete
    requirement appears that the LSM hooks cannot meet.
