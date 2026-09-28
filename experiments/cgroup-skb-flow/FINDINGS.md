# Flow aggregation over `cgroup_skb` — findings (#323, phase 2)

Phase 1 (PR #329, branch `experiment/cgroup-skb-audit` -- not merged, so not present on this branch) established that per-packet export
is not a viable architecture. This phase tests the follow-on hypothesis:

> Aegis may gain useful workload-aware network behaviour signals if `cgroup_skb`
> aggregates in-kernel and exports low-rate flow summaries instead of one event
> per packet.

Host: `7.0.0-28-generic` x86_64, libbpf 1.3.0, Docker 
+ kind v0.23.0 / Kubernetes v1.30.0. Kernel matrix in virtme-ng VMs.

**Verdict: KEEP AS EXPERIMENT ONLY.** The mechanism works better than expected;
the product case does not hold up. Reasoning in §M.

---

## A. Starting state

`main` at `f4edb11`, containing #318 (operator grammar), #324 (atomic policy
generations) and #328 (e2e layout assertion). No `cgroup_skb` code in `main` —
phase 1 stayed fully isolated, and so does this.

What the existing BPF-LSM network hooks already know, per hook
(`socket_connect`, `socket_bind`, `socket_listen`, `socket_accept`,
`socket_sendmsg`, `socket_recvmsg`): pid, ppid, start_time, parent_start_time,
cgid, comm, family, protocol, local/remote port, remote IPv4/IPv6, action,
rule_type. **All 13 network emit sites sit on deny paths**, so allowed traffic
produces zero network events today. `EVENT_EXEC`, by contrast, is emitted
unconditionally — which is what makes correlation possible at all.

## B. Aggregation architecture

`flow_key` = **cgroup_id + peer address + peer port + direction + family +
protocol**. Deliberately **no local port**, and that choice is measured, not
asserted (§E): a client's source port is ephemeral, so including it makes every
connection a new flow and the map grows with connection count rather than with
behaviour.

`flow_value` = packets, bytes, syn_count, rst_count, fin_count, first_seen_ns,
last_seen_ns, parse_errors.

Two fields were **removed** from the suggested starting schema after challenge:

- **no `ack` counter** — ACK is set on essentially every packet of an
  established connection, so it would restate `packets` in a second field and
  invite someone to read meaning into it.
- **nothing named `retransmission`** — without sequence-state tracking the
  program cannot prove a retransmit. The fields say what they count.

Map: `LRU_HASH`, 65,536 entries, bounded by construction. Export: **userspace
periodic walk** (option A of the four). BPF timers would be tidier but need
5.15+, and Aegis supports 5.14, so using them would trade real kernel coverage
for elegance. Expiry: idle timeout → emit final summary → delete. No TCP state
machine; this is not conntrack.

Enforces nothing: **zero `return 0` sites** in the BPF program, checkable by grep.

## C. Identity results

### Host cgroup — 5 kernels

| kernel | verifier | identity | ingress | egress |
|---|---|---|---|---|
| 5.14.21 | rc=0 | 49/49 | 24/24 | 25/25 |
| 5.15.0-131 | rc=0 | 49/49 | 24/24 | 25/25 |
| 6.1.0-50 | rc=0 | 49/49 | 24/24 | 25/25 |
| 6.5.0-060500 | rc=0 | 49/49 | 24/24 | 25/25 |
| 6.8.0-71 | rc=0 | 49/49 | 24/24 | 25/25 |

Verifier acceptance was not treated as proof: each VM attached to a real cgroup,
drove traffic, and compared the observed id against that cgroup's inode.

### Docker container — MEASURED

Ground truth = container cgroup inode read from the host, never IP.

```
cgroup: /sys/fs/cgroup/system.slice/docker-<id>.scope
TRUE cgid: 75569
observed : 75569  in 14/14 summaries   (ingress 7/7, egress 7/7)
```

Phase 1's 95.8% ingress failure does not recur, because identity now comes from
`bpf_skb_cgroup_id()` rather than the current task.

### Kubernetes (kind) — MEASURED, with an important qualification

```
pod slice        81399
  container      81573   <- observed cgid, 10/10 summaries, 1 distinct value
  pause/sandbox  81486
```

`bpf_skb_cgroup_id()` returns the **container** cgroup, not the pod cgroup. It is
stable and correct — but **pod-level attribution requires resolving the ancestor
chain** (`bpf_skb_ancestor_cgroup_id()` at the right level, or a userspace
container→pod map). Any product design that assumed "cgroup id == pod" would be
wrong in Kubernetes.

Traffic covered: pod → DNS via ClusterIP (kube-proxy), pod → external, pod →
ClusterIP:443, across veth. **Not** covered: multi-node, overlay/CNI other than
kind's default, service mesh. Those remain untested, not inferred.

## D. Coverage — what LSM misses

Unchanged from phase 1 and still the honest case *for* the hook: packets with no
syscall behind them (SYN to a closed port, RST, repeated SYN), and per-flow
volume. The LSM layer structurally cannot see these because there is no syscall
to hook, and it emits nothing at all for allowed traffic.

## E. Cardinality — and the finding that undermines the hypothesis

Same packet count (800) across four traffic shapes, with a shadow map recording
what a 5-tuple key would have cost:

| workload | packets | flow keys | reduction | 5-tuple keys |
|---|---|---|---|---|
| 400 connections → **one** destination | 800 | **2** | **400×** | 800 |
| UDP burst | 3000 | **1** | **3000×** | 1 |
| **400-destination fan-out** | 800 | **800** | **1×** | 800 |
| **400-port scan** | 800 | **800** | **1×** | 800 |
| long-lived TCP | 2 | 2 | 1× | 2 |

Dropping the local port is vindicated — 400× better than a 5-tuple key for
repeated connections, and never worse.

**But aggregation gives no reduction for fan-out or port scanning**, which are
precisely the behaviours the signals in §14 are meant to detect. The reduction
factor is workload-dependent and **attacker-controlled**: a workload that wants
to defeat aggregation simply varies its destination.

## F. Event reduction

| scenario | packets | summaries | reduction |
|---|---|---|---|
| Docker container, mixed traffic | 319 | 14 | **22.8×** |
| Kubernetes pod, mixed traffic | 236–241 | 10 | **~24×** |
| benign repeated connections | 172 | 4 | **43×** |
| UDP burst | 3000 | 1 | **3000×** |
| **fan-out / scan** | 800 | 800 | **1×** |
| 120k-destination flood | 120,000 | 65,472 | 1.8× |

Realistic mixed workloads land around **20–40×**. That is real, and it is not the
1000× the framing in §11 invited.

## G. Performance

Phase 1 established the per-packet split on this host: the hook alone is
indistinguishable from not running it (+40 ns/pkt, 5/9 rounds, sign test
p = 0.50), while per-packet ring-buffer export costs ~420 ns/pkt (8/9 rounds,
p = 0.02). Aggregation replaces that export with a map update, so it sits on the
cheap side of that split by construction.

**Not measured here, and stated as such:** a clean aggregation-vs-raw per-packet
cost comparison on this host, high-PPS CPU/softirq accounting, and physical-NIC
behaviour. Phase 1 burned three attempts learning that loopback TCP has a
variable packet count and cannot support these numbers; the Docker and
Kubernetes veth paths used here have a 1500-byte MTU, which is why the packet
counts in §C/§F are representative even though the CPU numbers are absent.

The one pressure test run was the 120k-destination flood (§K), which the
architecture survived with bounded memory.

## H. Correlation experiment

Same image, same network, two workloads. Join on cgroup id, never IP.

| | BENIGN | SCAN |
|---|---|---|
| LSM exec events | 86 (`sh`:42) | 150 (`sh`:74) |
| LSM sample argv | `sh -c`, `seq 1`, `nc -z` | `sh -c`, **`cp /bin/busybox`** |
| distinct peer IPs | **1** | **61** |
| distinct endpoints | 1 | 70 |
| syn / rst | 40 / 40 | 70 / 70 |
| flow summaries | 2 | 140 |

- **LSM alone: incomplete.** Both are `sh` running `nc`. The exec stream cannot
  distinguish 40 attempts at one host from 70 attempts at 61 hosts, and with no
  policy denying anything it emits **zero** network events.
- **Flow alone: ambiguous.** "This cgroup contacted 61 peers" also describes a
  package manager, a service-discovery client or a CI worker.
- **Combined: materially better.** A binary was staged into `/tmp` and executed,
  *and* that cgroup then contacted 61 distinct peers. Neither half says that.

So the case the brief asked for does exist.

**False-positive finding (§17):** the benign workload is *also* SYN-heavy and
RST-heavy (40/40), because connecting to a closed port generates an RST.
**RST-heavy and SYN-heavy are confounded signals; only fan-out separated the two
scenarios.** A crude "RST count high" rule would have fired on the benign case.

## I. Coexistence

Retested with aggregation and maps present:

```
incumbent only            other_ing
prototype attached        other_ing + aegis_flow_ingress + aegis_flow_egress   (3)
after prototype detach    other_ing                                            (survived)
prototype maps at exit    0 remaining
```

`BPF_F_ALLOW_MULTI`, explicit `bpf_prog_detach2`, no root-cgroup attach path.

## J. Kernel compatibility

`cgroup_skb`, `LRU_HASH`, `bpf_skb_cgroup_id()`, `bpf_skb_load_bytes_relative()`
and `PERCPU_ARRAY` are all accepted on **5.14 through 6.8** — the full supported
range. **No feature here would raise Aegis's minimum kernel**, which is precisely
why the export path is a userspace map walk rather than a BPF timer.

Incidental finding: these virtme-ng kernels fail to boot with `--memory 2G` and
need 4G. That is a harness fact, not a product one.

## K. Security / DoS analysis

| risk | measured behaviour |
|---|---|
| flow-map exhaustion | 120,000 distinct destinations → peak occupancy capped at **65,472**; `map-full = 0` because LRU evicts rather than failing |
| memory growth | bounded at **~6 MiB** for 65,536 entries |
| **silent observation loss** | **54,528 flows (45.4%) discarded with no summary ever emitted** |
| attacker-controlled cardinality | confirmed: destination variation drives keys 1:1 with packets |
| out-of-bounds read | `bpf_skb_load_bytes_relative`; `ihl` clamped; no `data`/`data_end` arithmetic |
| payload read as L4 on fragments | non-first fragments rejected before any L4 read |

**The eviction finding is a flaw this experiment found in its own design.** §8
requires that entries are not dropped without metrics, and BPF's LRU hash has no
eviction callback — an insert into a full LRU *succeeds* by discarding somebody
else, so the obvious counter stays zero no matter how much is thrown away. The
probe now derives and reports it (`evicted, inferred` + `observation loss %`). A
telemetry layer that silently discards what it was asked to observe is worse than
one that admits it cannot keep up.

## L. Remaining limitations

Untested, and labelled as such rather than argued from code:

- multi-node Kubernetes, non-kind CNIs, overlay networks, service mesh
- fragments and VLAN — loopback reassembles before the hook; VLAN is not visible
  at this attach point
- aggregation-vs-raw CPU cost on this host, high-PPS softirq accounting,
  physical NIC
- pod→pod and host→pod paths (only pod→DNS/external/ClusterIP were driven)
- IPv6 beyond basic UDP
- long-run stability; the longest run here was 60 seconds

## M. Final recommendation

### KEEP AS EXPERIMENT ONLY

The mechanism works, and works better than phase 1 suggested: identity is
correct in real Docker and real Kubernetes across five kernels, memory is
bounded, coexistence holds, nothing is raised in the support matrix, and the
LSM+flow join produces a signal neither source gives alone.

It is not promoted, for three reasons that the measurements — not taste — decide:

1. **Aggregation does not reduce the cases it exists for.** 400× on repeated
   traffic and **1×** on fan-out and port scanning. The workloads worth watching
   are exactly the ones that defeat the compression, and an attacker chooses
   which regime to be in.
2. **The signal that discriminated is the one with the worst false-positive
   profile.** Fan-out separated benign from scanning here, and fan-out is also
   what package managers, service discovery, CI workers and browsers do. The
   cheaper signals (SYN/RST counts) were confounded in the benign case.
   Shipping this means shipping a fan-out heuristic, and §17's list is the
   reason that is not ready.
3. **45.4% silent observation loss under pressure.** Bounded memory was achieved
   by throwing away nearly half the flows, invisibly until this experiment added
   a derived counter. A security subsystem whose coverage degrades silently
   under attacker-controlled load is not one to enable by default.

None of these is fatal to the idea; all three are unresolved. Promotion should
wait for: a concrete customer requirement naming a signal the LSM hooks cannot
meet, a false-positive study against the §17 workload list, and an eviction
strategy whose loss is visible and bounded by policy rather than by luck.

## §28 — direct answers

1. **`bpf_skb_cgroup_id()` correct in Docker/containerd?** Yes — 14/14
   summaries matched the container cgroup inode, ingress 7/7 and egress 7/7.
2. **Correct in Kubernetes/veth?** Yes, with a qualification: it returns the
   **container** cgroup (81573), not the **pod** slice (81399). Stable, 10/10.
   Pod attribution needs the ancestor chain. Single-node kind only.
3. **How many raw packets per summary?** 20–40 for realistic mixed workloads;
   3000 for a UDP burst; **1** for fan-out and port scanning.
4. **Event reduction factor?** **22.8×** (Docker), **~24×** (Kubernetes), 43×
   (repeated connections), 3000× (UDP burst), **1× for scans**. Workload-dependent
   and attacker-controlled — a single number would be misleading.
5. **Aggregation overhead per packet?** Not measured cleanly here. Phase 1
   bounds the components: hook ~0 (p = 0.50), per-packet export ~420 ns
   (p = 0.02). Aggregation replaces the export with a map update, so it is on the
   cheap side by construction — but that is reasoning, not a measurement, and is
   labelled as such.
6. **What happens at high PPS?** Tested by cardinality rather than rate: 120,000
   destinations → occupancy capped at 65,472, memory ~6 MiB, no insert failures,
   **45.4% of flows silently evicted**. CPU/softirq at high PPS is untested.
7. **Peak flow-map cardinality?** 65,472 of a 65,536 bound — the LRU held.
8. **Is memory bounded?** Yes, ~6 MiB, by construction. Bounded *coverage* is
   the thing that is not guaranteed.
9. **Does coexistence still work?** Yes — 3 programs simultaneously, incumbent
   survived detach, prototype maps freed.
10. **What new signal does LSM + flow produce?** Executable-attributed network
    behaviour: *a binary staged into `/tmp` then contacted 61 distinct peers*.
    LSM has the executable and no network view for allowed traffic; flow has the
    network view and no executable.
11. **Is it useful enough to justify the complexity?** **Not yet.** The signal is
    real but rests on fan-out, which has the worst false-positive profile of the
    candidates and is also the case where aggregation stops working.
12. **Should Aegis ship it as an optional observability subsystem?** **No, not
    yet.** Keep as an experiment. The blockers are specific and testable, not
    architectural.
