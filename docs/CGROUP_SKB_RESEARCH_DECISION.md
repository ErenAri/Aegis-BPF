# cgroup_skb research decision

Status: **Keep as experiment only**

Related:
- #323 — architecture experiment
- #329 — raw per-packet audit prototype
- #330 — aggregated flow-observability prototype

## Decision

Aegis will not ship `cgroup_skb` as a production subsystem at this time.

The existing BPF-LSM network/runtime path remains the authoritative enforcement
plane. No XDP or TC work is implied by this research.

## What the experiments proved

### Workload identity is viable

The packet-associated identity path worked across the tested environments:

- five kernels from 5.14 through 6.8: verifier accepted the programs and identity
  checks passed 49/49
- Docker: 14/14 against ground-truth cgroup inode
- kind/Kubernetes: 10/10

The earlier `bpf_get_current_cgroup_id()` ingress failure was avoided by using
`bpf_skb_cgroup_id()`.

Kubernetes qualification: the returned id is the container cgroup, not the pod
slice. Pod attribution therefore requires ancestor-chain resolution; treating a
single cgroup id as a pod id would be incorrect.

### Raw per-packet export is not a product architecture

The hook itself was inexpensive in the controlled measurement, while exporting
one record per packet introduced measurable cost and a large telemetry
amplification relative to Aegis' current deny-path LSM events.

### Aggregation helps benign/repeated traffic, but not the regime we care about most

Measured reduction included:

- repeated connections to one destination: 400x
- UDP burst: 3000x
- Docker/Kubernetes mixed traffic: about 22.8x / 24x
- 400-destination fan-out: 1x
- 400-port scan: 1x

An attacker can deliberately choose a high-cardinality regime, so compression
cannot be treated as a safety property.

### The current LRU design can lose security-relevant observations silently

At 120k destinations, the flow map stabilized near 65,472 entries and about
6 MiB while 45.4% of flows disappeared without a final summary.

The ordinary "map full" signal remained zero because LRU insertion can succeed
by evicting another entry. That means the observer can lose coverage without an
explicit insertion failure.

This is the main blocker for product promotion.

### Correlation has real value, but not enough yet

A useful joined case exists:

- LSM context showed a binary staged under `/tmp`
- the same cgroup then contacted 61 distinct peers

LSM alone did not provide that packet-level fan-out view, while packet data alone
was ambiguous. The combined signal was stronger.

However, the discriminators with the most value also have difficult false-positive
profiles. SYN/RST counts did not separate benign closed-port traffic from the
scan case, and fan-out is common in legitimate workloads such as package
managers, browsers, CI workers, service discovery, and controllers.

## Architectural consequence

Current direction:

```
BPF-LSM
  -> deterministic runtime/network enforcement
  -> process/executable/cgroup identity
  -> synchronous -EPERM semantics
```

Do not add a second packet-policy engine.

Flow telemetry, if revisited, remains runtime observation state and must remain
separate from atomic policy state.

## Revisit criteria

Reconsider `cgroup_skb` only if all of the following become credible:

1. a bounded aggregation design whose loss is directly observable
2. safe behavior under attacker-controlled high cardinality
3. robust pod/workload attribution, including ancestor resolution
4. representative evidence that LSM + flow correlation improves precision enough
   to justify the subsystem's operational complexity
5. acceptable behavior under realistic NIC/veth/high-PPS conditions

## XDP / TC

This research does not justify adding XDP or TC to Aegis.

Revisit XDP only when there is a measured high-PPS or pre-stack filtering problem
that the current architecture cannot address efficiently. XDP should be a response
to a demonstrated dataplane need, not a general expansion target.

## Preservation

The experimental implementations and detailed measurements remain available in
the closed, unmerged PRs #329 and #330. They are intentionally not part of
`main`.
