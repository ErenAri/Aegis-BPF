# EXPERIMENT: `cgroup_skb` audit-only observation (#323)

**This is not a feature.** It is a hypothesis being tested, and the honest
outcome may be "do not build this". Nothing here is wired into the agent, the
build, the policy grammar, or any production event schema. `rm -rf` this
directory and the product is unchanged.

## Hypothesis under test

> `cgroup_skb` may give Aegis packet-level ingress/egress visibility while
> preserving workload/cgroup identity better than XDP/TC.

## What is here

| File | Purpose |
|---|---|
| `aegis_cgroup_skb.bpf.c` | the prototype: `cgroup_skb/ingress` + `/egress`, audit-only |
| `skb_probe.c` | loader/harness: attaches to ONE named cgroup, measures, detaches |
| `run_experiment.sh` | short workloads (connect, refused, UDP, DNS) |
| `bulk_test.sh` | bidirectional bulk transfer — the identity-decisive case |
| `perf_test.sh` | B11/B12: hook cost vs observability cost, interleaved |
| `coexist_test.sh` | B9: composes with an already-attached cgroup program |
| `parse_test.sh` | B6/B15: adversarial packets must report, not guess |

Build and run (root, BPF-LSM kernel):

```sh
make
sudo ./skb_probe --check          # capability probe, attaches nothing
sudo ./bulk_test.sh 1
sudo ./parse_test.sh
```

## Safety properties

- **Enforces nothing.** Both programs `return 1` on every path including every
  error path. There is no code here that can return 0.
- **Never attaches to the root cgroup.** The loader requires an explicit cgroup
  path. A root attach would observe every packet on the machine, which is not
  something an experiment should be able to do by accident.
- **`BPF_F_ALLOW_MULTI`.** Attaching exclusively could evict a CNI's or
  systemd's cgroup program; failing to attach is strictly better than that.
- **Explicit detach.** `prog_attach` outlives the process, unlike a `bpf_link`,
  so the harness detaches on exit rather than relying on fd lifetime.
- **No payload, no DPI, no connection tracking.** Headers only, and only the
  fields the architectural question needs.
- **Separate ring buffer and event struct.** The production `events` ringbuf and
  `struct event` union are untouched, so no stable consumer can come to depend
  on prototype data.
- **Consumes no policy state.** It reads no policy map and no `active_slot`, so
  it cannot interact with the atomic-generation machinery at all.

## Why both cgroup ids are recorded

Every event carries two candidate identities:

- `skb_cgid` — `bpf_skb_cgroup_id(skb)`, the socket's cgroup
- `current_cgid` — `bpf_get_current_cgroup_id()`, the running task's cgroup

The existing LSM hooks use the second. Recording both is the experiment:
it measures whether the identity mechanism Aegis already relies on survives a
move into packet context, rather than assuming either answer.

## Results

See `FINDINGS.md`.
