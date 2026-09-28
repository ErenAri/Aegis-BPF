# EXPERIMENT: workload-attributed flow aggregation over `cgroup_skb` (#323, phase 2)

**Not a feature.** Phase 1 (PR #329, branch `experiment/cgroup-skb-audit` -- not on this branch) showed per-packet export is
not a viable architecture. This phase tests whether in-kernel aggregation fixes
that. The verdict is **KEEP AS EXPERIMENT ONLY** — see `FINDINGS.md`.

Nothing here is wired into the agent, the CMake build, any workflow, the policy
grammar, or the production event schema. `rm -rf` this directory and the product
is unchanged.

## Files

| File | Purpose |
|---|---|
| `aegis_flow.bpf.c` | aggregating `cgroup_skb/{ingress,egress}`, audit-only |
| `flow_probe.c` | loader + periodic map walk + idle-timeout summary export |
| `container_test.sh` | §6 Docker identity vs ground-truth cgroup inode |
| `k8s_test.sh` | §7 Kubernetes pod/container identity (kind) |
| `cardinality_test.sh` | §8/§11 flow growth + 5-tuple shadow comparison |
| `exhaust_test.sh` | §22 map exhaustion and eviction visibility |
| `correlate_test.sh` | §15/§16 LSM exec + flow join on cgroup id |
| `coexist_retest.sh` | §23 coexistence with an incumbent cgroup program |
| `kernel_matrix.sh` | §5/§25 identity + verifier on 5.14 → 6.8 |

```sh
make
sudo ./flow_probe --check            # capability probe, attaches nothing
sudo ./container_test.sh             # needs docker
sudo ./kernel_matrix.sh              # needs the cached kernels from the main matrix
```

## Safety properties

- **Enforces nothing.** Zero `return 0` sites in the BPF program — greppable on
  purpose. One `return 1`, reached on every path including every error path.
- **Never the root cgroup.** The loader requires an explicit cgroup path.
- **`BPF_F_ALLOW_MULTI`** so it cannot evict a CNI's or systemd's program;
  explicit `bpf_prog_detach2` on exit, since `prog_attach` outlives the process.
- **Headers only.** No payload, no DPI, no connection tracking, no TCP state.
- **No policy interaction.** Reads no policy map, never resolves `active_slot`,
  holds no generation reference — it cannot affect the atomic-swap machinery.
  Flow state is runtime telemetry, not policy, and is not persisted.
- **No second policy engine.** No deny grammar, no flow deny maps, no packet
  direction policy language. Per the earlier review, `port_key.direction` means
  socket-operation semantics and is *not* reinterpreted as packet direction.
- **Bounded memory** (LRU, 65,536 entries, ~6 MiB) with **eviction loss reported**
  rather than silent — see `FINDINGS.md` §K.

## Metrics that would belong in Prometheus (§21)

Low-cardinality aggregates only — active flows, map occupancy, summaries
exported, evicted/lost flows, parse failures, unsupported-L4 count. **Never
per-IP or per-port labels**, which would move the cardinality problem from the
BPF map into the metrics store.
