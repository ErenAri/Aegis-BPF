# Backpressure saturation (laptop, kernel 6.17)

Proves the property that separates an *enforcement* agent from a *telemetry* agent:
**the enforcement decision stays synchronous and correct when the telemetry channel is
saturated.** The design thesis is *losing telemetry is acceptable; losing a decision is
not* — this battery makes AegisBPF lose telemetry on purpose and asserts it never loses a
decision.

## Why the decision must be decoupled

The deny is a `-EPERM` returned from an in-kernel LSM hook (`lsm/file_open` /
`lsm/inode_permission`). Event delivery to userspace is a *separate* concern: the hook
reserves a ring-buffer slot and, if the reserve fails, increments a drop counter and
**still returns `-EPERM`**. So a full/overflowing buffer must never turn a deny into an
allow. This run demonstrates that empirically under sustained loss.

## Mechanism — why we freeze the consumer

Under a pure high-rate firehose (48 workers, ~35K denials/s) the userspace consumer keeps
up and **nothing drops** — a good robustness signal, but it proves nothing about
decoupling because no telemetry is actually lost. So the harness induces the worst-case
operational stall directly: it **`SIGSTOP`s the agent's userspace**. The BPF programs
remain attached in-kernel and keep returning `-EPERM`, but the ring buffers stop draining,
overflow, and `aegisbpf_ringbuf_drops_total` climbs. A separate canary process reads the
denied inode throughout and must be denied every time. `aegisbpf metrics` reads the pinned
maps directly, so drop counters stay observable while the daemon is frozen.

This models a real failure mode: an agent whose userspace is overwhelmed, descheduled, or
blocked on I/O. `SIGSTOP` is the extreme (a *fully* stalled consumer) and guarantees
sustained drops.

## Result (`result.json`, `run.log`)

| phase | telemetry drops (delta) | canary | in-kernel enforcement |
|---|---|---|---|
| **A — consumer live** | 0 new | 0 miss / 200 | `blocks_total` climbing |
| **B — consumer frozen (6 s)** | **+228,442** | **0 miss / 1,200** | `blocks_total` climbing 1.22M → 1.48M *while frozen* |
| **C — resumed (`SIGCONT`)** | (drains) | 0 miss / 200 | daemon alive, recovered |

- **Saturation achieved:** 228,442 events dropped while frozen (~38K/s) — far past the
  `MIN_DROPS=1000` teeth gate. Without real drops the run reports INCONCLUSIVE, not pass.
- **Zero decisions lost:** 0 canary misses across **1,600** reads spanning all three
  phases. Every read of the denied inode was blocked while its telemetry was being dropped.
- **Enforcement kept running while userspace was frozen:** `blocks_total` advanced by
  ~264K *during* the freeze — the deny path is in-kernel and does not depend on the
  consumer.
- **Clean recovery:** the agent survived `SIGCONT` and resumed draining; metrics were
  readable throughout.

### Note on the counters

`aegisbpf_ringbuf_drops_total` and `aegisbpf_blocks_total` are **pinned, cumulative**
BPF-map counters that survive daemon restarts, so absolute values carry residue from
earlier runs (hence `drops_baseline` ≈ 180K here). The harness asserts the **per-run
delta** (`drops_delta_frozen`), the same methodology the soak uses for decisions.

## Reproduce

```bash
# Build the BPF object from source against this kernel first (SKIP_BPF_BUILD=OFF), then:
sudo BIN=./build/aegisbpf \
  OUT_JSON=evidence/backpressure-saturation-laptop/result.json \
  bash scripts/backpressure_saturation.sh
# PASS iff: drops delta >= MIN_DROPS (saturation real) AND 0 canary misses AND agent
# survives SIGCONT. Tunables: WORKERS, FREEZE_SECONDS, RINGBUF_BYTES, MIN_DROPS,
# CANARY_READS_PER_SAMPLE.
```

## Caveats

- **One kernel (6.17), one host.** Buffer-drain behaviour is timing- and core-count
  dependent; cross-kernel / cross-host confirmation needs the matrix.
- `SIGSTOP` is a *fully* stalled consumer — the extreme end of backpressure. A partially
  slow consumer is a milder case of the same mechanism and is bounded by it.
- Scope is the **file** deny path. The network hooks use their own ring buffer
  (`aegisbpf_net_ringbuf_drops_total`) and would need a sibling run to make the same claim.
