# BPF Security Agent Benchmark Comparison

**Date:** 2026-05-15
**Kernel:** 6.17.0-20-generic (Ubuntu HWE)
**Hardware:** x86_64
**Workload:** synthetic mix of exec (`/bin/true`), file I/O (create+delete), and `connect()` syscalls

## Methodology

A controlled workload generator (`bench/workload.sh`) runs N iterations across
M parallel workers.  Each iteration performs:
- 1x exec storm (`/bin/true`)
- 1x file storm (create + delete temp files)
- 0.1x connect storm (TCP connect to localhost:1, ECONNREFUSED)

Total ops per run = workers * (iterations + iterations + iterations/10).

Each agent is started, given time to initialize, then the workload runs.
Wall-clock time, peak RSS, and average CPU% are collected.

## Results (500 iterations x 4 workers = 4,200 ops)

| Agent          | Version | Time (ms) | Overhead | Peak RSS (KB) | Avg CPU% |
|----------------|---------|-----------|----------|---------------|----------|
| **Baseline**   | —       | 448       | 0%       | —             | —        |
| **Tetragon**   | 1.6.0   | 1,085     | 142%     | 65,452        | 52.1%    |
| **Falco**      | 0.43.1  | 682       | 52%      | 248,960       | 36.7%    |
| **Tracee**     | 0.24.1  | 634       | 41%      | 156,500       | 61.5%    |

## Results (2,000 iterations x 4 workers = 16,800 ops)

| Agent          | Version | Time (ms) | Overhead | Peak RSS (KB) | Avg CPU% |
|----------------|---------|-----------|----------|---------------|----------|
| **Baseline**   | —       | 1,615     | 0%       | —             | —        |
| **Tetragon**   | 1.6.0   | 1,792     | 10%      | 162,440       | 63.5%    |
| **Falco**      | 0.43.1  | 2,057     | 27%      | 249,692       | 36.2%    |
| **Tracee**     | 0.24.1  | 2,324     | 43%      | 155,736       | 61.0%    |

The 2,000-iteration run is more representative: longer workload amortizes
agent initialization overhead and reduces noise.

## Analysis

### Wall-clock overhead (2,000 iter)
- **Tetragon (10%):** Lowest overhead at scale. Its ringbuf-based event
  pipeline is efficient for high-throughput exec/file workloads. The large
  overhead at 500 iterations (142%) suggests significant per-run startup cost
  that amortizes at higher load.
- **Falco (27%):** Middle ground. Uses modern eBPF driver with efficient
  kernel-side filtering. Startup cost is lower than Tetragon.
- **Tracee (43%):** Highest overhead. Tracee's broader default event scope
  and Go-based userspace processing add latency.

### Memory footprint
- **Tetragon:** 64-162 MB — grows with event volume. Go runtime + gRPC
  server contribute to baseline.
- **Falco:** ~249 MB — heaviest, but stable (doesn't grow much with load).
  Includes rule engine, plugin framework, and container runtime metadata.
- **Tracee:** ~156 MB — moderate. Static binary with embedded eBPF objects.

### CPU utilization
- **Falco (36%):** Most CPU-efficient — offloads filtering to kernel-side
  eBPF programs, reducing userspace processing.
- **Tetragon (52-63%):** Moderate — gRPC export and policy evaluation in
  userspace.
- **Tracee (61%):** Highest — Go runtime overhead and broader event
  collection scope.

## aegis-next prototype status

The aegis-next prototype (BPF arena + provenance graph) was designed for
kernels 6.9-6.12 and cannot load on kernel 6.17 due to two API changes:

1. **`bpf_iter_task_new` return type:** Changed from `void` to `int` in
   kernel 6.12+. The prototype declares the old signature.
2. **`bpf_arena_alloc_pages` became sleepable:** In kernel 6.17, this kfunc
   requires a sleepable program context. The prototype calls it from
   non-sleepable LSM hooks via lazy initialization.

Both are fixable with proper kernel version detection (CO-RE or build-time
guards), tracked as a follow-up item for the prototype graduation path.

### Architectural advantage (projected)

The arena-mmap design eliminates per-event copy-out overhead. Where Tetragon,
Falco, and Tracee each copy every event through ringbuf/perfbuf to userspace,
aegis-next writes directly to mmapped shared memory. For exec-heavy workloads,
this should yield:
- Near-zero userspace read latency (no syscall per event)
- Constant memory overhead (fixed 64 MiB arena vs. growing buffers)
- Lower CPU (no ringbuf wakeup/poll overhead)

## Reproducing

```bash
# Install agents (Tetragon, Falco, Tracee) — see prototype/aegis-next/bench/
# Run comparison:
sudo bash prototype/aegis-next/bench/compare.sh 2000 4
```

Raw results are saved to `results/bench-YYYYMMDD-HHMMSS/summary.json`.
