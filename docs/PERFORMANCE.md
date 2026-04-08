# AegisBPF Performance Profile

Version: 2.0 (2026-04-08) — superseded the 2026-02-09 "expected ranges"
v1.0 with Phase 1-2 measurements. v1.0 numbers were pre-perf-gate
guesses and did not match reality on the reference host; the authoritative
measurement is now `docs/PERF_BASELINE.md` + the artifacts under
`/tmp/aegis_perf_verify/` (2026-04-08 run).

This document provides guidance on AegisBPF's runtime resource consumption,
measured overhead, and tuning parameters.

## CPU overhead per hook

AegisBPF attaches BPF programs to kernel LSM hooks. Each hooked syscall
incurs additional latency from the BPF program execution.

### Measured overhead (reference host, 2026-04-08)

Host: Linux 6.17.0-19-generic, i9-13900H, CPU pinned bench (CPU 0) /
agent (CPU 1), 200 k opens / 50 k connects, 5 repeats, audit mode.

| Syscall | Baseline p50 | With-agent p50 | Baseline p95 | With-agent p95 | Delta (µs/op) | p95 overhead |
|---------|-------------:|---------------:|-------------:|---------------:|--------------:|-------------:|
| `open` / `read` / `close` on /etc/hosts | 1.22 µs | 1.25 µs | 1.25 µs | 1.29 µs | +0.03 | +3.2% |
| `connect` to 127.0.0.1:9/udp | 2.11 µs | 2.19 µs | 4.26 µs | 4.44 µs | +0.09 | +4.2% |

Both deltas are well under the 10% perf-gate SLO.

**Methodology caveat:** `scripts/perf_open_bench.sh` runs the agent in
`--audit` mode, and the agent logs `"Audit mode optimization: skipping
file hooks (no deny rules loaded)"`. The delta measured above is
therefore **not** a pure LSM-hook cost — it is the residual cost of the
agent process being alive (execve tracepoint, process-tree tracking,
ringbuf management, cache eviction). The numbers are still a valid
user-visible "is the agent free to run?" answer, but if you want to
isolate the LSM hook itself, load at least one deny rule first and
re-run.

The per-hook microbenches (`build/aegisbpf_bench`) isolate the hot-path
kernels used by the hooks:

| Kernel used by | Microbench | Time |
|---|---|---|
| all file/net deny hooks | `BM_DenyEntriesLookup/100` | 3.90 ns |
| all file/net deny hooks | `BM_DenyEntriesLookup/10000` | 3.93 ns (flat) |
| deny policy apply | `BM_DenyEntriesInsert/100` | ~26 ns/op |
| deny policy apply | `BM_DenyEntriesInsert/10000` | ~46 ns/op |
| path-key hash | `BM_FillPathKeyShort` | 13.8 ns |
| inode hash | `BM_InodeIdHash` | 0.10 ns |
| port hash | `BM_PortKeyHash` | 0.09 ns |
| exec integrity | `BM_Sha256Short` | 710 ns |

### Factors that do NOT affect per-syscall overhead

- **Number of deny rules:** BPF map lookups are O(1) for hash maps and
  O(prefix-length) for LPM tries.  Adding more rules does not increase lookup
  time (until hash collision rates rise at very high entry counts).
- **Ring buffer size:** The ring buffer is written asynchronously.  Buffer size
  affects memory consumption, not per-syscall latency.

### Factors that DO affect per-syscall overhead

- **BPF JIT availability:** Kernels without JIT (`/proc/sys/net/core/bpf_jit_enable=0`)
  run BPF programs in an interpreter, which is significantly slower.
- **Kernel version:** Newer kernels have faster BPF infrastructure.
- **CPU architecture:** x86_64 with JIT is the primary benchmark target.

## Memory consumption

### Formula

```
total_memory ≈ bpf_maps + ring_buffer + per_cpu_arrays + userspace_heap
```

### BPF map memory

The authoritative source for map sizing is `bpf/aegis_common.h`. The
values below are pulled from that header; if they ever drift again,
`bpf/aegis_common.h` wins and this table is a bug.

| Map | Key+Value raw | max_entries | Source constant |
|-----|---|---|---|
| `process_tree` | 4 + 48 B | 65536 | `MAX_PROCESS_TREE_ENTRIES` |
| `allow_cgroup` | 8 + 1 B | 1024 | `MAX_ALLOW_CGROUP_ENTRIES` |
| `survival_allowlist` | 16 + 1 B | 256 | `MAX_SURVIVAL_ENTRIES` |
| `deny_inode` | 16 + 1 B | 65536 | `MAX_DENY_INODE_ENTRIES` |
| `deny_path` | 256 + 1 B | **16384** | `MAX_DENY_PATH_ENTRIES` |
| `deny_ipv4` | 4 + 1 B | **65536** | `MAX_DENY_IPV4_ENTRIES` |
| `deny_ipv6` | 16 + 1 B | 65536 | `MAX_DENY_IPV6_ENTRIES` |
| `deny_port` | 4 + 1 B | 4096 | `MAX_DENY_PORT_ENTRIES` |
| `deny_ip_port_v4` | 8 + 1 B | 4096 | `MAX_DENY_IP_PORT_V4_ENTRIES` |
| `deny_ip_port_v6` | 20 + 1 B | 4096 | `MAX_DENY_IP_PORT_V6_ENTRIES` |
| `deny_cidr_v4` (LPM) | 8 + 1 B | 16384 | `MAX_DENY_CIDR_V4_ENTRIES` |
| `deny_cidr_v6` (LPM) | 20 + 1 B | 16384 | `MAX_DENY_CIDR_V6_ENTRIES` |
| `deny_cgroup_inode` | 16 + 17 B | 32768 | `MAX_DENY_CGROUP_INODE_ENTRIES` |
| `deny_cgroup_ipv4` | 12 + 1 B | 16384 | `MAX_DENY_CGROUP_IPV4_ENTRIES` |
| `deny_cgroup_port` | 12 + 1 B | 4096 | `MAX_DENY_CGROUP_PORT_ENTRIES` |
| `dead_processes` | 16 + 72 B | 4096 | `MAX_DEAD_PROCESS_ENTRIES` |
| `enforce_signal_state` | per-CPU | 65536 | `MAX_ENFORCE_SIGNAL_ENTRIES` |
| `trusted_exec_hash` | 32 + 1 B | 16384 | `MAX_TRUSTED_EXEC_ENTRIES` |
| `events` (ringbuf) | — | 16 MB | `RINGBUF_SIZE_BYTES` |
| `priority_events` (ringbuf) | — | 4 MB | `PRIORITY_RINGBUF_SIZE` |
| `diagnostics` (ringbuf) | — | 1 MB | `DIAGNOSTICS_RINGBUF_SIZE` |
| `hook_latency` | per-CPU | 16 | `HOOK_LATENCY_MAX` |
| `*_stats` (per-map) | per-CPU | matches map | various |

BPF hash map overhead is approximately 2–4× the raw key+value size due
to internal hash table structure, per-element metadata, and alignment.
Per-CPU arrays multiply by the CPU count at load time.

### Measured memory footprint (reference host, 2026-04-08)

On Linux 6.17 / i9-13900H (20 CPU) the agent running in `--audit` mode
with an empty policy shows:

| Metric | Value | How measured |
|---|---|---|
| Userspace VmRSS | ~7.4 MB | `/proc/PID/status` after 8 s warmup |
| Userspace VmPeak | ~19.7 MB | same |
| BPF map memlock total | ~100 MB | `bpftool map show` summed over all pinned + non-pinned maps |

**The BPF-map memlock is dominated by:**
- 16 MB `events` ringbuf
- 4 MB `priority_events` ringbuf
- 1 MB `diagnostics` ringbuf
- Per-CPU stats arrays (20 CPUs × ~25 maps × ~24 B × per-entry multiplier)
- Pre-allocated hash-map buckets (e.g. `deny_inode` 65536 × ~48 B ≈ 3 MB,
  `deny_path` 16384 × ~320 B ≈ 5 MB, `process_tree` 65536 × ~76 B ≈ 5 MB)

**Loading 10 000 inode deny rules does NOT add ~5 MB** — BPF hash maps
allocate all buckets at program-load time, so the space is already
accounted for in the "empty policy" 100 MB baseline above.

When capacity-planning a container limit, budget **~120 MB memlock +
~16 MB userspace = ~140 MB** to leave headroom. The Helm chart's
`resources.limits.memory` guidance in `deploy/helm/` uses 256 MB by
default for this reason.

### Ring buffer memory

The ring buffer is a shared memory region between kernel and userspace.

```
ring_buffer_memory = ringbuf_size_bytes  (default: 256 KB)
```

The ring buffer size must be a power of 2.  It can be tuned via
`--ringbuf-size=<bytes>` at agent startup.

### Per-CPU arrays

Stats maps (`block_stats`, `net_block_stats`, per-map stats) use per-CPU
arrays:

```
per_cpu_memory = num_stats_maps * value_size * num_cpus
```

On a 64-core host with all stats maps: ~64 * 7 * 24 B ≈ 10 KB.

### Userspace heap

The agent's userspace memory is dominated by:
- Policy parsing buffers (transient, freed after apply)
- Deny entry tracking (`DenyEntries` map, ~100 B per entry)
- Cgroup path cache (~500 B per cached entry)
- Event processing buffers (ring buffer consumer)

Typical steady-state userspace RSS: ~7 MB on the 2026-04-08 reference
host (see "Measured memory footprint" above); 5–15 MB is a reasonable
range across deployments.

## Ring buffer sizing guidance

The ring buffer holds events generated by BPF programs until the userspace
consumer drains them.

### Sizing formula

```
recommended_size = events_per_second * avg_event_size * buffer_seconds
```

| Event type | Approximate size |
|-----------|-----------------|
| `ExecEvent` | 40 B |
| `BlockEvent` | 336 B |
| `NetBlockEvent` | 104 B |

### Example

For a workload generating 1,000 block events/sec with 2 seconds of buffer:

```
1000 * 336 * 2 = 672,000 B → round up to 1 MB (next power of 2)
```

### Pressure behavior

When the ring buffer is full:
- **New events are dropped**, not queued.  The BPF program increments the
  `ringbuf_drops` counter in the `block_stats` map.
- **Enforcement is NOT affected** by ring buffer pressure.  Deny decisions
  happen before event emission.  A full ring buffer means lost telemetry, not
  lost enforcement.
- The agent logs a warning when `ringbuf_drops` increases between poll cycles.

### Monitoring ring buffer health

```bash
# Check current drop count
aegisbpf stats --detailed

# Prometheus metric
aegisbpf_ringbuf_drops_total
```

If drops are persistent, increase the ring buffer size:
```bash
aegisbpf run --ringbuf-size=1048576  # 1 MB
```

## Capacity planning

Use the `footprint` subcommand to estimate memory requirements before
deployment:

```bash
aegisbpf footprint \
    --deny-inodes=10000 \
    --deny-paths=5000 \
    --deny-ips=1000 \
    --deny-cidrs=500 \
    --deny-ports=100 \
    --ringbuf-bytes=524288
```

This outputs estimated memory for each map and the total.

## Benchmarking

### Userspace benchmarks

Userspace hot-path benchmarks (policy parsing, hashing, key construction) run
without root privileges:

```bash
./build/aegisbpf_bench --benchmark_format=json
```

For CI comparison on shared hosted runners, filter out high-noise rows and use
primary mean rows only:

```bash
./build/aegisbpf_bench \
  --benchmark_min_time=1s \
  --benchmark_repetitions=16 \
  --benchmark_report_aggregates_only=true \
  --benchmark_out=benchmark.raw.json \
  --benchmark_out_format=json
python3 scripts/filter_benchmark_results.py \
  --input benchmark.raw.json \
  --output benchmark.json \
  --min-mean-time-ns 50 \
  --focus-pattern-file config/benchmark_focus_patterns.txt
```

The filter drops `stddev`/`cv` rows (and non-primary aggregate suffix rows),
removes very short operations (`<50ns`), and keeps only high-signal benchmark
families from `config/benchmark_focus_patterns.txt` so alerts track real
latency shifts rather than variance artifacts. When aggregate rows exist,
per-repetition raw rows are removed and only `mean` aggregates are kept.

`benchmark.yml` uses this filtered result for advisory trend tracking. Strict
pass/fail performance policy remains in `.github/workflows/perf.yml`.

### Syscall-level benchmarks

Syscall benchmarks measure actual `open()` and `connect()` latency with BPF
hooks attached.  These require root:

```bash
sudo scripts/bench_syscall.sh --json --out results.json
```

### Shell-based benchmarks

For quick A/B comparisons with and without the agent running:

```bash
# Baseline (no agent)
scripts/perf_open_bench.sh

# With agent
sudo WITH_AGENT=1 scripts/perf_open_bench.sh

# Network
sudo WITH_AGENT=1 scripts/perf_connect_bench.sh
```

## Tuning recommendations

| Parameter | Default | Guidance |
|-----------|---------|----------|
| `--ringbuf-size` | 256 KB | Increase if `ringbuf_drops` is non-zero |
| `--max-deny-inodes` | 65536 | Increase for large policy sets; each entry ~80 B |
| `--deny-rate-threshold` | 0 (disabled) | Set to auto-revert if deny rate spikes (e.g., 1000/s) |
| `--audit` vs `--enforce` | audit | Use enforce mode only after validating policy correctness |

## Related documents

- `docs/GUARANTEES.md` — Enforcement guarantees and TOCTOU analysis
- `docs/THREAT_MODEL.md` — Threat model and coverage boundaries
- `docs/COMPATIBILITY.md` — Kernel version compatibility
