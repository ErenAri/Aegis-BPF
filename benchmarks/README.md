# AegisBPF Competitive Benchmark Suite

Reproducible performance benchmarks comparing AegisBPF against other eBPF
security agents (Falco, Tetragon, Tracee).

## Quick Start

```bash
# Run all benchmarks (requires root for BPF)
sudo ./run-benchmarks.sh

# Run specific benchmark
sudo ./run-benchmarks.sh --test file-open
sudo ./run-benchmarks.sh --test network-connect
sudo ./run-benchmarks.sh --test memory

# Compare against other tools (must be installed separately)
sudo ./compare.sh --tools aegisbpf,falco,tetragon
```

## Benchmark Categories

| Test | What It Measures | Method |
|------|-----------------|--------|
| `file-open` | File open syscall overhead | 100k `open()`/`close()` cycles |
| `network-connect` | TCP connect latency | 10k `connect()` to localhost |
| `process-exec` | Process execution overhead | 1k `/bin/true` invocations |
| `memory` | RSS/VSZ at idle | `/proc/<pid>/status` sampling |
| `startup` | Time to first enforcement | Wall clock from exec to `--help` exit |

## Methodology

All benchmarks follow these principles:

1. **Isolation**: Each test runs in a clean cgroup/namespace
2. **Warm-up**: 1000 iterations discarded before measurement
3. **Statistical rigor**: Reports mean, p50, p95, p99, min, max
4. **Baseline**: Always measures without any agent first
5. **Reproducibility**: Pinned kernel version, documented CPU governor

## Requirements

- Linux 5.15+ with BTF enabled
- Root access (for BPF programs)
- `perf` tools installed
- At least 4 CPU cores (for isolation)
- CPU frequency governor set to `performance`
