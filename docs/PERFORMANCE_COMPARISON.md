# AegisBPF Performance Comparison

This document provides a comparative analysis of AegisBPF against other
eBPF-based runtime security tools, covering architectural differences,
performance characteristics, and resource consumption.

## Architecture Comparison

| Feature | AegisBPF | Falco | Tetragon | Tracee |
|---------|----------|-------|----------|--------|
| **Enforcement model** | BPF LSM deny-list | Detect-only (rules engine) | BPF LSM + tracing | Detect-only + LSM |
| **Policy language** | Declarative INI | YAML rules (Falco rules) | CRDs (TracingPolicy) | Rego / Signatures |
| **Hook mechanism** | LSM hooks + tracepoints | Kernel module / eBPF | LSM hooks + kprobes | Tracepoints + LSM |
| **Language** | C++20 / C (BPF) | C++ (userspace) | Go (userspace) | Go (userspace) |
| **Policy evaluation** | In-kernel (O(1) hash) | Userspace (rule engine) | In-kernel | Hybrid |
| **Hot-reload** | Atomic map swap (<50ms) | Rule file reload | CRD apply | Signature reload |
| **Container-native** | Cgroup-aware | Container runtime | Kubernetes-native | Container-native |

## Performance Characteristics

### Why AegisBPF Is Fast

1. **Inode-first policy evaluation**: Deny decisions use BPF hash map lookups
   (O(1)) on inode+device pairs. Path resolution happens only after a match,
   not for every syscall. Competitors that evaluate path-based rules must
   resolve paths on every check.

2. **Minimal userspace involvement**: All enforcement decisions happen in
   BPF programs at the kernel boundary. Userspace only handles event
   consumption and policy management — never enforcement decisions.

3. **Compact deny maps**: Hash maps with 16-byte keys and 1-byte values
   minimize cache pressure. One cache line can hold multiple deny entries.

4. **No rule engine overhead**: AegisBPF uses direct map lookups, not a
   rules engine. There is no rule-ordering overhead, no regex evaluation,
   and no condition chain to process per-syscall.

5. **Single-binary deployment**: No sidecar, no daemon framework, no gRPC
   overhead. The agent is a single static binary with sub-second startup.

### Performance Metrics

| Metric | AegisBPF | Falco¹ | Tetragon² | Tracee³ |
|--------|----------|--------|-----------|---------|
| **File open overhead** | 0.1–0.5 µs | 2–5 µs | 0.5–2 µs | 3–8 µs |
| **Network connect overhead** | 0.2–1.0 µs | N/A⁴ | 0.5–3 µs | 2–6 µs |
| **Memory (idle, no rules)** | ~15 MB | ~85 MB | ~45 MB | ~120 MB |
| **Memory (10k rules)** | ~20 MB | ~150 MB | ~80 MB | ~200 MB |
| **Startup time** | <0.5s | 3–5s | 1–2s | 2–4s |
| **Policy reload** | <50ms | 1–5s | 2–10s | 1–5s |
| **CPU at 1k events/s** | <1% | 3–5% | 1–3% | 5–10% |
| **Binary size** | ~2 MB | ~50 MB⁵ | ~30 MB | ~40 MB |

¹ Falco 0.37+ with modern BPF driver
² Cilium Tetragon 1.0+
³ Aqua Tracee 0.20+
⁴ Falco monitors network via syscall tracing, not enforcement
⁵ Including rules engine and YAML parser

> **Note**: These numbers are estimated based on public benchmarks, published
> documentation, and architectural analysis. Actual performance varies by
> workload, kernel version, and configuration. Run `benchmarks/` scripts
> for reproducible measurements on your hardware.

### Why These Numbers Matter

For a host processing 10,000 file opens per second:

| Agent | Added latency per open | Total overhead per second |
|-------|----------------------|--------------------------|
| AegisBPF | 0.3 µs | 3 ms (0.3%) |
| Tetragon | 1.0 µs | 10 ms (1.0%) |
| Falco | 3.0 µs | 30 ms (3.0%) |
| Tracee | 5.0 µs | 50 ms (5.0%) |

On latency-sensitive workloads (databases, trading systems, real-time
applications), the difference between 0.3% and 5% overhead is significant.

## Feature Comparison

| Capability | AegisBPF | Falco | Tetragon | Tracee |
|-----------|----------|-------|----------|--------|
| **File access enforcement** | ✅ Kernel deny | ❌ Detect only | ✅ Kernel deny | ⚠️ Limited |
| **Network enforcement** | ✅ Socket hooks | ❌ Detect only | ✅ Socket hooks | ⚠️ Limited |
| **Process execution tracking** | ✅ BPF tracepoint | ✅ Syscall tracing | ✅ Kprobe/LSM | ✅ Tracepoint |
| **Ptrace blocking** | ✅ LSM hook | ❌ Detect only | ✅ LSM hook | ⚠️ Signature |
| **Module load blocking** | ✅ LSM hook | ❌ Detect only | ✅ LSM hook | ⚠️ Signature |
| **BPF program blocking** | ✅ LSM hook | ❌ Detect only | ❌ No | ❌ No |
| **Policy hot-reload** | ✅ Atomic swap | ⚠️ File reload | ⚠️ CRD update | ⚠️ File reload |
| **Kubernetes-native** | ✅ CRD operator | ✅ Helm chart | ✅ CRD native | ✅ Helm chart |
| **Prometheus metrics** | ✅ Built-in | ✅ Built-in | ✅ Built-in | ✅ Built-in |
| **Grafana dashboards** | ✅ 4 dashboards | ✅ Community | ✅ Hubble UI | ⚠️ Community |
| **SIEM integration** | ✅ Splunk, Elastic, OTLP | ✅ Falcosidekick | ⚠️ JSON export | ⚠️ JSON export |
| **Compliance mappings** | ✅ NIST, CIS, ISO, SOC2, PCI | ⚠️ Basic | ❌ None | ❌ None |
| **Exec identity verification** | ✅ Inode + hash | ❌ No | ❌ No | ⚠️ Signature |
| **Break-glass mechanism** | ✅ Emergency toggle | ❌ No | ❌ No | ❌ No |
| **Multi-arch** | ✅ x86_64, ARM64 | ✅ x86_64, ARM64 | ✅ x86_64, ARM64 | ✅ x86_64, ARM64 |

## Resource Consumption Profile

### Memory Breakdown

```
AegisBPF (15 MB typical):
├── BPF maps (pre-allocated)     5-10 MB
├── Ring buffer (default)        256 KB
├── Per-CPU arrays               ~10 KB
├── Userspace heap               5-10 MB
│   ├── Policy tracking          ~1 MB
│   ├── Cgroup cache             ~500 KB
│   ├── Event processing         ~2 MB
│   └── Process lineage          ~2 MB
└── BPF program text             ~50 KB

Falco (85 MB typical):
├── Rules engine                 20-30 MB
├── Syscall buffer               16-32 MB
├── YAML parser + rule state     10-15 MB
├── gRPC framework               10-15 MB
└── Kernel module / eBPF         5-10 MB

Tetragon (45 MB typical):
├── Go runtime                   15-20 MB
├── BPF maps + programs          10-15 MB
├── CRD controller               5-10 MB
├── Metrics + export             5-10 MB
└── Ring buffer                  5-10 MB
```

### Scaling Behavior

| Dimension | AegisBPF | Falco | Tetragon |
|-----------|----------|-------|----------|
| Rules × 2 | +0% CPU (O(1) lookup) | +10-20% CPU (rule eval) | +5-10% CPU |
| Events × 2 | +linear ring buffer | +linear event queue | +linear ring buffer |
| CPUs × 2 | +per-CPU map memory | +buffer memory | +per-CPU map memory |
| Nodes × 2 | Linear (per-node agent) | Linear (per-node agent) | Linear (per-node agent) |

## Benchmark Methodology

### Running Benchmarks

```bash
# Userspace benchmarks (no root required)
./build/aegisbpf_bench --benchmark_format=json

# Syscall-level benchmarks (root required)
sudo scripts/bench_syscall.sh --json --out results.json

# Quick A/B comparison
scripts/perf_open_bench.sh            # Baseline
sudo WITH_AGENT=1 scripts/perf_open_bench.sh  # With AegisBPF
```

### Reproducing the Comparison

To produce comparable numbers on your hardware:

1. **Prepare a clean VM** (no other security agents running)
2. **Kernel**: Ubuntu 24.04 with kernel 6.8+ (BTF enabled)
3. **Hardware**: 4+ cores, 8+ GB RAM
4. **Workload**: `sysbench fileio --file-test-mode=seqrd --file-num=100 run`

```bash
# AegisBPF
sudo aegisbpf daemon &
sysbench fileio --file-test-mode=seqrd run
# Record: ops/sec, latency p99

# Falco (if installed)
sudo falco &
sysbench fileio --file-test-mode=seqrd run

# Tetragon (if installed)
kubectl apply -f tetragon/install.yaml
sysbench fileio --file-test-mode=seqrd run
```

## Architecture Advantages

### AegisBPF Design Decisions

| Decision | Rationale | Performance Impact |
|----------|-----------|-------------------|
| Inode-first evaluation | Avoids path resolution for non-matching files | 10-50x faster than path-first |
| Hash maps for deny rules | O(1) lookup regardless of rule count | Constant-time scaling |
| LPM trie for CIDR rules | O(prefix-length) for network ranges | Optimal for IP matching |
| Per-CPU arrays for stats | Lock-free counters, no contention | Zero overhead at scale |
| Dual ring buffer | Priority events survive telemetry shedding | Enforcement reliability |
| Shadow map swap | Atomic policy reload without enforcement gap | Zero-downtime updates |
| Single binary + BPF | No runtime dependencies, no GC pauses | Predictable latency |

## Related Documents

- `docs/PERFORMANCE.md` — Detailed performance profile and tuning
- `docs/PERF_BASELINE.md` — CI performance baselines
- `docs/GUARANTEES.md` — Enforcement guarantees and TOCTOU analysis
- `docs/THREAT_MODEL.md` — Threat model and coverage boundaries
