# AegisBPF: Peer Comparison & Soak Testing Roadmap

**Status:** Active plan
**Last updated:** 2026-04-15

---

## 1. Current State Assessment

### What Already Exists

| Asset | Purpose | Status |
|---|---|---|
| `scripts/soak_reliability.sh` | Soak with RSS/drop/ratio gates (audit + enforce, file + network) | ✅ Production |
| `scripts/soak_monitor.sh` | Cron-based CSV metric collection | ✅ Working |
| `scripts/compare_runtime_security.sh` | Multi-agent comparison driver (3 workloads) | ✅ Supports 6 agents |
| `scripts/perf_open_bench.sh` | open/read/close microbench with percentiles | ✅ JSON + text output |
| `scripts/perf_connect_bench.sh` | UDP socket connect/close microbench | ✅ JSON + text output |
| `scripts/perf_exec_bench.sh` | fork+execve microbench with percentiles | ✅ JSON + text output |
| `scripts/install_peer_tools.sh` | One-command Falco + Tetragon installer | ✅ Idempotent |
| `scripts/aws_soak_24h.sh` | AWS EC2 24-hour soak automation | ✅ Self-terminating |
| `.github/workflows/soak.yml` | Weekly CI: 1h audit + 15m enforce + 5m ASAN soak | ✅ Active |
| `.github/workflows/comparison.yml` | Weekly CI: head-to-head comparison (3 workloads) | ✅ Active |
| `docs/PERFORMANCE_COMPARISON.md` | Measured comparison doc (3 workloads, 4 agents) | ✅ Published |
| `docs/SOAK_TESTING_GUIDE.md` | Manual soak testing runbook | ✅ Published |
| `docs/COMPETITIVE_BENCH_METHODOLOGY.md` | Comparison methodology doc | ✅ Published |
| `evidence/comparison/` | Raw comparison results (open_close, connect_close, exec_loop) | ✅ 2026-04-15 |

### What's Remaining

1. ~~**Falco and Tetragon not installed**~~ — ✅ Done (`install_peer_tools.sh`)
2. ~~**No enforce-mode soak**~~ — ✅ Done (soak.yml soak-enforce job)
3. ~~**No network-policy soak**~~ — ✅ Done (`SOAK_NET_WORKLOAD=1` in all jobs)
4. ~~**No long-duration CI soak**~~ — ✅ Done (1-hour audit soak in CI)
5. ~~**No multi-workload benchmark**~~ — ✅ Done (open_close + connect_close + exec_loop)
6. ~~**No automated comparison CI**~~ — ✅ Done (comparison.yml weekly Monday)
7. **No Grafana/visualization pipeline** — soak CSV is not visualized (future)
8. **No 24-hour soak results yet** — infrastructure ready (`aws_soak_24h.sh`), pending first run

---

## 2. Peer Tool Installation

### 2.1 Falco (Modern eBPF, No Kernel Module)

Falco's modern eBPF probe is embedded in the binary — no driver download needed.
Requires kernel ≥5.8.

The easiest way to install both is:

```bash
sudo scripts/install_peer_tools.sh all
```

Manual installation if preferred:

```bash
# Add Falco APT repo
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
  sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
  https://download.falco.org/packages/deb stable main" | \
  sudo tee /etc/apt/sources.list.d/falcosecurity.list

sudo apt-get update
sudo FALCO_FRONTEND=noninteractive apt-get install -y falco

# Verify
falco --version
```

**For benchmarking** -- run with an empty rules file to measure baseline overhead:

```bash
echo "" > /tmp/falco-empty.yaml
sudo falco -r /tmp/falco-empty.yaml -o "log_level=error" -o "engine.kind=modern_ebpf"
```

Note: Falco 0.43+ uses `-o "engine.kind=modern_ebpf"` (not `--modern-bpf`).
The comparison script (`compare_runtime_security.sh`) already does this in `run_falco()`.

### 2.2 Tetragon (Standalone, No Cilium Required)

Tetragon works standalone — no Cilium dependency. Current stable: v1.6.0.

```bash
# Download and install
TETRAGON_VERSION="v1.6.0"
curl -LO "https://github.com/cilium/tetragon/releases/download/${TETRAGON_VERSION}/tetragon-${TETRAGON_VERSION}-amd64.tar.gz"
tar -xvf "tetragon-${TETRAGON_VERSION}-amd64.tar.gz"
cd "tetragon-${TETRAGON_VERSION}-amd64/"
sudo ./install.sh

# Verify
tetragon version
sudo systemctl start tetragon
sudo systemctl status tetragon

# Install tetra CLI (for querying events)
curl -L "https://github.com/cilium/tetragon/releases/download/${TETRAGON_VERSION}/tetra-linux-amd64.tar.gz" | tar -xz
sudo mv tetra /usr/local/bin/
```

**For benchmarking** -- run with no TracingPolicies to measure baseline overhead:

```bash
# Start with no policies, export disabled
sudo tetragon --export-filename ""
```

Note: Tetragon v1.6+ uses `--export-filename` (not `--export-file`).
The comparison script already handles this in `run_tetragon()`.

### 2.3 Optional: Tracee & KubeArmor

```bash
# Tracee (Aqua) — container image is easiest
docker run --name tracee -d --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /boot:/boot:ro \
  aquasec/tracee:latest

# KubeArmor — standalone host mode
curl -sfL https://raw.githubusercontent.com/kubearmor/kubearmor-client/main/install.sh | sudo sh -
```

---

## 3. Comparison Methodology

### 3.1 Metrics to Measure

| Metric | How | Why |
|---|---|---|
| **Syscall latency (µs/op)** | `perf_open_bench.sh` — p50/p95/p99 | Primary overhead indicator |
| **Delta vs bare baseline** | % change from no-agent run | Apples-to-apples overhead |
| **RSS at idle** | `/proc/$PID/status` VmRSS | Memory footprint |
| **RSS under load** | Same, during sustained workload | Memory scaling behavior |
| **CPU at idle** | `ps -p $PID -o %cpu=` | Background cost |
| **CPU under load** | Same, during sustained workload | Processing overhead |
| **Startup time** | `time $agent run` until ready | Deployment impact |
| **Event throughput** | Events/sec at saturation | Ring buffer capacity |
| **Ring buffer drops** | Agent-specific drop counters | Reliability under load |
| **Policy reload time** | Time to apply a 100-rule policy | Operational agility |

### 3.2 Workloads

| Workload | What It Tests | Implementation | Status |
|---|---|---|---|
| `open_close` | File hook overhead | `scripts/perf_open_bench.sh` | ✅ Measured |
| `connect_close` | Network hook overhead | `scripts/perf_connect_bench.sh` | ✅ Measured |
| `exec_loop` | Exec identity / bprm_check overhead | `scripts/perf_exec_bench.sh` | ✅ Measured |
| `mixed_io` | Realistic file + network combined | Interleaved file opens + TCP connects | Future |
| `stress_ng` | Whole-system stress | `stress-ng --cpu 4 --io 4 --vm 2 --timeout 60s` | Future |

### 3.3 Test Matrix

| Dimension | Values |
|---|---|
| **Agents** | none, aegisbpf, falco, tetragon, (tracee, kubearmor optional) |
| **Workloads** | open_close, connect_close, exec_loop |
| **Policy size** | empty, 10 rules, 100 rules, 1000 rules |
| **Iterations** | 200,000 per measurement (3 repeats, 1 burn-in) |
| **Duration per agent** | ~5 min per workload × policy combination |
| **Total estimated time** | ~2 hours for full matrix (3 agents × 3 workloads × 3 policy sizes) |

### 3.4 Statistical Rigor

- **Minimum 3 repeats** per measurement point (already in `perf_open_bench.sh`)
- **1 burn-in run** discarded (already implemented)
- **Report median**, not mean (already implemented)
- **Report p50/p95/p99** (already implemented)
- **CPU pinning** to reduce scheduler noise (already in `perf_open_bench.sh`)
- **Cooldown period** between agents (already in `compare_runtime_security.sh`)
- **Conflicting agent check** before starting (already implemented)
- **Add:** Confidence intervals (±) for repeated runs
- **Add:** Environment fingerprint (kernel, CPU, governor, turbo boost state)

### 3.5 Fair Comparison Rules

1. All agents run on the **same host, same kernel, same boot**
2. Each agent runs with the **most benign possible configuration** (audit/detect only, empty rules)
3. Only **one agent active** at a time — conflicting agents killed before each run
4. **CPU frequency governor** locked to `performance` during benchmarks
5. Results are **only valid within a single run** — never copy across hosts or dates
6. All numbers published must be **reproducible** via `scripts/compare_runtime_security.sh`

---

## 4. Soak Testing Roadmap

### Phase 1: Extend Current Soak -- ✅ COMPLETE

**Goal:** Fill gaps in the existing soak infrastructure.

#### 1a. Enforce-mode soak variant -- ✅ Done

`soak_reliability.sh` now supports `SOAK_MODE=enforce`. CI runs a 15-minute
enforce-mode soak in `soak.yml` (`soak-enforce` job).

#### 1b. Network workload in soak -- ✅ Done

`SOAK_NET_WORKLOAD=1` adds UDP connect() workers to exercise socket hooks.
All three CI soak jobs (audit, enforce, ASAN) now include network workload.

#### 1c. Extended CI soak duration -- ✅ Done

- **Weekly:** 1-hour audit soak (was 15 min)
- **Enforce:** 15-minute enforce soak (new)
- **ASAN:** 5-minute ASAN soak (unchanged, ASAN overhead makes long runs impractical)

### Phase 2: Install Peer Tools & Run Comparison -- ✅ COMPLETE

**Goal:** Produce the first real head-to-head numbers.

1. ✅ Installed Falco (modern eBPF, v0.43.1) and Tetragon (standalone, v1.6.0)
2. ✅ Ran `compare_runtime_security.sh --agents none,aegisbpf,falco,tetragon`
3. ✅ Saved results to `evidence/comparison/` (2026-04-15)
4. ✅ Updated `docs/PERFORMANCE_COMPARISON.md` with measured numbers
5. ✅ Only published what was measured -- no fabrication or extrapolation

### Phase 3: Multi-Workload Benchmarks -- ✅ COMPLETE

**Goal:** Expand beyond `open_close` to cover network and exec paths.

1. ✅ `connect_close` workload via `scripts/perf_connect_bench.sh`
2. ✅ `exec_loop` workload via `scripts/perf_exec_bench.sh`
3. ✅ Full comparison matrix across all 3 workloads × 4 agents
4. ✅ Results documented in `docs/PERFORMANCE_COMPARISON.md` and `evidence/comparison/`

### Phase 4: Long-Duration Soak -- IN PROGRESS

**Goal:** Prove stability advantage over time.

Infrastructure ready:
- ✅ `scripts/aws_soak_24h.sh` -- launches EC2 t3.micro, builds from HEAD,
  enables BPF LSM, runs 24h soak, uploads to S3, self-terminates (~$0.25/day)
- Supports `--dry-run`, `--instance-type`, `--duration`, `--mode` (audit/enforce)

Pending:
- First 24-hour soak execution
- Multi-agent 24-hour memory curves (RSS over time for each agent)

### Phase 5: Automated Comparison CI -- ✅ COMPLETE

**Goal:** Catch performance regressions against peer tools automatically.

✅ `.github/workflows/comparison.yml`:
- Weekly Monday 03:00 UTC (or manual dispatch)
- Matrix: `open_close` x `connect_close` x `exec_loop`
- Installs Falco + Tetragon via `install_peer_tools.sh`
- Per-workload artifact upload + job summary

---

## 5. Implementation Priority

| # | Task | Effort | Impact | Status |
|---|---|---|---|---|
| 1 | Install Falco + Tetragon | 30 min | High | ✅ Done |
| 2 | Run first comparison | 15 min | **Critical** | ✅ Done (2026-04-15) |
| 3 | Publish results to docs | 30 min | High | ✅ Done |
| 4 | Add `connect_close` workload | 2 hrs | Medium | ✅ Done |
| 5 | Add enforce-mode soak | 2 hrs | Medium | ✅ Done |
| 6 | Extend CI soak to 1 hour | 15 min | Medium | ✅ Done |
| 7 | Add network workload to soak | 1 hr | Medium | ✅ Done |
| 8 | Add `exec_loop` workload | 2 hrs | Medium | ✅ Done |
| 9 | Run 24-hour soak | 24 hrs (wall) | High | Infrastructure ready |
| 10 | Automated comparison CI | 4 hrs | Medium | ✅ Done (comparison.yml) |

---

## 6. Expected Architectural Advantages

Based on design analysis (these are predictions, not measurements):

| Metric | AegisBPF Expected Edge | Reasoning |
|---|---|---|
| **File open latency** | Competitive or better | O(1) hash-map lookup vs rule-engine walk |
| **Memory footprint** | Significantly lower | C++20 static binary, no Go GC heap |
| **GC pause impact** | Zero | No garbage collector (Tetragon/Tracee/KubeArmor are Go) |
| **Policy reload** | Fast (shadow-map swap) | Atomic map swap vs CRD reconciliation |
| **Enforcement latency** | Equal or better | In-kernel LSM decision, no userspace round-trip |
| **Startup time** | Faster | Single binary, no runtime reflection |
| **Event throughput** | Comparable | All tools use ring buffers; sizing matters more than language |

**Important:** These are hypotheses to be validated, not claims to publish.

---

## 7. Risk Assessment

| Risk | Mitigation |
|---|---|
| AegisBPF performs worse than expected | Document honestly; focus on unique capabilities (copy-up, IMA, break-glass) |
| Falco's modern eBPF conflicts with AegisBPF's LSM hooks | Run agents sequentially, never simultaneously |
| Tetragon's BPF programs conflict with kernel BPF state | Full agent stop + 5s cooldown between runs (already implemented) |
| Benchmark results vary across runs | Pin CPUs, lock governor, report median of 3 repeats |
| Self-hosted runner environment changes between weekly runs | Log full environment fingerprint; discard cross-boot comparisons |

---

## 8. References

- [Falco Performance Testing](https://falco.org/blog/falco-performance-testing/)
- [Falco Modern BPF](https://falco.org/blog/falco-modern-bpf/)
- [Falco Install Packages](https://falco.org/docs/setup/packages/)
- [Tetragon Standalone Installation](https://tetragon.io/docs/installation/package/)
- [Tetragon without Cilium](https://isovalent.com/blog/post/can-i-use-tetragon-without-cilium-yes/)
- [Tetragon GitHub Releases](https://github.com/cilium/tetragon/releases)
- [Comparative Analysis of eBPF-Based Runtime Security (2025 paper)](https://www.scitepress.org/Papers/2025/142727/142727.pdf)
- [Datadog: Hardening eBPF for Workload Protection](https://www.datadoghq.com/blog/engineering/ebpf-workload-protection-lessons/)
- [Falco vs Tetragon Showdown](https://medium.com/@mughal.asim/falco-vs-tetragon-a-runtime-security-showdown-for-kubernetes-a0e9fb9f30a0)
