# AegisBPF vs Other eBPF Runtime Security Tools

Status: **measured** — includes first head-to-head comparison (2026-04-15)
Last updated: 2026-04-15

This document compares AegisBPF against other eBPF-based runtime security
tools (Falco, Tetragon, Tracee, KubeArmor). **It deliberately avoids
side-by-side performance numbers that have not been measured on the same
hardware in this repository.** Earlier revisions of this document included
µs and MB figures copied from third-party blog posts and architecture
diagrams — those have been removed. The replacement methodology is in
[`docs/COMPETITIVE_BENCH_METHODOLOGY.md`](COMPETITIVE_BENCH_METHODOLOGY.md)
and reproducible via [`scripts/compare_runtime_security.sh`](../scripts/compare_runtime_security.sh).

## Honesty preface

Two classes of claim appear below:

- **Verifiable** — backed by code in this repository, tests in CI, or
  benchmarks that are reproducible on the reader's own hardware.
- **Architectural** — follows from the upstream design of each tool and
  can be cross-checked against their published source.

Anything that would require a head-to-head benchmark has been removed. If
you want those numbers, run `scripts/compare_runtime_security.sh` on a
clean host that has all four agents installed.

## Architecture comparison (verifiable / architectural)

| Trait | AegisBPF | Falco | Tetragon | Tracee | KubeArmor |
|---|---|---|---|---|---|
| Primary purpose | Enforcement + audit | Detection / alerting | Enforcement + observability | Detection + signatures | Enforcement + audit |
| Enforcement via BPF LSM | Yes (14 hooks) | No | Yes | Limited | Yes |
| Policy evaluation | In-kernel, hash/LPM map | Userspace rule engine | In-kernel per TracingPolicy | Hybrid / userspace | In-kernel + userspace |
| Policy language | Declarative INI | Falco rules (DSL) | CRDs (TracingPolicy) | Rego / Go signatures | CRD (KubeArmorPolicy) |
| Hot-reload | Atomic shadow-map swap | Rule-file reload | CRD apply | Signature reload | CRD apply |
| Primary language | C++20 + C (BPF) | C++ | Go | Go | Go |

## Kernel hook coverage (verifiable — `bpf/*.bpf.h`)

AegisBPF attaches 14 unique BPF LSM hooks and 4 tracepoints:

| Category | Hooks |
|---|---|
| File / exec | `file_open`, `inode_permission`, `bprm_check_security` (exec identity), `bprm_check_security` (IMA hash), `file_mmap` |
| Socket lifecycle | `socket_connect`, `socket_bind`, `socket_listen`, `socket_accept`, `socket_sendmsg`, `socket_recvmsg` |
| Kernel security | `ptrace_access_check`, `locked_down`, `bpf` |
| Overlay / container | `inode_copy_up` |
| Tracepoints (audit fallback) | `sys_enter_execve`, `sys_enter_openat`, `sched_process_fork`, `sched_process_exit` |

Hooks that are architecturally uncommon in peer tools:

- **`socket_recvmsg` and `socket_accept`** — most eBPF security tools stop
  at `connect`/`bind`. Hooking the receive path enables detection of
  inbound data from denied peers, not just outbound initiation.
- **`inode_copy_up`** — OverlayFS copy-up propagation for deny rules.
  Without this, a container that writes to a lower-layer file creates a
  new upper-layer inode that silently bypasses an inode-based deny rule.
- **IMA hash path in `bprm_check_security`** — cross-checks the exec'd
  binary's IMA hash against an allowlist on kernels 6.1+.

## Enforcement guarantees with CI proofs (verifiable — `docs/ENFORCEMENT_CLAIMS.md`)

Every enforcement guarantee in AegisBPF has a proof script that runs on a
real BPF LSM kernel in CI (`scripts/e2e_enforcement_proofs.sh`, workflow
`e2e.yml`). The current matrix is nine claims:

| # | Claim | Proof |
|---|---|---|
| C1 | `deny_path /X` blocks `open("/X")` | `test_deny_path` |
| C2 | `deny_inode dev:ino` blocks `open()` on that inode | `test_deny_inode` |
| C3 | `allow_cgroup` bypasses deny for that cgroup | `test_cgroup_bypass` |
| C4 | `deny_ipv4` blocks `connect()` to that IP | `test_deny_ipv4` |
| C5 | `deny_port` blocks `bind()` on that port | `test_deny_port` |
| C6 | Break-glass disables enforcement | `test_break_glass` |
| C7 | Deadman switch reverts to audit after TTL | `test_deadman` |
| C8 | Survival allowlist prevents blocking critical binaries | `test_survival` |
| C9 | Emergency disable stops enforcement instantly | `test_emergency` |

Falco does not claim enforcement; its equivalent is alert delivery. Tetragon
has TracingPolicy enforcement tests upstream; Tracee and KubeArmor have
their own claim matrices. **This repository does not reproduce peer-tool
proofs** — cross-claims about what they can and cannot block are
architectural, not measured.

## Hot-path data-plane numbers (verifiable — `build/aegisbpf_bench`)

The following numbers are produced by `build/aegisbpf_bench` on the
reference host (13th Gen Intel i9-13900H, kernel 6.17.0-19-generic). They
measure the userspace-visible fast-path operations that back the
in-kernel deny decision. They are **not** syscall-level numbers — those
live in `docs/PERF_BASELINE.md`.

| Operation | Time | Scales with rule count? |
|---|---|---|
| Deny map lookup (100 entries) | 3.90 ns | — |
| Deny map lookup (512 entries) | 4.07 ns | — |
| Deny map lookup (4 096 entries) | 3.95 ns | — |
| Deny map lookup (10 000 entries) | 3.93 ns | **no** |
| Deny map insert (100 entries) | ~25.8 ns/op | — |
| Deny map insert (512 entries) | ~37.5 ns/op | — |
| Deny map insert (4 096 entries) | ~37.9 ns/op | — |
| Deny map insert (10 000 entries) | ~46.4 ns/op | mild growth |
| Path key fill (short path) | 13.8 ns | — |
| Inode ID hash | 0.10 ns | — |
| Port key hash | 0.09 ns | — |
| SHA-256 (short input) | 710 ns | — |

Numbers above are the 2026-04-08 re-run on Linux 6.17 / i9-13900H.
Every microbench is equal to or slightly better than the previous
2026-02-15 reference. Note the deny-map insert row: the earlier
table quoted a single "27.3 ns/op" number that was only the N=100
measurement; the full curve shows insert time grows mildly with table
size because of bucket-chain length and hash-collision rehashing. The
insert path is not a hot path (it runs at policy-apply time, not per
syscall), so this growth is not a concern.

The flat 3.9–4.1 ns lookup curve from 100 to 10 000 entries is the single
most important number here. It is evidence for the claim that
**AegisBPF's policy evaluation is O(1) in rule count**, because it is a
BPF hash-map lookup, not a rule-engine walk. Tools that use a rule DSL
(Falco, Tracee signatures) are asymptotically O(rules) by construction;
this is an architectural advantage that does not depend on benchmarking
them.

Reproduce locally:

```bash
cmake -B build -G Ninja && cmake --build build -j$(nproc) --target aegisbpf_bench
./build/aegisbpf_bench --benchmark_format=console | grep BM_DenyEntriesLookup
```

## Syscall-level overhead on the reference host

From `docs/PERF_BASELINE.md` (self-hosted perf gate, Ubuntu 24.04, kernel
6.14, audit-only, empty policy):

- `open` p50/p95/p99 with agent: **1.22 / 1.26 / 1.47 µs**
- `connect` p50/p95/p99 with agent: **2.16 / 3.22 / 4.60 µs**
- `open_close` delta vs baseline: **−2.19 %** (within noise)

These are **one host, one kernel, one workload, audit-only**. They show
the agent is not detectable in this microbench — they do *not* show the
agent is faster than competitors on arbitrary hardware. For a true
comparison you must run `scripts/compare_runtime_security.sh` on the
same box as the peer tools.

## Head-to-head comparison (measured 2026-04-15)

The following numbers were produced by `scripts/compare_runtime_security.sh`
on the same host, same kernel, same boot, same run. Each agent was started
in isolation with an empty/minimal policy (audit or detect only), then
200 000 `open → read → close` cycles were measured with CPU governor locked
to `performance`.

**Environment:** 13th Gen Intel i9-13900H, kernel 6.17.0-19-generic, Ubuntu 24.04

| Agent | Version | µs/op | p50 (µs) | p95 (µs) | p99 (µs) | Delta vs bare |
|---|---|---|---|---|---|---|
| none (baseline) | — | 1.69 | 1.56 | 1.64 | 2.53 | — |
| **AegisBPF** | 0.1.0 | 1.68 | 1.58 | 1.63 | 2.42 | **−0.59%** |
| Tetragon | v1.6.0 | 1.63 | 1.52 | 1.57 | 2.27 | −3.55% |
| Falco | 0.43.1 | 2.33 | 2.20 | 2.36 | 3.47 | **+37.87%** |

### Network workload: `connect_close` (UDP socket → connect → close)

| Agent | Version | µs/op | p50 (µs) | p95 (µs) | p99 (µs) | Delta vs bare |
|---|---|---|---|---|---|---|
| none (baseline) | — | 3.62 | 2.66 | 5.50 | 7.38 | — |
| **AegisBPF** | 0.1.0 | 3.87 | 2.67 | 5.34 | 8.18 | **+6.91%** |
| Tetragon | v1.6.0 | 3.74 | 2.89 | 5.46 | 7.18 | +3.31% |
| Falco | 0.43.1 | 4.44 | 3.47 | 6.13 | 8.56 | **+22.65%** |

### Exec workload: `exec_loop` (fork → execve(/bin/true) → waitpid)

| Agent | Version | µs/op | p50 (µs) | p95 (µs) | p99 (µs) | Delta vs bare |
|---|---|---|---|---|---|---|
| none (baseline) | — | 279.33 | 244.98 | 461.58 | 619.09 | — |
| **AegisBPF** | 0.1.0 | 246.77 | 236.82 | 319.24 | 417.77 | −11.66% |
| Tetragon | v1.6.0 | 251.07 | 239.23 | 320.30 | 430.46 | −10.12% |
| Falco | 0.43.1 | 245.54 | 235.24 | 315.48 | 405.85 | −12.10% |

### Key observations

- **File I/O (`open_close`):** AegisBPF and Tetragon are both within noise
  of the bare baseline. Falco shows +38% overhead from its userspace rule
  engine.
- **Network (`connect_close`):** All agents show small overhead. AegisBPF
  at +6.9% reflects its 6 socket lifecycle hooks (connect/bind/listen/
  accept/sendmsg/recvmsg). Tetragon is +3.3%, Falco +22.7%.
- **Exec (`exec_loop`):** All agents are within noise of each other
  (~245–280 µs/op). The negative deltas vs baseline are measurement
  variance — fork+execve is inherently noisy (~250 µs/op with high p95/p99
  tails from scheduler jitter). No agent adds measurable exec overhead.
- The negative deltas in `open_close` and `exec_loop` are measurement
  variance, not real speedups. The `connect_close` workload is noisier
  (higher variance) due to UDP socket teardown timing.
- Falco's overhead is consistent in `open_close` and `connect_close`
  because its userspace rule engine processes every syscall event regardless
  of type. In `exec_loop` the per-op cost (~250 µs) dwarfs the agent
  overhead, so all agents converge.

**Reproduce:**

```bash
sudo scripts/install_peer_tools.sh all
# File I/O workload
sudo scripts/compare_runtime_security.sh \
    --agents none,aegisbpf,falco,tetragon \
    --workload open_close --iterations 200000 --out results/
# Network workload
sudo scripts/compare_runtime_security.sh \
    --agents none,aegisbpf,falco,tetragon \
    --workload connect_close --iterations 200000 --out results/
# Exec workload
sudo scripts/compare_runtime_security.sh \
    --agents none,aegisbpf,falco,tetragon \
    --workload exec_loop --iterations 5000 --out results/
```

Raw per-agent JSON: `evidence/comparison/`

## Architectural advantages (defensible)

These statements follow from design, not from performance benchmarks
against competitors.

1. **In-kernel enforcement, not userspace alerting.** Falco and Tracee
   are fundamentally detection engines — they cannot block a syscall.
   AegisBPF, Tetragon, and KubeArmor can.
2. **O(1) deny evaluation.** BPF hash-map lookups are constant-time in
   rule count (measured flat from 100 → 10 000 entries above). Rule-engine
   designs cannot match this asymptotically.
3. **Full socket lifecycle coverage.** `connect`, `bind`, `listen`,
   `accept`, `sendmsg`, `recvmsg` — most peer tools hook only the first
   two.
4. **OverlayFS copy-up propagation.** Container escape via copy-up is a
   real gap; AegisBPF is the only tool I am aware of that propagates
   deny rules across copy-up.
5. **IMA-backed exec identity** on kernel 6.1+.
6. **Break-glass, deadman, emergency disable** — operational safety
   primitives with e2e proofs (C6, C7, C9).
7. **Single binary, no Go runtime, no GC pauses.** `build/aegisbpf`
   is ~45 MB unstripped (debug_info + RAII C++20), ~130 ms startup on
   the reference host, no sidecar, no gRPC. It is **dynamically
   linked** against libbpf / libsystemd / libstdc++ / libelf / libcap
   / libgcrypt / lib{z,lz4,lzma,zstd} / libc — a static build is not
   currently shipped but is a possible future packaging option.

## What is *not* claimed

These are explicit non-claims to prevent overclaiming:

- **"AegisBPF is faster than $tool."** The head-to-head numbers above show
  AegisBPF and Tetragon are both within noise of baseline for file I/O.
  The results do *not* support "faster than" claims — they support
  "competitive with" claims. Only the Falco +38% `open_close` overhead is
  statistically significant.
- **Memory-footprint superiority over peer tools.** AegisBPF's memory is
  documented in `docs/PERFORMANCE.md`; peer-tool memory is not measured
  here.
- **MITRE ATT&CK coverage superiority.** AegisBPF does not ship a
  technique-mapped coverage matrix, so coverage comparisons are
  unsupported.
- **Independent security review.** `docs/EXTERNAL_VALIDATION.md` is the
  canonical source — it currently reads "no independent security review
  has been published."
- **Production-workload overhead.** All measured numbers use empty/minimal
  policies and synthetic microbenchmarks. Production workloads with
  hundreds of rules may differ.

## How to actually compare (reproducible)

See [`docs/COMPETITIVE_BENCH_METHODOLOGY.md`](COMPETITIVE_BENCH_METHODOLOGY.md)
for the full methodology and
[`scripts/compare_runtime_security.sh`](../scripts/compare_runtime_security.sh)
for the driver. The short version:

```bash
# Requires: clean host with aegisbpf, falco, tetragon, tracee, kubearmor
#           all installable. Root. No other LSM conflict.
sudo scripts/compare_runtime_security.sh \
    --agents aegisbpf,falco,tetragon \
    --workload open_close \
    --duration 60s \
    --out results/
```

The script runs each agent in isolation with the same sysbench/`perf_open_bench`
workload and emits a single `results.json` plus a Markdown table. Only
numbers produced by that script should ever appear in comparison tables
in this repository.

## Related documents

- `docs/PERFORMANCE.md` — AegisBPF's own performance profile and tuning
- `docs/PERF_BASELINE.md` — CI perf baseline and gate
- `docs/COMPETITIVE_BENCH_METHODOLOGY.md` — how to produce head-to-head numbers
- `docs/ENFORCEMENT_CLAIMS.md` — enforcement guarantees and proofs
- `docs/EXTERNAL_VALIDATION.md` — independent review status
- `docs/GUARANTEES.md` — enforcement guarantees and TOCTOU analysis
- `docs/THREAT_MODEL.md` — threat model and coverage boundaries
