# AegisBPF vs Other eBPF Runtime Security Tools

Status: **honest-draft**
Last updated: 2026-04-07

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
| Deny map lookup (100 entries) | 4.22 ns | — |
| Deny map lookup (512 entries) | 4.40 ns | — |
| Deny map lookup (4 096 entries) | 4.50 ns | — |
| Deny map lookup (10 000 entries) | 4.17 ns | **no** |
| Deny map insert (100 entries) | 27.3 ns/op | linear in inserts |
| Path key fill (short path) | 14.6 ns | — |
| Inode ID hash | 0.10 ns | — |
| Port key hash | 0.11 ns | — |
| SHA-256 (short input) | 742 ns | — |

The flat 4.2–4.5 ns lookup curve from 100 to 10 000 entries is the single
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
7. **Single static binary, no Go runtime, no GC pauses.** `build/aegisbpf`
   is ~47 MB, sub-second startup, no sidecar, no gRPC.

## What is *not* claimed

These are explicit non-claims because the evidence does not exist in this
repository:

- **Any "AegisBPF is N× faster than $tool" statement.** We have not run
  $tool on the same hardware as AegisBPF with the same workload.
- **Memory-footprint superiority over peer tools.** AegisBPF's memory is
  documented in `docs/PERFORMANCE.md`; peer-tool memory is not measured
  here.
- **MITRE ATT&CK coverage superiority.** AegisBPF does not ship a
  technique-mapped coverage matrix, so coverage comparisons are
  unsupported.
- **Independent security review.** `docs/EXTERNAL_VALIDATION.md` is the
  canonical source — it currently reads "no independent security review
  has been published."

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
