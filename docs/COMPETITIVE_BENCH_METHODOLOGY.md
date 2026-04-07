# Competitive Benchmark Methodology

Status: **honest-draft**
Last updated: 2026-04-08

This document specifies how `scripts/compare_runtime_security.sh` is meant
to be used and what its output is, and is not, allowed to claim.

It exists because earlier revisions of `docs/PERFORMANCE_COMPARISON.md`
contained µs and MB figures for Falco, Tetragon, Tracee and KubeArmor that
were copied from third-party blog posts and architecture diagrams. Those
numbers were not measured on the same hardware as AegisBPF, were not
reproducible from this repository, and have been removed. This file is the
rule that prevents that mistake from repeating.

## Why a separate methodology document

Runtime-security agents differ along several axes that make naive
comparison meaningless:

1. **Where the work happens.** Falco evaluates rules in userspace; Tetragon
   evaluates TracingPolicy in-kernel; KubeArmor combines AppArmor with
   eBPF; AegisBPF evaluates BPF hash maps in-kernel. A "syscall overhead"
   number from one tool is not the same physical thing as the same number
   from another.
2. **What is loaded by default.** Falco with `falco-rules.yaml` loaded is
   not the same workload as Falco with an empty rules file. Tetragon with
   no TracingPolicy is fundamentally a different program from Tetragon
   with the standard `process_credentials` policy.
3. **The host kernel.** Modern BPF features (BPF LSM, ringbuf,
   CO-RE/BTF) have a measurable cost difference between e.g. kernel 5.15
   and 6.14. Cross-kernel comparison is not allowed.
4. **The host's idle noise.** Under load from another agent, a desktop
   browser, or a chatty cron job, p95 and p99 numbers move by tens of
   percent. Quiescing the host is not optional.

The script `scripts/compare_runtime_security.sh` enforces (1)–(3); the
operator is responsible for (4).

## Reproducibility constraints

The script's output is **only meaningful** when all of the following hold:

- All agents in the comparison were measured on **the same physical host**
  in **the same invocation** of the script.
- The host was **quiesced**: no other security agent active, no GUI
  workload, no concurrent benchmarks, no power-management transitions
  during the run. CPU governor pinned to `performance` is recommended but
  not required, as long as it does not change between agents in the same
  run.
- The kernel, libc, and `aegisbpf` build are unchanged between agents in
  the same run.
- The workload (`--workload`) and iteration count (`--iterations`) are
  unchanged between agents in the same run.
- The comparison ran as **root**. The non-baseline agents all need
  CAP_BPF or equivalent and will fail to start otherwise.
- No agent's daemon is left running across runs of the script. The script
  refuses to start if it detects a peer security agent process already
  alive (`falco`, `tetragon`, `tracee`, `tracee-ebpf`, `kubearmor`,
  `aegisbpf`); fix the environment, do not edit the assertion away.

If any of the above is violated, the row for the affected agent must be
discarded. Do not partially edit a `results.md` to "fill in" a missing
agent from a different run.

## Workload definition

The current and only supported workload is `open_close`:

- A Python tight loop that calls `open(/etc/hosts, O_RDONLY)`,
  `read(fd, 1)`, `close(fd)` for `--iterations` iterations after a 1024
  iteration warmup, repeated three times with a one-iteration burn-in,
  reporting median across the three full runs.
- The runner is the existing `scripts/perf_open_bench.sh` invoked with
  `WITH_AGENT=0`. The "with agent" condition is provided by the parent
  script starting the agent in the background, not by the runner itself.
- The bench process is pinned to CPU 0 and (when applicable) the agent
  process is pinned to CPU 1, via `taskset`.
- `iterations` defaults to 200 000, which on the reference host gives a
  total wall time of ~2 s per agent and a stable p99.

This workload was deliberately chosen to be:

- **Hooked by every agent in the matrix.** All five agents observe
  `openat`. None of them needs a custom rule to be exercised.
- **CPU-bound, not I/O-bound.** `/etc/hosts` is in the page cache after
  warmup; no disk traffic confounds the measurement.
- **Cheap enough that per-syscall overhead dominates.** A heavier
  workload (e.g. `find /usr`) would dilute the agent's contribution into
  filesystem walk noise.

Future workloads (`exec`, `connect_close`, `sendmsg`) are out of scope
for this revision and **must not** be added to the comparison table
without first updating this methodology document with their definition.

## Per-agent baseline configuration

The script starts each non-baseline agent with the most-benign
configuration possible. The intent is to measure each agent's *resting
overhead* — the cost it imposes simply by being attached, with no policy
matching anything. This is the lower bound on its production cost; a
production rule set will be **at least** this expensive and usually
more.

| Agent | Configuration | Why |
|---|---|---|
| `none` | No agent. | Baseline; everything else is measured as a delta. |
| `aegisbpf` | `aegisbpf run --audit` with no policy file. | Audit-only, no enforcement, no rules to match. Mirrors the production "shadow mode" deployment. |
| `falco` | `falco --modern-bpf -r empty.yaml -o log_level=error` | modern-bpf driver (the default since 0.34) with an empty rules file. No rule can match, so the cost is just the driver tap. |
| `tetragon` | `tetragon` with no TracingPolicy. | Default Tetragon process exec/exit observer, no user policies attached. |
| `tracee` | `tracee --output option:no-color --output json --scope global` with no signatures. | Detect-only, JSON output, global scope, no signature engine. |
| `kubearmor` | `kubearmor --enableKubeArmorPolicy=false --enableKubeArmorHostPolicy=true --k8s=false` | Host mode, no Kubernetes integration, no policies. |

These configurations are **not** meant to represent each tool at its most
useful. They are meant to give every tool the benefit of the doubt by
measuring it with no rules. If you want to compare *production*
overhead, run the same script with each tool's vendor-recommended
ruleset; that requires updating this document and the script before
publishing the numbers.

## Running the script

Prerequisites:

- A clean host. Run `pgrep -x falco; pgrep -x tetragon; pgrep -x tracee; pgrep -x kubearmor; pgrep -x aegisbpf` and confirm all return nothing.
- Root.
- An aegisbpf build at `./build/aegisbpf` (override with `AEGISBPF_BIN`).
- The peer agents you want compared, installed on `$PATH`. The script
  does not install or remove anything.
- `python3` for the JSON parsing.

Minimal run (just AegisBPF vs no agent):

```bash
sudo scripts/compare_runtime_security.sh \
    --agents none,aegisbpf \
    --workload open_close \
    --iterations 200000 \
    --out results/
```

Full matrix (only the agents that are present will be exercised):

```bash
sudo scripts/compare_runtime_security.sh \
    --agents none,aegisbpf,falco,tetragon,tracee,kubearmor \
    --workload open_close \
    --iterations 200000 \
    --out results/
```

Strict mode — fail loudly if any requested agent is missing:

```bash
sudo scripts/compare_runtime_security.sh \
    --agents none,aegisbpf,falco \
    --strict-missing \
    --out results/
```

The script writes:

- `results/<agent>.json` — raw `perf_open_bench` payload per agent
- `results/results.md` — combined Markdown table

Exit codes:

- `0` — all requested agents ran (or were skipped cleanly)
- `1` — bad arguments, baseline failed, or a peer agent was found running
- `2` — at least one agent ran but failed; with `--strict-missing`, also
  if at least one agent was skipped because it was missing

## Interpreting the results table

A typical `results.md` looks like:

```
| agent     | status | us/op | p50 (µs) | p95 (µs) | p99 (µs) | delta vs none | notes |
|-----------|--------|-------|----------|----------|----------|---------------|-------|
| none      | ok      | 1.18 | 1.16     | 1.22     | 1.41     | —             |       |
| aegisbpf  | ok      | 1.21 | 1.19     | 1.24     | 1.45     | +2.54%        |       |
| falco     | ok      | 1.46 | 1.42     | 1.55     | 2.10     | +23.7%        |       |
| tetragon  | skipped |      |          |          |          |               | tetragon not installed |
```

Reading this correctly:

- **The `delta vs none` column is the only number you should quote.** It
  is the only one that has a defensible meaning in isolation (it is
  measured against a baseline that ran on this exact host minutes
  earlier).
- **Absolute µs numbers are host-specific.** A p50 of 1.18 µs on a
  13th-gen i9 says nothing about a p50 on a c5.large. Do not paste these
  numbers into a public comparison without the host string from the
  `results.md` header.
- **A negative delta inside ±5 % means "within noise".** It does *not*
  mean the agent makes things faster. Anything between roughly −5 % and
  +5 % on a 200 000-iteration run is consistent with noise on this
  workload.
- **A skipped agent is not a missing agent.** A `skipped` row means the
  binary was not on `$PATH`. It is not a measurement of zero overhead.
  Do not pretend a row was zero just because it was skipped.
- **A failed agent is data.** If an agent reproducibly fails to start in
  this configuration, that is itself worth noting in any writeup, with
  the contents of the `notes` column.

## Hall of shame: things you must not do

The following moves are explicitly forbidden when writing comparison
content in this repository:

- **Cross-run number copying.** Numbers from
  `results-2025-12-01/results.md` may not be combined with numbers from
  `results-2026-04-08/results.md`. The host could have been rebooted, the
  kernel patched, or the BPF JIT improved between runs.
- **Cross-host number copying.** Numbers from a CI runner may not be
  combined with numbers from a developer laptop, even if the kernel
  version string matches. Microarchitecture, frequency scaling, and idle
  C-states are not the same.
- **Adding a row by hand.** If a `results.md` row was not produced by
  `compare_runtime_security.sh` in the same run as its peers, it must
  not exist. There is no "ballpark estimate" mode.
- **Inverting "we don't know" into "we are faster".** Marketing-style
  claims like "AegisBPF is 5× faster than $tool" are forbidden unless
  there is a `results.md` in this repository that contains both rows
  from the same run, and the multiplier matches the `delta vs none`
  columns. So far, no such artifact exists.
- **Quoting an upstream blog post.** Numbers from a vendor blog, KubeCon
  talk, or design doc are not measurements of the *current* version of
  that tool on the *current* hardware in question. They cannot be used
  to populate any table in this repository.
- **Tuning the agent under test but not the others.** All agents in a
  run share `--iterations`, the same workload, the same host, and the
  same `taskset` pinning. Tuning aegisbpf with extra flags while leaving
  Falco at defaults is not a fair comparison and will be reverted.

If you find yourself wanting to do one of the above, the answer is:
either run the script for real, or do not publish the comparison.

## What this methodology cannot tell you

Even when run perfectly, `compare_runtime_security.sh` measures **one
microbench on one host on one kernel with each agent in its empty-rules
configuration**. It is silent on:

- **Behavior under load.** Resting overhead is not the same as overhead
  under a real production workload (web server, database, batch job).
- **Memory footprint.** The script does not measure RSS, kernel memory,
  or BPF map memory. `docs/PERFORMANCE.md` covers AegisBPF's footprint
  in isolation; peer-tool footprint is not measured here.
- **Detection coverage.** A faster agent that misses the syscall is
  worse than a slower one that catches it. This script does not score
  detection.
- **Production rule cost.** Every agent in the matrix is measured with
  *no rules*. Real deployments will be more expensive than the numbers
  this script produces.
- **MITRE ATT&CK coverage.** AegisBPF does not ship a technique-mapped
  matrix; comparisons across that axis are out of scope until it does.
- **Stability over time.** Single-shot runs are subject to thermal
  throttling and background drift. For longitudinal claims, run the
  script repeatedly across a working week and report the distribution,
  not a single number.

These gaps are intentional. They are listed here so that anyone reading
a `results.md` can immediately see the boundary of what it claims.

## Related documents

- `docs/PERFORMANCE_COMPARISON.md` — the consumer of this methodology
- `docs/PERF_BASELINE.md` — AegisBPF's standalone CI perf baseline
- `docs/PERFORMANCE.md` — AegisBPF's own performance profile
- `docs/EXTERNAL_VALIDATION.md` — independent review status
- `scripts/compare_runtime_security.sh` — the comparison driver
- `scripts/perf_open_bench.sh` — the underlying microbench
