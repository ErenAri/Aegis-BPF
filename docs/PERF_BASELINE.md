# Performance Baseline Report

Status: **current**  
Last updated: 2026-02-15

This report captures the **repeatable performance baseline** used for
credibility claims. It should be updated whenever the perf workflow is run
on the target self‑hosted environment.

Hosted `benchmark.yml` trends are advisory and intentionally tolerant to
shared-runner noise. Promotion decisions use self-hosted `perf.yml` evidence.

## Latest run status

- **Perf Regression (self‑hosted):** last run success  
  Run: https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/runs/22043845474

## Baseline environment

- **Hardware:** 13th Gen Intel(R) Core(TM) i9-13900H (20 CPUs)  
- **Kernel + distro:** Ubuntu 24.04.3 LTS, Linux 6.14.0-37-generic  
- **Filesystem:** /tmp on ext2/ext3

## Baseline results (self-hosted perf gate artifacts)

Open/close microbench (audit-only, empty deny policy):

- baseline_us_per_op: `1.37`
- with_agent_us_per_op: `1.34`
- delta_pct: `-2.19%` (budget: `<= 10%`)

Percentile profiles (with agent):

- open p50/p95/p99 (us): `1.22` / `1.26` / `1.47`
- connect p50/p95/p99 (us): `2.16` / `3.22` / `4.60`

KPI gates:

- open_p95_ratio: `0.787500` (target <= `1.050000`)
- connect_p95_ratio: `0.993827` (target <= `1.050000`)

Workload suite rows (delta_pct, budget <= 15%):

- open_close: `11.94%`
- connect_loopback: `-3.31%`
- full_read: `2.55%`
- stat_walk: `0.00%`

## Required baseline fields

When a successful run exists, record:
- **Hardware:** CPU model, cores, RAM, storage
- **Kernel + distro:** exact versions
- **Workload profile:** open/close microbench + workload suite
- **Overhead:** p50 / p95 / p99 syscall latency delta
- **Drop rate:** ring buffer drops under load
- **CPU impact:** mean and p95 CPU overhead under workload

## How to produce a baseline

Use the perf workflow:

```
gh workflow run perf.yml --ref main
```

Then link the run and attach the artifact summary here.
