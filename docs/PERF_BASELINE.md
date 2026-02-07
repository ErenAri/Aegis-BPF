# Performance Baseline Report

Status: **pending**  
Last updated: 2026-02-06

This report captures the **repeatable performance baseline** used for
credibility claims. It should be updated whenever the perf workflow is run
on the target self‑hosted environment.

## Latest run status

- **Perf Regression (self‑hosted):** last run failed  
  Run: https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/runs/21726758288

> No published baseline yet. We will update this document with a successful
> run, hardware details, kernel version, and p50/p95/p99 results.

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

