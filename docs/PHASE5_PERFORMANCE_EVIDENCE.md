# Phase 5 Performance Evidence

This page captures evidence for **Phase 5: Performance credibility** from
`docs/MATURITY_PROGRAM.md`.

## Gate-to-evidence mapping

| Phase-5 gate | Evidence |
|---|---|
| Reproducible harness documents CPU/kernel/filesystem/workload profile | `docs/PERF.md` workload profile + noise controls |
| Published p50/p95/p99 overhead for open/connect paths | `scripts/perf_open_bench.sh` and `scripts/perf_connect_bench.sh` output `p50_us`, `p95_us`, `p99_us`; KPI gate enforces `p95_with_agent / p95_baseline <= 1.05` |
| Published max sustained event rate and drop threshold behavior | `scripts/soak_reliability.sh`, `.github/workflows/soak.yml`, and target in `docs/MATURITY_PROGRAM.md` (`<0.1%` drops) |
| Benchmark noise controls defined | deterministic self-hosted perf gate in `.github/workflows/perf.yml`; advisory hosted trend in `.github/workflows/benchmark.yml` |
| Perf artifact schema is machine-validated | `scripts/validate_perf_artifacts.py` run in `.github/workflows/perf.yml` |

## CI evidence links

- Perf gate workflow:
  - https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/workflows/perf.yml
- Hosted benchmark trend workflow (advisory):
  - https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/workflows/benchmark.yml
- Soak reliability workflow:
  - https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/workflows/soak.yml

## Artifact contract

Each strict perf run must produce:
- latency profiles: `open_baseline.json`, `open_with_agent.json`,
  `connect_baseline.json`, `connect_with_agent.json`
- workload output: `perf_workload.json` and `perf_workload.log`
- schema report: `perf-evidence-report.md`
- environment metadata: `kernel-info.txt`, `os-release.txt`, `cpu-info.txt`,
  `fs-type.txt`

This ensures every published performance claim has reproducible, machine-checked
evidence attached to the workflow run.
