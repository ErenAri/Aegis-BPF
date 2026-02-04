# Phase 5 Performance Evidence

This page captures evidence for **Phase 5: Performance credibility** from
`docs/MATURITY_PROGRAM.md`.

## Gate-to-evidence mapping

| Phase-5 gate | Evidence |
|---|---|
| Reproducible harness documents CPU/kernel/filesystem/workload profile | `docs/PERF.md` workload profile + noise controls |
| Published p50/p95/p99 overhead for open/connect paths | `scripts/perf_open_bench.sh` and `scripts/perf_connect_bench.sh` output `p50_us`, `p95_us`, `p99_us` |
| Published max sustained event rate and drop threshold behavior | `scripts/soak_reliability.sh`, `.github/workflows/soak.yml`, and target in `docs/MATURITY_PROGRAM.md` (`<0.1%` drops) |
| Benchmark noise controls defined | deterministic self-hosted perf gate in `.github/workflows/perf.yml`; advisory hosted trend in `.github/workflows/benchmark.yml` |

## CI evidence links

- Perf gate workflow:
  - https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/workflows/perf.yml
- Hosted benchmark trend workflow (advisory):
  - https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/workflows/benchmark.yml
- Soak reliability workflow:
  - https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/workflows/soak.yml
