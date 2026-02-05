# Performance Harness

This document defines the reproducible performance harness used for Phase 5.

## Workload profile (pinned)

- CPU governor: `performance`
- Target host class: dedicated self-hosted perf runner
- Kernel: captured in CI artifact metadata (`uname -r`)
- Filesystem target: `/etc/hosts` for open/read microbenches
- Network target: loopback (`127.0.0.1`) for connect microbench
- Agent mode: `--audit` for overhead measurement (no deny action side effects)

## Noise controls

- Open benchmark default iterations: `200000`
- Connect benchmark default iterations: `50000`
- Perf gate compares baseline vs with-agent on the same host and run
- Hosted `benchmark.yml` is advisory only; strict gating runs in
  `.github/workflows/perf.yml` on deterministic runners
- Use stable thresholds in `scripts/perf_workload_suite.sh`
- Strict KPI gate: `p95_with_agent / p95_baseline <= 1.05` for both open and
  connect profiles (validated by `scripts/validate_perf_artifacts.py`)

## Benchmarks

### Open/close latency (includes percentiles)

```bash
ITERATIONS=200000 FILE=/etc/hosts scripts/perf_open_bench.sh
WITH_AGENT=1 BIN=./build/aegisbpf ITERATIONS=200000 FILE=/etc/hosts scripts/perf_open_bench.sh
```

Output includes:
- `us_per_op`
- `p50_us`
- `p95_us`
- `p99_us`

### Loopback connect latency (includes percentiles)

```bash
ITERATIONS=50000 scripts/perf_connect_bench.sh
WITH_AGENT=1 BIN=./build/aegisbpf ITERATIONS=50000 scripts/perf_connect_bench.sh
```

Output includes:
- `us_per_op`
- `p50_us`
- `p95_us`
- `p99_us`

### Workload suite gate

```bash
sudo BIN=./build/aegisbpf \
  FILE=/etc/hosts \
  OPEN_ITERATIONS=200000 \
  CONNECT_ITERATIONS=50000 \
  READ_ITERATIONS=50000 \
  STAT_SAMPLE=400 \
  STAT_ITERATIONS=50 \
  MAX_OPEN_PCT=10 \
  MAX_CONNECT_PCT=15 \
  MAX_READ_PCT=15 \
  MAX_STAT_PCT=15 \
  scripts/perf_workload_suite.sh
```

The suite fails if any workload exceeds threshold.

## Event-rate and drop behavior

- Soak reliability and drop-ratio evidence are collected via:
  - `scripts/soak_reliability.sh`
  - `.github/workflows/soak.yml`
- Product reliability target remains `<0.1%` event-drop ratio under sustained
  benchmarked load (see `docs/MATURITY_PROGRAM.md`).

## JSON output

Both open and connect benches support `FORMAT=json` and `OUT=/path`:

```bash
FORMAT=json OUT=/tmp/open.json ITERATIONS=200000 FILE=/etc/hosts scripts/perf_open_bench.sh
FORMAT=json OUT=/tmp/connect.json ITERATIONS=50000 scripts/perf_connect_bench.sh
```

CI stores these JSON profiles as `perf-profiles` artifacts in
`.github/workflows/perf.yml`.

## Artifact schema validation

Perf CI validates artifact schema before upload:

```bash
python3 scripts/validate_perf_artifacts.py \
  --open-baseline artifacts/perf/open_baseline.json \
  --open-with-agent artifacts/perf/open_with_agent.json \
  --connect-baseline artifacts/perf/connect_baseline.json \
  --connect-with-agent artifacts/perf/connect_with_agent.json \
  --workload artifacts/perf/perf_workload.json \
  --report artifacts/perf/perf-evidence-report.md
```

Validation guarantees:
- required JSON keys exist for each profile
- percentile ordering is sane (`p50 <= p95 <= p99`)
- workload suite includes all required rows
  (`open_close`, `connect_loopback`, `full_read`, `stat_walk`)
- with-agent profiles are labeled consistently
- KPI ratios stay within gates:
  - `open_p95_ratio <= 1.05`
  - `connect_p95_ratio <= 1.05`

## Perf artifact contract

Required artifacts for each strict perf run:
- `open_baseline.json`
- `open_with_agent.json`
- `connect_baseline.json`
- `connect_with_agent.json`
- `perf_workload.json`
- `perf_workload.log`
- `perf-evidence-report.md`
- `kernel-info.txt`
- `os-release.txt`
- `cpu-info.txt`
- `fs-type.txt`
