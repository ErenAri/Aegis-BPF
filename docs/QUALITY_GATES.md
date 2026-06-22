# Quality Gates

This project enforces quality gates through required CI checks on `main`.

## Required gates

- Build matrix (`ubuntu-22.04`, `ubuntu-24.04`)
- Test suite (`ctest`)
- Sanitizers (`asan`, `ubsan`, `tsan`)
- Lint (`clang-format`, `cppcheck`)
- Clang-Tidy (changed C++ files)
- Semgrep (changed C/C++ files; full scan on schedule)
- Smoke fuzzing (60s per fuzz target on PR/main)
- BPF compiler matrix (`bpf-compile (clang-15..18)`), with required jobs
  reporting on every PR and expensive BPF work gated inside the job
- Coverage report with minimum thresholds
- Required-checks contract validation (`required_checks*.txt` -> workflow contexts)
- Label contract validation (`repo_labels.json` -> workflows/templates references)
- Capability contract validation (`capability_contract`)
- SBOM generation
- Security scans (`dependency-review`, `codeql`, `gitleaks`)
- Failure-mode regression contract, including parser/signature failures,
  map-full rollback, BPF load/verifier failures, silent partial attach
  rejection, network/IMA degraded-mode gates, no-pretend capability reporting,
  strict degrade fail-closed, and 1,000-attempt rollback stress under a 5s
  budget
- Release KPI threshold contract:
  - Rollback reliability | `100%` over `1,000`
  - Rollback speed | `p99 <= 5s`
  - Unexplained event drops | `<0.1%`
  - Syscall overhead (p95) | `<=5%`
  - p95 ratio gates (`<=1.05`) for open/connect perf profiles
- Benchmark regression policy:
  - PR: advisory signal only
  - Main: advisory trend storage on `gh-pages` (non-blocking on hosted runners)
  - Hosted trend comparison uses filtered benchmark rows:
    - `mean` aggregates only
    - rows `<50ns` excluded
    - high-signal families from `config/benchmark_focus_patterns.txt`
  - Strict fail-on-regression: `.github/workflows/perf.yml` on deterministic self-hosted perf runners
  - Canonical SLO table gate: `scripts/perf_slo_check.sh` (`perf-slo-report.md`)
  - Perf artifact schema validation: `scripts/validate_perf_artifacts.py` in strict perf workflow
  - Strict KPI ratio gates: open/connect `p95_with_agent / p95_baseline <= 1.05`
  - Soak reliability gate enforces event-drop ratio `<0.1%` with minimum decision-event volume

## Hardware-backed gates

Privileged enforcement E2E runs in `E2E (BPF LSM)` on `self-hosted,bpf-lsm`
runners and includes:

- file-enforcement matrix
- filesystem matrix
- namespace matrix
- kernel e2e matrix summary validation (`scripts/validate_e2e_matrix_summary.py`,
  minimum 100 checks, zero failed checks, required coverage categories)

These jobs are release evidence and may be required by release approvers, but
they are not part of the default `main` branch required-check baseline unless
the self-hosted runner fleet is continuously available.

Self-hosted PR jobs are capacity-gated by repository variable:
`AEGIS_ENABLE_SELF_HOSTED_PR_GATES=true`. When the variable is absent or false,
PR-triggered self-hosted jobs are skipped before runner allocation; release
approvers must treat that state as missing privileged evidence, not as a passed
kernel/e2e gate.

## Coverage ratchet policy

Coverage thresholds are enforced in CI and should only move upward:

- Start from an enforceable baseline.
- Raise thresholds when sustained coverage exceeds the current floor.
- Never lower thresholds without an explicit incident-level justification.

Threshold configuration lives in `config/coverage_thresholds.json`.
Automated recommendation workflow: `.github/workflows/coverage-ratchet.yml`.

## Branch protection source of truth

`config/required_checks.txt` is the authoritative list for required status checks.
The workflow `branch-protection-audit.yml` validates repository protection against that list.
Release branch required checks are tracked in `config/required_checks_release.txt`.
Required checks must report on every pull request; workflows for required jobs
must not use `pull_request.paths` filters.
`scripts/validate_ci_workflow_policy.py` additionally prevents PR-triggered
self-hosted jobs from queueing without the explicit capacity gate.
