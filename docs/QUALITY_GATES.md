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
- Kernel e2e matrix summary validation (`scripts/validate_e2e_matrix_summary.py`,
  minimum 100 checks, zero failed checks)
- Coverage report with minimum thresholds
- Required-checks contract validation (`required_checks*.txt` -> workflow contexts)
- Label contract validation (`repo_labels.json` -> workflows/templates references)
- Capability contract validation (`capability_contract`)
- SBOM generation
- Security scans (`dependency-review`, `codeql`, `gitleaks`)
- Benchmark regression policy:
  - PR: advisory signal only
  - Main: advisory trend storage on `gh-pages` (non-blocking on hosted runners)
  - Strict fail-on-regression: `.github/workflows/perf.yml` on deterministic self-hosted perf runners
  - Perf artifact schema validation: `scripts/validate_perf_artifacts.py` in strict perf workflow
  - Strict KPI ratio gates: open/connect `p95_with_agent / p95_baseline <= 1.05`
  - Soak reliability gate enforces event-drop ratio `<0.1%` with minimum decision-event volume

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
