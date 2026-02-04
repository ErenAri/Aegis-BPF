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
- Coverage report with minimum thresholds
- Required-checks contract validation (`required_checks*.txt` -> workflow contexts)
- Label contract validation (`repo_labels.json` -> workflows/templates references)
- Phase evidence contracts (`phase2_evidence_contract`, `phase3_safety_contract`,
  `phase4_portability_contract`, `phase5_performance_contract`,
  `phase6_meta_security_contract`, `phase7_reviewability_contract`)
- SBOM generation
- Security scans (`dependency-review`, `codeql`, `gitleaks`)
- Benchmark regression policy:
  - PR: advisory signal only
  - Main: advisory trend storage on `gh-pages` (non-blocking on hosted runners)
  - Strict fail-on-regression: `.github/workflows/perf.yml` on deterministic self-hosted perf runners

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
