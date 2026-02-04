# Phase 2 Correctness Evidence

This page is the evidence bundle for **Phase 2: Correctness proof** from
`docs/MATURITY_PROGRAM.md`.

## Scope

Phase 2 targets:

- kernel e2e enforcement confidence
- parser/signature/failure-path regression coverage
- CI execution on multiple kernel targets for enforcement-path changes

## Coverage basis set (anti-test-explosion)

To avoid combinatorial test explosion while still proving correctness, Phase 2
uses a required basis set of bypass-relevant scenarios:

- direct open/read against denied inode
- symlink path to denied inode
- hardlink path to denied inode
- rename of denied inode (same inode identity after move)
- mount/view caveats explicitly documented (`bind mounts`, `OverlayFS`,
  `mount namespaces`)
- privilege caveats explicitly documented (`user namespaces`,
  privileged container workloads)

The first four are enforced by `scripts/e2e_file_enforcement_matrix.sh`; the
remaining caveats are explicit contract boundaries in `docs/THREAT_MODEL.md`
and `docs/POLICY_SEMANTICS.md`.

## Gate-to-evidence mapping

| Phase-2 gate | Evidence |
|---|---|
| `>=30` kernel e2e enforcement checks in CI | `scripts/e2e_file_enforcement_matrix.sh` (45 checks) wired in `.github/workflows/e2e.yml` and `.github/workflows/kernel-matrix.yml` |
| Multi-kernel enforcement-path CI | `kernel-matrix-pr` job in `.github/workflows/kernel-matrix.yml` on `kernel-5.15` + `kernel-6.1` |
| Parser/property fuzz signal for changed parser paths | `parser-fuzz` job in `.github/workflows/ci.yml` using `scripts/run_parser_fuzz_changed.sh` |
| Baseline fuzzing across parser/network/event surfaces | `smoke-fuzz` in `.github/workflows/ci.yml` and deep run in `.github/workflows/nightly-fuzz.yml` |
| Failure-mode regression suite | `failure_modes_contract` CTest entry backed by `tests/check_failure_modes_contract.py` |
| Concrete failure paths covered | `tests/test_policy.cpp`, `tests/test_commands.cpp`, `tests/test_tracing.cpp` |
| Kernel/distro/filesystem execution metadata retained | artifact upload steps in `.github/workflows/e2e.yml` and `.github/workflows/kernel-matrix.yml` (summary JSON + kernel/os/fs metadata) |

## Failure-path inventory (covered)

- parse failure (`PolicyTest.MissingVersion`)
- signature enforcement failures:
  - unsigned with `--require-signature`
  - corrupted bundle signature
- map operation failure (`BpfMapOperationFailed`) with rollback attempt
- rollback failure while preserving original apply error
- BPF load failure and verifier-reject surfaced as daemon load errors

## Operator-facing workflows

- CI: `.github/workflows/ci.yml`
- privileged e2e: `.github/workflows/e2e.yml`
- kernel matrix: `.github/workflows/kernel-matrix.yml`
- nightly fuzz: `.github/workflows/nightly-fuzz.yml`
- kernel evidence artifacts: uploaded from `.github/workflows/e2e.yml` and
  `.github/workflows/kernel-matrix.yml`

## Notes

- Hosted benchmark trend checks are advisory; strict perf gating is handled in
  `.github/workflows/perf.yml` on deterministic self-hosted runners.
