# CI Workflow Audit — 2026-04-26

This document is a one-time audit of `.github/workflows/`. The
project ships **34 workflows**; this pass categorizes them, flags
staleness, identifies overlap, and proposes consolidation.

It is intentionally non-prescriptive — it documents the current
state and surfaces decisions the maintainers can make. No workflows
are deleted as part of this audit.

## Inventory

| Workflow | Triggers | Runner | Last run | Status | Category |
|---|---|---|---|:---:|---|
| `arm64-production` | push:main, pull_request | `ubuntu-24.04-arm` | 2026-04-25 | ✅ | Build matrix |
| `benchmark` | push, pull_request | `ubuntu-24.04` | 2026-04-25 | ⏳ | Performance |
| `bootstrap-repo-controls` | workflow_dispatch | `ubuntu-latest` | _never_ | — | Repo admin |
| `bpf-compiler-matrix` | push, pull_request | `ubuntu-24.04` | 2026-04-25 | ✅ | Build matrix |
| `bpf-coverage` | push:main, schedule | `ubuntu-24.04` | 2026-04-09 | ✅ | Coverage |
| `branch-protection-audit` | schedule, dispatch | `ubuntu-latest` | 2026-02-23 | ✅ | Repo admin |
| `canary` | schedule (Mon 02:00 UTC), dispatch | **self-hosted bpf-lsm** | 2026-02-23 | ⚠ cancelled | Operational drill |
| `check-vendored` | pull_request paths | `ubuntu-24.04` | 2026-02-15 | ✅ | Supply chain |
| `ci` | push, pull_request | `ubuntu-24.04` | 2026-04-25 | ⏳ | Core test |
| `comparison` | schedule (weekly), dispatch | **self-hosted bpf-lsm** | 2026-04-20 | ⚠ cancelled | Performance |
| `coverage-ratchet` | schedule, dispatch | `ubuntu-latest` | 2026-02-23 | ✅ | Coverage |
| `e2e` | pull_request paths | **self-hosted bpf-lsm** | 2026-02-22 | ⚠ cancelled | E2E test |
| `failure-drill` | schedule (Mon 05:00), dispatch | **self-hosted bpf-lsm** | 2026-02-23 | ⚠ cancelled | Operational drill |
| `go-live-gate` | workflow_dispatch | mixed | _never_ | — | Release gate |
| `helm` | pull_request paths | `ubuntu-24.04` | 2026-02-16 | ✅ | Component test |
| `incident-drill` | schedule, dispatch | mixed | _never_ | — | Operational drill |
| `kernel-bpf-test` | push:main, pull_request | `ubuntu-24.04` | 2026-04-25 | ✅ | Kernel test |
| `kernel-matrix` | workflow_call | mixed | 2026-02-06 | ❌ failure | Kernel test |
| `kernel-matrix-dispatch` | schedule, dispatch | mixed | 2026-02-22 | ⚠ cancelled | Kernel test |
| `key-rotation-drill` | schedule, dispatch | mixed | _never_ | — | Operational drill |
| `label-sync` | schedule, dispatch | `ubuntu-latest` | 2026-02-23 | ✅ | Repo admin |
| `multi-arch` | push:main | `ubuntu-24.04` | 2026-04-25 | ✅ | Build matrix |
| `nightly-fuzz` | schedule | `ubuntu-24.04` | 2026-02-27 | ❌ failure | Fuzzing |
| `operator` | push, pull_request paths | `ubuntu-24.04` | 2026-04-14 | ✅ | Component test |
| `perf` | push:main paths, pull_request paths, dispatch | **self-hosted perf** | 2026-02-22 | ⚠ cancelled | Performance |
| `release` | push tags `v*` | mixed (incl. self-hosted) | 2026-02-16 | ❌ failure | Release |
| `release-branch-guard` | pull_request to release/* | `ubuntu-latest` | _never_ | — | Release gate |
| `release-drill` | schedule (1st of month), dispatch | **self-hosted bpf-lsm** | 2026-02-06 | ❌ failure | Operational drill |
| `release-readiness` | push, pull_request | `ubuntu-24.04` | 2026-04-25 | ⏳ | Release gate |
| `reproducibility` | push:main, pull_request, dispatch | `ubuntu-24.04` | 2026-02-17 | ✅ | Build verify |
| `scorecard` | schedule, push:main, branch_protection_rule | `ubuntu-latest` | 2026-04-25 | ✅ | Supply chain |
| `security` | push, pull_request | `ubuntu-24.04` | 2026-04-25 | ⏳ | Security scan |
| `soak` | schedule, dispatch | **self-hosted bpf-lsm** | 2026-02-22 | ⚠ cancelled | Soak test |
| `veristat` | push:main, pull_request | `ubuntu-24.04` | 2026-04-09 | ✅ | BPF verifier |

Legend: ✅ = succeeded, ❌ = failed, ⚠ = cancelled (typically runner unavailable), ⏳ = in flight at audit time, — = never run.

## Findings

### 1. Self-hosted runner has been unavailable since ~2026-02-22

Every workflow that requires `runs-on: [self-hosted, bpf-lsm]` or
`[self-hosted, perf]` last completed in February. They have not
failed; they have been **cancelled** (the runner never picked them
up, GitHub Actions cancels after the queue timeout):

- `e2e` (e2e tests on real BPF LSM kernel)
- `perf` (performance regression gate)
- `soak` (long-running soak)
- `comparison` (head-to-head vs Falco/Tetragon)
- `canary` (staging canary)
- `failure-drill`, `release-drill` (operational drills)
- `kernel-matrix-dispatch` (per-kernel boot matrix)

This is **the single largest CI gap**. The release pipeline still
ships releases (v0.5.1 was cut 2026-04-23) because `release.yml`
falls back gracefully when the self-hosted job is unreachable, but
the project has been operating without:

- Real-kernel e2e validation on PRs.
- Performance regression gating on PRs.
- Weekly head-to-head benchmark vs Falco/Tetragon.
- Monthly release drills.

**Recommended action:** restore the self-hosted runner, OR
re-architect the heavy workflows around hosted runners. virtme-ng
inside `kernel-bpf-test.yml` already proves real-kernel-on-hosted
is possible; the others could follow that pattern at the cost of
some test fidelity.

### 2. `kernel-matrix` and `release-drill` failed last and never recovered

| Workflow | Last result | Last run |
|---|---|---|
| `kernel-matrix` | ❌ failure | 2026-02-06 |
| `kernel-matrix-dispatch` | ⚠ cancelled | 2026-02-22 |
| `nightly-fuzz` | ❌ failure | 2026-02-27 |
| `release-drill` | ❌ failure | 2026-02-06 |

These are real failures, not infrastructure-availability issues.
They have not been re-run successfully since.

**Recommended action:** open a tracking issue per workflow, decide
whether to fix or remove. A failing workflow that nobody addresses
is worse than no workflow — it teaches contributors to ignore CI
red.

### 3. Five workflows have never run

| Workflow | Trigger | Why probably never fired |
|---|---|---|
| `bootstrap-repo-controls` | dispatch only | One-time setup; not expected to run in normal flow |
| `go-live-gate` | dispatch only | v1.0 GA gate; not yet invoked |
| `incident-drill` | schedule + dispatch | Drill that hasn't been run yet |
| `key-rotation-drill` | schedule + dispatch | Drill that hasn't been run yet |
| `release-branch-guard` | PR to `release/*` | No `release/*` branches exist yet |

`incident-drill` and `key-rotation-drill` are scheduled but appear
not to have fired — verify their cron syntax actually triggers.
The other three are intentional.

### 4. Workflow overlaps worth resolving

| Overlap | Workflows | Recommendation |
|---|---|---|
| Kernel testing on PR | `kernel-bpf-test`, `e2e`, `kernel-matrix` | These are layered (smoke / e2e / matrix) — keep, but document the layering. Currently it's not clear from filenames which is the "blocking" check. Consider renaming to `kernel-pr-smoke`, `kernel-pr-e2e`, `kernel-nightly-matrix`. |
| Performance | `perf`, `benchmark`, `comparison` | `perf` is the SLO gate, `benchmark` is the dev microbench, `comparison` is the vs-peer benchmark. Distinct purposes. Worth a one-paragraph description at the top of each YAML. |
| Coverage | `bpf-coverage`, `coverage-ratchet`, `ci` | `bpf-coverage` covers BPF programs, `coverage-ratchet` covers C++/Go, `ci` runs both. The ratchet is the one that fails on regression — make sure README references it. |
| Drills | `canary`, `failure-drill`, `incident-drill`, `key-rotation-drill`, `release-drill` | Five separate operational drills. They are designed to be infrequent and independent. Keep all five but consider a `drills/` subdirectory for organization (GitHub Actions doesn't actually nest workflows but the prefix helps humans). |
| Release readiness | `release-readiness`, `go-live-gate` | `release-readiness` is per-PR, `go-live-gate` is one-shot for v1.0. Distinct. |
| Repo admin | `bootstrap-repo-controls`, `branch-protection-audit`, `label-sync` | Three workflows for repo administration. Could plausibly merge into one `repo-admin` workflow with multiple jobs, but the gain is small and the split is honest. |

### 5. Trigger-path filtering is inconsistent

Some workflows use `paths:` filters (`check-vendored`, `e2e`,
`helm`, `operator`, `perf`); others run on every push regardless of
what changed (`ci`, `kernel-bpf-test`, `bpf-compiler-matrix`,
`security`). Adding `paths:` filters to the docs-only and
config-only paths in `ci.yml` would noticeably reduce CI minutes
without reducing coverage — `ci.yml` runs ~20 jobs on every PR.

### 6. Workflows referencing this audit will go stale

This document is a snapshot. The 2026-02 vs 2026-04 contrast in
"Last run" is the critical signal. Re-running the inventory in
6 months will tell whether the self-hosted runner gap was
addressed and whether the failed workflows were resolved.

A small follow-up could be `scripts/audit_workflows.sh` that
regenerates the inventory table from `gh run list` output. This
would let the audit be a living artifact rather than a snapshot.

## Proposed near-term actions

Numbered for ease of opening tracking issues. None require code
changes outside `.github/workflows/`.

1. **Decide self-hosted runner fate** (P0). Either restore the
   `bpf-lsm` and `perf` self-hosted runners, or rewrite their
   workflows to use virtme-ng on hosted runners, or document them
   as dispatch-only.
2. **Fix or delete `kernel-matrix`, `nightly-fuzz`, `release-drill`**
   (P1). Last-run failure with no recovery is the worst of both
   worlds.
3. **Cron-verify `incident-drill` and `key-rotation-drill`** (P2).
   They are scheduled but have never fired; check the cron
   expressions and the scheduled-workflow disablement that GitHub
   applies to inactive repos (60-day rule).
4. **Add `paths:` filter to `ci.yml`** (P2). Skip the 20-job ci
   matrix on docs-only PRs.
5. **Document the layering** of kernel tests and performance
   workflows in this file or in `docs/CI_EXECUTION_STRATEGY.md`
   (P3).
6. **Consider `scripts/audit_workflows.sh`** to regenerate this
   inventory (P3). Optional; nice-to-have for quarterly review.

## What this audit explicitly does not do

- Delete any workflows.
- Change any workflow YAML.
- Re-run any failed workflow.
- Disable any scheduled workflow.

The maintainers should make those calls. This audit's job was to
surface the data.

## Refreshing this audit

The "Inventory" table at the top of this document goes stale as
new workflows are added and existing ones change status.
[`scripts/audit_workflows.sh`](../scripts/audit_workflows.sh)
regenerates that table from the live state of the repo:

```bash
scripts/audit_workflows.sh > /tmp/inventory.md
# Diff against the table in this doc and hand-merge.
```

The script reads `.github/workflows/*.yml`, queries `gh run list`
for the most recent run of each workflow, and emits a Markdown
table to stdout. Re-run quarterly (or before any TOC review) and
update the table here. The script does NOT modify this document
in-place — that's deliberate, so the surrounding prose stays
consistent with the data.

## See also

- [`docs/CI_EXECUTION_STRATEGY.md`](CI_EXECUTION_STRATEGY.md) — design
  intent for the workflow split.
- [`docs/PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) — which
  workflows back which production-readiness gates.
- [`docs/QUALITY_GATES.md`](QUALITY_GATES.md) — the contract each
  workflow must uphold.
- [`scripts/audit_workflows.sh`](../scripts/audit_workflows.sh) —
  inventory regeneration helper.
