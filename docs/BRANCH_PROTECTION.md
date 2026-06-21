# Branch Protection Baseline

This is the minimum protected-branch baseline for `main`.

## Required repository settings

- Require a pull request before merging
- Require approvals (minimum: 1; recommended: 2)
- Dismiss stale approvals when new commits are pushed
- Require conversation resolution before merge
- Require status checks to pass before merging
- Do not allow force pushes
- Do not allow branch deletion

For `release/*` branches, enforce additional guardrails via
`.github/workflows/release-branch-guard.yml`:

- PR must carry `security`, `critical`, or `release-approved` label
- high-risk paths require `release-approved`
- large release PRs require `release-approved`

Repository label definitions are managed in `config/repo_labels.json` and kept
in sync by `.github/workflows/label-sync.yml`.

## Required status checks

Use `config/required_checks.txt` as the source of truth.

Check names are stored as **job names** (for example, `build (ubuntu-24.04)`
or `semgrep`) to match GitHub branch-protection contexts directly.

For protected `release/*` branches, use `config/required_checks_release.txt`.

Every check listed in `config/required_checks.txt` must report on every pull
request. Do not put required checks behind `pull_request.paths` or
`paths-ignore` filters; keep the required job visible and gate expensive work
inside the job.

Privileged `E2E (BPF LSM)` runs on `self-hosted,bpf-lsm` runners. It is
hardware-backed release evidence and can be required for release approval, but
it is not part of the default `main` branch required-check baseline unless
runner capacity is continuously available.

## Audit command

With an admin-capable GitHub token:

```bash
REPO=<owner/repo> BRANCH=main scripts/check_branch_protection.sh
```

This compares configured checks against `config/required_checks.txt` and fails
if any required check is missing.

Audit main + protected release branches together:

```bash
REPO=<owner/repo> scripts/audit_branch_protection_matrix.sh
```

Bootstrap labels + branch protection defaults (dry-run by default):

```bash
REPO=<owner/repo> scripts/bootstrap_repo_controls.py
REPO=<owner/repo> scripts/bootstrap_repo_controls.py --apply
```

Equivalent manual workflow dispatch: `Bootstrap Repo Controls`.

If audit drift is detected in CI, `branch-protection-audit.yml` opens/updates an
issue titled `Branch protection drift detected`.
