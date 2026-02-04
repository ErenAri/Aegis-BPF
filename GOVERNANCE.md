# Project Governance

## Roles

- **Maintainers**: merge rights, release authority, roadmap accountability.
- **Reviewers**: trusted code review contributors without merge rights.
- **Contributors**: anyone submitting issues, docs, or code changes.
- **Security team**: handles private vulnerability intake and coordinated disclosure.

## Decision process

- **Routine technical changes**: lazy consensus among maintainers.
- **Breaking changes** (policy format, map layout, CLI compatibility): RFC + approval from at least 2 maintainers.
- **Security issues**: handled privately until coordinated disclosure window completes.

## Release ownership

- Maintainers own release quality gate enforcement and final sign-off.
- Release branches (`release/X.Y.x`) accept only critical and security fixes.

## Becoming a maintainer

1. Sustained, high-quality contributions over time.
2. Demonstrated ownership across code, tests, and operations.
3. Nomination by an existing maintainer.
4. Approval by majority of maintainers.

## Repository controls

- Branch protection on `main` with required status checks.
- CODEOWNERS enforced for sensitive paths (security, BPF, release workflows).
- Signed tags required for releases.
