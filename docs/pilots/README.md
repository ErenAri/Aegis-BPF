# Pilot Evidence Packs

This folder stores weekly pilot evidence reports used by
`docs/RELEASE_READINESS_SCORECARD.md`.

Rules:
- Keep at least **two active pilot reports** under version control.
- Use file names `pilot-<env>-<yyyywWW>.md`.
- Internal staging pilots are acceptable before design-partner onboarding, but
  must be labeled as `pre-design-partner`.
- Every report must include:
  - rollback success rate
  - rollback p99 duration
  - unexplained event drop ratio
  - silent partial attach incidents
  - syscall p95 delta
  - time-to-correct-policy
  - time-to-diagnose-deny
  - evidence links
