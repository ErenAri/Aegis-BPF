# External Validation

This document tracks **public, third-party validation** of AegisBPF. We do not
claim independent review unless it is recorded here with a verifiable summary.

## Transparency status (current)

**As of 2026-06-22:** no independent security review has been published and no
external design-partner pilot case study has been published. Internal staging
pilot evidence is tracked in `docs/pilots/`, but it is product-readiness
evidence, not third-party validation. We will update this page immediately when
that changes.

If you are evaluating AegisBPF, assume **no external validation** unless a
dated entry appears under “Published reviews” or “Pilot case studies.”

## Status

- **Independent security review:** not yet published.
- **External design-partner pilot case study:** not yet published.
- **Internal staging pilot evidence:** published in `docs/pilots/`.

## How to contribute a review

If you performed an independent assessment and are willing to share a summary,
email `security@aegisbpf.io` with:

- Scope (commit, tag, or date range)
- Methodology (manual review, fuzzing, deployment test)
- Findings summary (critical/high/medium/low)
- Remediations required (if any)
- Whether the summary can be published

## Published reviews

None yet.

## Pilot case studies

None yet.

## Internal staging pilot evidence

Internal staging pilot reports are published separately in `docs/pilots/`.
They validate pilot onboarding mechanics, weekly evidence capture, and KPI
tracking discipline before design-partner onboarding. They must not be cited as
external validation.

## Pilot case study template (public-safe)

When a pilot is complete, publish a **redacted** case study here:

- Environment (kernel, distro, workload class)
- Policy scope (what was enforced vs audited)
- Mean / p95 / p99 overhead
- Ring buffer drop ratio
- Operational incidents (if any)
- Lessons learned / follow-ups
