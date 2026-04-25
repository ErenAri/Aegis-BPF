# AegisBPF Adopters

This file lists organizations and projects using AegisBPF. The list exists
because CNCF Incubation, third-party evaluators, and prospective adopters
all want to know who else trusts this software in production or
test/integration environments.

## How to add yourself

We welcome all adopters — production, staging, and test/integration count.
You do **not** need to be a paying customer or a household name; "we run
AegisBPF on our staging cluster as part of evaluating runtime security"
is a valuable data point.

To add your organization:

1. Open a PR editing this file and add a row to the table below.
2. Choose a level (`Production`, `Testing/Integration`, `Evaluation`).
3. Optionally include: cluster scale, kernel version, deployment mode
   (`audit` / `enforce`), what you use it for, and a contact handle.
4. If you would prefer to be listed anonymously, open the PR with a
   placeholder name (e.g., "FinTech-1") and email
   `adopters@aegisbpf.io` (or contact `@ErenAri` directly) so the
   maintainers can verify the entry without exposing your identity.

By adding your organization, you agree that the maintainers may publicly
state that you are an adopter. You may remove your entry at any time by
opening another PR.

## Adopter levels

- **Production** — AegisBPF is part of your production change-management
  surface. Removing it would require a coordinated rollback.
- **Testing/Integration** — AegisBPF runs on long-lived non-production
  infrastructure (staging, CI runners, internal dogfood) where outages
  matter and the agent has been there ≥ 30 days.
- **Evaluation** — short-term install for a specific evaluation;
  may not survive the evaluation window.

## Adopters

| Organization | Level | Use case | Scale | Kernel | Mode | Since | Contact |
|---|---|---|---|---|---|---|---|
| _(your organization here)_ | _Production / Testing / Evaluation_ | _what you use it for_ | _N nodes / pods_ | _e.g. 6.8_ | _audit / enforce_ | _YYYY-MM_ | _@github-handle_ |

## Case studies

Detailed write-ups of production deployments live under
[`docs/case_studies/`](docs/case_studies/). If you would like to author
one (or have us anonymize and write one for you), open an issue.

## Why adopters matter for AegisBPF

- **CNCF maturity ladder.** Sandbox can be granted with no public
  adopters, but Incubation explicitly requires named users in production
  or testing/integration. Graduation requires sustained, cross-industry
  adoption.
- **Procurement diligence.** Enterprise buyers ask "who else runs
  this?" before piloting. A real adopter list shortens that
  conversation.
- **Roadmap signal.** Knowing who runs AegisBPF, on what kernels, and
  in what modes lets the maintainers prioritize compatibility and
  hardening work that matters.

## See also

- [`MAINTAINERS.md`](MAINTAINERS.md) — current maintainers and how to
  reach them.
- [`GOVERNANCE.md`](GOVERNANCE.md) — how decisions are made.
- [`docs/POSITIONING.md`](docs/POSITIONING.md) — where AegisBPF sits in
  the eBPF runtime-security landscape and what's on the roadmap.
- [`docs/PRODUCTION_DEPLOYMENT_BLUEPRINT.md`](docs/PRODUCTION_DEPLOYMENT_BLUEPRINT.md)
  — reference deployment for new adopters.
