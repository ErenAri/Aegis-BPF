# Product Excellence Plan

This plan turns AegisBPF product-excellence goals into measurable, release-
blocking gates.

## Flagship category and differentiation

Flagship category to win first:

> Inode-first Linux file enforcement for production workloads, with explicit
> semantics, safe rollback, and auditable policy provenance.

Differentiation claims (must be artifact-backed):

1. **Defensible semantics:** policy decisions are deterministic and documented.
2. **Operational survivability:** rollout and rollback are safe under failure.
3. **Low overhead with explainability:** overhead stays bounded and every deny
   decision can be explained.

## Execution model (3 super-phases)

### Super-Phase A - Defensibility Core

Goal: Semantically defensible enforcement.

Workstreams:

- Final threat model and trust-boundary contract (`docs/THREAT_MODEL.md`).
- Final policy semantics contract (`docs/POLICY_SEMANTICS.md`).
- Bypass catalog with disposition (accepted/mitigated/planned).
- Edge-case kernel e2e basis set and replay harness.
- Verifier/CO-RE robustness: attach matrix, feature detection, map-pressure
  behavior.

Numeric gate (all required):

- `>=100` kernel e2e enforcement cases.
- `>=4` kernel targets across `>=2` distro families.
- `0` ambiguous policy decisions in golden decision vectors.
- `0` silent partial attaches (explicit hard-fail or explicit degraded mode).

### Super-Phase B - Production Survivability

Goal: The system does not break production when stressed or misconfigured.

Workstreams:

- Audit-first safe defaults and explicit enforce promotion.
- Canary -> ramp workflows and emergency break-glass controls.
- Atomic policy swap and last-known-good rollback guarantees.
- Degraded-mode contracts for map pressure, ring buffer drops, and logging
  failures.
- Pinned benchmark + soak/reliability tracks.
- Operational observability for attach/enforcement/drop/rollback states.

Numeric gate (all required):

- Rollback success `100%` over `1,000` stress iterations.
- Rollback completion `p99 <= 5s`.
- Unexplained event drops `<0.1%` at declared sustained load.
- Syscall overhead `p95 <= 5%` (stretch target `<=3%`).
- `0` false-green health states (process alive while enforcement inactive).

### Super-Phase C - Trust and Adoption

Goal: External trust signals and real production adoption.

Workstreams:

- Signed policy lifecycle (rotate/revoke/anti-rollback) with drills.
- Signed releases + SBOM + provenance + reproducibility checks.
- Explainability tooling (`why denied` chain) and policy-lint ergonomics.
- Hardened deployment guides (systemd + Kubernetes + air-gapped path).
- Governance and disclosure operations with SLA-backed response.
- Independent review and design-partner pilots.

Numeric gate (all required):

- `0` unresolved critical external-review findings.
- `100%` release artifacts signed with SBOM + provenance attached.
- Explainability coverage for every deny decision class.
- `>=2` pilot environments with weekly evidence reports.

## External validation timing

External validation is not deferred to the end of the program:

- Independent review scoping starts in Super-Phase A.
- Pilot deployments start in Super-Phase B.
- Pilot and reviewer feedback can reprioritize backlog before Super-Phase C
  closes.
- External review prep checklist: `docs/EXTERNAL_REVIEW_PREP.md`.
- External review closure tracker: `docs/EXTERNAL_REVIEW_STATUS.md`.
- Weekly pilot evidence template: `docs/PILOT_EVIDENCE_TEMPLATE.md`.
- Weekly pilot evidence reports: `docs/pilots/`.

## Claim discipline policy

Every externally-visible claim must link to:

1. Spec section
2. Automated test
3. CI artifact
4. Runbook/operator guidance

Claims must be tagged as `ENFORCED`, `AUDITED`, or `PLANNED`.
Unmapped claims are release blockers.

## Program cadence

- Weekly: KPI/status review, risk register update, top-3 blocker burn-down.
- Monthly: claim audit (remove or downgrade unsupported claims).
- Per release: go/no-go uses `docs/RELEASE_READINESS_SCORECARD.md` plus
  `docs/GO_LIVE_CHECKLIST.md`.

## Immediate implementation backlog

1. Lock KPI thresholds in contract tests and release templates.
2. Expand edge-case e2e matrix to satisfy Super-Phase A floor.
3. Harden degraded-mode and rollback tests for Super-Phase B gates.
4. Run pilot onboarding with `docs/PILOT_EVIDENCE_TEMPLATE.md`, publish weekly
   reports in `docs/pilots/`, and track reviewer closure in
   `docs/EXTERNAL_REVIEW_STATUS.md`.
