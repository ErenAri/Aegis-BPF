# AegisBPF Production Roadmap (Product Excellence Plan)

This roadmap defines the execution plan to reach a trusted, production-grade
security product. It is intentionally strict: no new surface area is added
until the current phase gates are met.

## Scope Freeze (v1 Golden Contract)

**Contract (v1):**
"Aegis enforces deny decisions for file open/exec using inode-first rules on
selected cgroups, with audited policy provenance and safe rollback."

**Non-goals (v1):**
- Network deny enforcement
- Kill escalation modes
- Broad SIEM integrations
- Multi-surface enforcement beyond file open/exec

These items are planned only after v1 gates are met.

## Phase A — Defensibility Core

**Goal:** Semantically defensible enforcement.

### A1. Versioned Security Contract
- Threat model and trust boundaries
- Explicit non-goals
- TOCTOU stance

**Gate A1:** Contract published and referenced from README.

### A2. Enforcement Semantics Whitepaper (v1)
- Path vs inode authority
- Namespace semantics
- Bind/overlay/rename/link behavior
- Bypass catalog (accepted/mitigated/roadmap)

**Gate A2:** `docs/POLICY_SEMANTICS.md` published and versioned.
**Gate A2:** `docs/BYPASS_CATALOG.md` published and versioned.

### A3. Edge-Case Compliance Suite
- >= 60 enforced e2e scenarios (baseline)
- Coverage basis set: symlink swap, hardlink, rename, overlayfs, mount ns
- Golden policy vectors + deterministic replay

**Gate A3:** Suite passes in CI with 0 failed checks.
**Gate A3:** Scenario count >= 60.
**Gate A3:** `docs/EDGE_CASE_COMPLIANCE_SUITE.md` published.

### A4. Verifier / CO-RE Robustness
- Verifier budget regression tests
- Attach-failure matrix
- Explicit partial-attach states
- BTF detection + clear errors

**Gate A4:** 0 silent partial attaches in tests.

## Phase B — Production Survivability

**Goal:** Will not break production.

### B1. Safe Defaults + Rollback Guarantees
- Audit-first default
- Atomic policy swap + deterministic rollback
- Break-glass tests

**Gate B1:** 100% rollback success in 1,000-iteration stress test.
**Gate B1:** p99 rollback <= 5s.

### B2. Degraded-Mode Contract
- Explicit fail-open/fail-closed per hook
- Map full / ringbuf overflow behavior
- Backpressure + sampling policy

**Gate B2:** 0 undocumented failure modes in tests.

### B3. Performance Credibility
- Pinned methodology (kernel, FS, workload)
- Metrics: p50/p95/p99 overhead, CPU, drop rate
- Soak tests >= 6h

**Gate B3:** p99 syscall overhead < 5% (initial gate).
**Gate B3:** unexplained drop rate < 0.1%.

### B4. Observability + Diagnostics
- Versioned log schema
- Metrics contract
- Enforcement-active signal
- `aegis doctor` CLI

**Gate B4:** doctor passes on 2 kernels.
**Gate B4:** one pilot deployment completed (real environment).
**Gate B4:** external review kickoff (scope + timeline defined).

## Phase C — Trust & Adoption

**Goal:** Externally credible and preferred.

### C1. Meta-Security & Supply Chain
- Mandatory policy signatures in enforce
- Key rotation + revocation drills
- Signed releases + SBOM + provenance

**Gate C1:** signature lifecycle tests pass; SBOM + signatures present.

### C2. UX & Explainability
- Policy linter with fixes
- Dry-run traces
- `aegis explain <event>`

**Gate C2:** time-to-correct-policy <= baseline from 3 pilot users.

### C3. Deployment Hardening
- Hardened systemd / Helm defaults
- Air-gapped install path
- Secrets handling guide

**Gate C3:** production deployment blueprint published.
Blueprint: `docs/PRODUCTION_DEPLOYMENT_BLUEPRINT.md`.

### C4. Governance & Evidence Pack
- Strict DoD for enforcement changes
- CVE workflow + changelog discipline
- Independent security review (mid-cycle)
- Pilot case study (mid-cycle)
- Evidence pack per release (links to CI + artifacts)

**Gate C4:** Evidence pack published for each release.
**Gate C4:** external compliance suite run by third party.

## Execution Strategy (Critical Path)

1) Decide CI realism now:
- Self-hosted runners with fixed kernels (preferred), or
- VM-kernel CI for determinism

2) Pull external validation earlier:
- One pilot and one external review during Phase B

## KPI Summary (Non-negotiable Gates)

- >= 60 enforced e2e scenarios (Phase A baseline)
- >= 100 enforced e2e scenarios (Phase B authority baseline)
- >= 120 enforced e2e scenarios + external run (Phase C)
- >= 4 kernels, >= 2 distro families
- Rollback success 100% (1,000 iterations)
- p99 rollback <= 5s
- p99 syscall overhead < 5% (Phase B gate)
- p99 syscall overhead < 3% (Phase C stretch)
- Unexplained drop rate < 0.1%
- 0 silent partial attaches

## Differentiation KPIs (Adoption Drivers)

At least one of the following must be tracked in pilots:
- Time-to-correct-policy (median minutes)
- Time-to-diagnose-deny (median minutes)
- Operator cognitive load (steps required to resolve incident)

## Reference Enforcement Slice (Decision-Grade)

One inode-first deny path is designated as the decision-grade reference.
It must pass all Phase A/B gates and an independent review before any
expansion of enforcement scope.

Canonical reference: `docs/REFERENCE_ENFORCEMENT_SLICE.md`.

## Differentiation Commitment

At least one adoption KPI must improve by >= Z% vs baseline before any
public excellence claim is made.

## Kill Criteria (Hard Stop Conditions)

- If no pilot expansion or renewal within X months -> scope freeze +
  reassessment.
- If differentiation KPI does not beat baseline by Y% -> reposition or
  narrow use-case.
