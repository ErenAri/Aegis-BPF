# AegisBPF Maturity Program

This document turns product-readiness goals into objective, testable phase
gates.

## Golden contract (Phase 0 freeze)

For the 100-point push, the flagship guarantee is:

> AegisBPF blocks unauthorized file opens/reads using inode-first enforcement
> for selected workloads (cgroup-targeted), with safe rollback and auditable
> signed policy provenance.

Scope control:
- No expansion of enforcement surface until this contract is proven across
  stated kernels/distros.
- Network and kill-escalation capabilities remain secondary to this contract.

## Phase 0: MVP freeze and success metrics

The program is considered successful only if all targets below are met:

- **Correctness:** zero known bypasses within declared scope.
- **Portability:** pass matrix on at least 4 kernel targets across at least 2
  distro families.
- **Operational safety:** rollback completes in <5s for typical policy change,
  break-glass verified, canary gating enforced.
- **Performance:** p99 overhead target met on pinned workload profile.
- **Reliability:** event-drop ratio <0.1% at sustained benchmarked load.

## Claim taxonomy

All product claims must be tagged as one of:

- **ENFORCED:** kernel denies operation in current release.
- **AUDITED:** operation is observed and logged, but not denied.
- **PLANNED:** not currently shipped; roadmap only.

Rules:
- Never mix enforced/audited/planned behavior in one statement without labels.
- README, API docs, and runbooks must use the same labeling.

## Phase 1: Product contract

Definition of done:
- Threat model, non-goals, and bypass acceptance list are versioned and linked
  from `README.md`.
- Policy semantics spec defines precedence, inode/path behavior, and namespace
  caveats.
- Claim taxonomy is documented and applied to user-facing feature statements.
- Evidence pack exists at `docs/PHASE1_PRODUCT_CONTRACT_EVIDENCE.md` and is
  enforced by `phase1_product_contract`.

## Phase 2: Correctness proof

Definition of done:
- At least 100 kernel e2e enforcement tests run in CI.
- Basis-set scenarios (direct/symlink/hardlink/rename) are mandatory and
  versioned in Phase-2 evidence.
- CI executes on at least 2 kernel targets for enforcement-path changes.
- Parser/property fuzzing runs nightly and on-demand for changed parsers.
- Failure-mode regression suite covers map-full, verifier reject, load failure,
  parse/signature failure, and rollback failure.
- Kernel/distro/filesystem execution metadata is retained as CI artifacts.

## Phase 3: Operational safety

Definition of done:
- Safe rollout controls exist: audit-only, canary scope, break-glass.
- Kill behavior is behind compile-time and runtime gates, default off, and
  rate-limited.
- Canary workflows enforce staged `ENFORCE_SIGNAL=term`; kill-mode canary is
  explicitly blocked unless a dedicated override is supplied.
- Rollback path is load-tested over >=1000 stress iterations and measured
  (<5s target for standard policy updates).
- Agent crash behavior and recovery are tested and documented.

Evidence bundle: `docs/PHASE3_OPERATIONAL_SAFETY_EVIDENCE.md`.

## Phase 4: Portability proof

Definition of done:
- CI matrix covers >=4 kernel targets across >=2 distro families.
- Runtime feature detection tests cover LSM/BTF/cgroup-v2/bpffs availability.
- Compatibility table is backed by CI evidence links, not manual assertions.

Evidence bundle: `docs/PHASE4_PORTABILITY_EVIDENCE.md`.

## Phase 5: Performance credibility

Definition of done:
- Reproducible harness documents CPU, kernel, filesystem, workload profile.
- Published p50/p95/p99 overhead for open/connect paths.
- Published max sustained event rate and drop threshold behavior.
- Benchmark noise controls defined (repetitions/min-time/tolerance bands).
- Perf artifacts are schema-validated and attached to workflow evidence.

Evidence bundle: `docs/PHASE5_PERFORMANCE_EVIDENCE.md`.

## Phase 6: Agent meta-security

Definition of done:
- Signing lifecycle tests cover key add/rotate/revoke + anti-rollback.
- Release pipeline emits SBOM + signed artifacts + provenance attestations.
- Capability requirements are minimized, documented, and validated via CI
  artifacts (`key-rotation-summary.json`, `capability-contract-report.md`).

Evidence bundle: `docs/PHASE6_META_SECURITY_EVIDENCE.md`.

## Phase 7: Evidence pack and reviewability

Definition of done:
- Single readiness page links to CI runs, benchmark artifacts, threat model,
  runbooks, and compatibility evidence.
- Any unverified claim is downgraded to planned or removed.
- Release review checklist requires evidence links before approval.

Evidence bundle: `docs/PHASE7_REVIEWABILITY_EVIDENCE.md`.

## CI execution strategy

This program depends on deterministic privileged test infrastructure.
Implementation details live in `docs/CI_EXECUTION_STRATEGY.md`.

## Super-phase execution overlay

For market-leadership execution, the phase gates above are grouped into three
delivery tracks:

- **Super-Phase A (Defensibility Core):** contract semantics + kernel
  correctness + verifier robustness
- **Super-Phase B (Production Survivability):** safe operations + degraded-mode
  behavior + performance/reliability
- **Super-Phase C (Trust and Adoption):** supply-chain trust + explainability +
  deployment hardening + external validation

Detailed execution plan:

- `docs/MARKET_LEADERSHIP_PLAN.md`

Release-go/no-go scorecard:

- `docs/MARKET_SCORECARD.md`
