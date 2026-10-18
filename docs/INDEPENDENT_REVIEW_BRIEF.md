# Independent Security Review Brief — AegisBPF

**Status:** review scope prepared; **no independent assessment has been commissioned or published here**. This document is an input for a qualified third-party reviewer, not an assertion of certification.

## Objectives

Verify whether the *current shipped artifact* on explicitly supported Linux kernels enforces the documented file/network policies without avoidable bypasses, and whether its recovery mechanisms work under failure. Evaluate the key management, BPF object integrity and operator privilege model within the published [Threat Model](THREAT_MODEL.md).

## Scope for the reviewer

- **Target version:** identify a specific commit and release tag **at the start of the engagement**. Do not silently change the target.
- **User-space:** CLI policy parser, policy-state application, signature verification, key lookup and rollback, daemon lifecycle and deployment privilege boundaries.
- **BPF:** LSM hooks for file/inode, exec identity, network socket operations, map lifetime, namespace/cgroup behavior, and inability to enforce when BPF LSM is absent.
- **Bypass probes:** hardlinks, bind mounts, OverlayFS copy-up/re-propagation timing, alternate syscall paths, TOCTOU, mount namespace aliases and map update races. Distinguish mitigated and accepted residual risk.
- **Recovery:** startup break-glass, `emergency-disable`, deadman TTL, daemon crash/restart and safe policy removal.
- **Distribution:** CI build provenance, dependency management, artifact hashes, signed policies and install-time privilege changes.

**Out of scope unless separately agreed:** kernel compromise, Linux kernel verifier defects, commercial SLA, cloud provider platform guarantees, and claims about competitors.

## Required methodology

1. Review [Threat Model](THREAT_MODEL.md), [Guarantees](GUARANTEES.md), [Bypass Catalog](BYPASS_CATALOG.md), [Claims Matrix](ENFORCEMENT_CLAIMS.md), [Public Evidence Matrix](SECURITY_EVIDENCE_MATRIX.md) and existing internal [Security Audit](SECURITY_AUDIT.md).
2. Build from the pinned SHA; archive SBOM, BPF object hash, exact versions and configuration.
3. Execute the unit tests and privileged BPF-LSM [E2E test suite](../.github/workflows/e2e.yml) on multiple documented kernel environments; capture **pass/fail/skip** by assertion.
4. Develop independent negative/adversarial cases rather than relying only on the project's own tests; record reproduction commands and impact.
5. Assess operational rollback and report whether an enforcement feature silently degrades to audit-only.
6. Privately report sensitive findings through [SECURITY.md](../SECURITY.md). Give maintainers a remediation and retest opportunity, then publish a redacted report by mutual agreement.

## Report deliverables

- Reviewer names and relationship to project; independence declaration; review dates; immutable version / SHA and environments.
- Scope, methodology, exclusions and limitations (what could **not** be assessed).
- Findings with severity, prerequisites, exploitability, reproduction evidence, affected versions and resolution state.
- Retest outcome tied to a fixed commit; **do not** describe a fix as verified unless reproduced.
- Executive summary suitable for linking from [External Validation](EXTERNAL_VALIDATION.md); reviewer-approved public artifact.

## Acceptance criteria for describing a review as independent

A qualified reviewer unaffiliated with project implementation produces a verifiable assessment with its own test evidence and publishes (or authorizes publication of) an identifiable report. Project-maintainer AI-assisted code review, internal CI, media coverage and paid promotional articles **do not qualify**.

No production-security guarantee, endorsement, completed external audit or CNCF certification is asserted by this brief.
