# External Security Review Prep

This checklist prepares the independent review that starts in Super-Phase A.

## Review scope

- Threat-model correctness (`docs/THREAT_MODEL.md`)
- Policy semantics determinism (`docs/POLICY_SEMANTICS.md`)
- Bypass catalog and accepted residual risks
- Kernel attach/degraded-mode behavior
- Signed policy and anti-rollback controls
- Release artifact trust chain (SBOM/provenance/signatures)

## Required evidence pack

- `docs/MARKET_LEADERSHIP_PLAN.md`
- `docs/MARKET_SCORECARD.md`
- `docs/PHASE2_CORRECTNESS_EVIDENCE.md`
- `docs/PHASE3_OPERATIONAL_SAFETY_EVIDENCE.md`
- `docs/PHASE6_META_SECURITY_EVIDENCE.md`
- latest go-live checklist (`docs/GO_LIVE_CHECKLIST.md`)

## Reviewer deliverables

- Findings with severity and exploitability
- Reproduction notes or proof-of-concept paths
- Coverage/bypass assessment with scope boundaries
- Remediation recommendations with priority

## Internal response SLA

- Critical: owner assigned in 24h, mitigation in 7 days
- High: owner assigned in 48h, mitigation in 14 days
- Medium/Low: owner assigned in 5 business days

## Exit criteria

- `0` unresolved critical findings
- High findings have approved remediation plan and due date
- Claim taxonomy updated where findings invalidate current claims
- Updated scorecard row evidence linked in PR/release docs
