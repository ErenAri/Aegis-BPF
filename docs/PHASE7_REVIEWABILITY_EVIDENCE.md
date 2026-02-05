# Phase 7 Reviewability Evidence Pack

This page is the single reviewability index for Phase 7 from
`docs/MATURITY_PROGRAM.md`.

## CI and release evidence links

- CI (build/test/lint/sanitizers):
  - https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/workflows/ci.yml
- Security scans:
  - https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/workflows/security.yml
- Kernel portability matrix:
  - https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/workflows/kernel-matrix.yml
- Perf certification:
  - https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/workflows/perf.yml
- Release build/signing/provenance:
  - https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/workflows/release.yml
- Go-live gate aggregate:
  - https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/workflows/go-live-gate.yml

## Required supporting evidence

- Threat model and boundaries: `docs/THREAT_MODEL.md`
- Policy semantics and caveats: `docs/POLICY_SEMANTICS.md`
- Compatibility claims with CI linkage: `docs/COMPATIBILITY.md`,
  `docs/PHASE4_PORTABILITY_EVIDENCE.md`
- Performance methodology and percentile outputs: `docs/PERF.md`,
  `docs/PHASE5_PERFORMANCE_EVIDENCE.md`
- Agent meta-security proofs (key lifecycle, release signing, capability bounds):
  `docs/PHASE6_META_SECURITY_EVIDENCE.md`
- Market go/no-go scorecard: `docs/MARKET_SCORECARD.md`
- External review closure status: `docs/EXTERNAL_REVIEW_STATUS.md`
- Pilot evidence reports: `docs/pilots/`
- Design artifact sync status: `docs/DESIGN_ARTIFACT_STATUS.md`
- Operational runbooks and incident controls: `docs/runbooks/`,
  `docs/INCIDENT_RESPONSE.md`

## Review policy

- Any unverified claim must be downgraded to `PLANNED` or removed before merge.
- Release-impacting PRs must include evidence links in the PR template.
- Go-live approvals must include evidence links for every checklist item in
  `docs/GO_LIVE_CHECKLIST.md`.
