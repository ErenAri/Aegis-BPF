# AegisBPF Documentation Index

A categorized map of the `docs/` tree. For a high-level overview start with the
[project README](../README.md); for hands-on walkthroughs see the
[tutorials](../tutorials/); for reproducible trust artifacts see
[evidence/](../evidence/) and the [Public Evidence Pack](EVIDENCE.md).

## Getting Started
- [Why AegisBPF](WHY_AEGISBPF.md)
- [Kubernetes Quickstart](QUICKSTART_K8S.md)
- [AegisBPF Product Baseline](PRODUCT.md)
- [Positioning & Professional-Product Roadmap](POSITIONING.md)
- [AegisBPF vs Other eBPF Runtime Security Tools](PERFORMANCE_COMPARISON.md)
- [Peer Comparison & Soak Testing Roadmap](COMPARISON_AND_SOAK_PLAN.md)
- [Production Deployment Blueprint](PRODUCTION_DEPLOYMENT_BLUEPRINT.md)
- [Production Readiness Checklist](PRODUCTION_READINESS.md)

## Architecture & Design
- [AegisBPF Architecture](ARCHITECTURE.md)
- [Architecture Support Matrix](ARCHITECTURE_SUPPORT.md)
- [Future Architecture: Control Plane, Multi-Tenancy, Canary Rollout](ARCHITECTURE_CONTROL_PLANE.md)
- [Network Layer Design](NETWORK_LAYER_DESIGN.md)
- [BPF Map Schema Reference](BPF_MAP_SCHEMA.md)
- [Policy Semantics](POLICY_SEMANTICS.md)
- [Enforcement Semantics Whitepaper (v1.0)](ENFORCEMENT_SEMANTICS_WHITEPAPER.md)

## Enforcement & Security
- [Enforcement Guarantees](ENFORCEMENT_GUARANTEES.md) · [Guarantees](GUARANTEES.md) · [Enforcement Claims Matrix](ENFORCEMENT_CLAIMS.md)
- [Enforcement Wedge Strategy](ENFORCEMENT_WEDGE_STRATEGY.md)
- [Reference Enforcement Slice](REFERENCE_ENFORCEMENT_SLICE.md)
- [Threat Model](THREAT_MODEL.md)
- [Daemon Hardening](HARDENING.md) · [Memory Safety Posture](MEMORY_SAFETY.md)
- [Cryptographic Security Audit](SECURITY_AUDIT.md) · [Security Fix: TweetNaCl Memory Exhaustion](SECURITY_FIX_TWEETNACL_MEMORY.md)
- [BPF Object Integrity](BPF_OBJECT_INTEGRITY.md) · [BPF Verification Bypass Analysis](BPF_VERIFICATION_BYPASS.md)
- [Bypass Catalog](BYPASS_CATALOG.md)
- [Capability/Posture Contract](CAPABILITY_POSTURE_CONTRACT.md) · [Hook Capability Probe](HOOK_CAPABILITY_PROBE.md)
- [Verified Exec Contract](VERIFIED_EXEC_CONTRACT.md)
- [Emergency Control Contract](EMERGENCY_CONTROL_CONTRACT.md)

## Kernel Compatibility
- [Kernel Compatibility Matrix](KERNEL_COMPAT_MATRIX.md) · [Kernel Matrix Results (Layer A)](KERNEL_MATRIX_RESULTS.md)
- [Compatibility Matrix](COMPATIBILITY.md)
- [BTF Fallback](BTF_FALLBACK.md)

## Operations & Runbooks
- [Monitoring & Alerting Guide](MONITORING_GUIDE.md) · [Metrics Operations](METRICS_OPERATIONS.md)
- [Troubleshooting Guide](TROUBLESHOOTING.md) · [Error Handling Guidelines](ERROR_HANDLING.md)
- [Emergency Recovery Runbook](RUNBOOK_RECOVERY.md) · [Incident Response Runbook](INCIDENT_RESPONSE.md)
- [Staging Canary Runbook](CANARY_RUNBOOK.md) · [Release Drill Runbook](RELEASE_DRILL.md)
- [Capacity Planning](CAPACITY_PLANNING.md)
- [Production Rollout Plan](ROLLOUT_PLAN.md) · [Production Rollout Checklist](../ROLLOUT_CHECKLIST.md)
- [Kubernetes Rollout: Audit + Enforce on Labeled Nodes](K8S_ROLLOUT_AUDIT_ENFORCE.md)
- [Kubernetes RBAC / Break-Glass](KUBERNETES_RBAC.md)
- [Key Management Runbook](KEY_MANAGEMENT.md)
- Alert/incident runbooks: [runbooks/](runbooks/)

## Performance
- [Performance Profile](PERFORMANCE.md) · [Performance Baseline Report](PERF_BASELINE.md) · [Performance Harness](PERF.md)
- [Competitive Benchmark Methodology](COMPETITIVE_BENCH_METHODOLOGY.md) · [Determinism Benchmark](DETERMINISM_BENCHMARK.md)
- [Event Loss and Backpressure](EVENT_LOSS_AND_BACKPRESSURE.md)

## Policy & Rules
- [Policy Format (v1–v6)](POLICY.md) · [Policy Audit & Explainability](POLICY_AUDIT_EXPLAINABILITY.md)
- [SIEM Integration Guide](SIEM_INTEGRATION.md)
- Rule packs: [../rules/](../rules/) · MITRE tag schema: [rules/MITRE_ATTACK_TAG_SCHEMA.md](rules/MITRE_ATTACK_TAG_SCHEMA.md)

## Compliance & Evidence
- [Trust & Evidence Framework](TRUST_EVIDENCE.md) · [Trust & Security Badges](TRUST_BADGES.md)
- [Public Evidence Pack](EVIDENCE.md) · [External Validation](EXTERNAL_VALIDATION.md)
- [Production Readiness Validation Report](VALIDATION_2026-02-07.md)
- [Quality Gates](QUALITY_GATES.md) · [Reproducible Builds](REPRODUCIBLE_BUILDS.md)
- [Edge-Case Compliance Suite](EDGE_CASE_COMPLIANCE_SUITE.md) · [Results](EDGE_CASE_COMPLIANCE_RESULTS.md)
- Framework mappings: [compliance/](compliance/) (CIS, NIST 800-53/190, ISO 27001, PCI-DSS, SLSA, SOC2, OpenSSF)
- [CNCF Sandbox Application](CNCF_SANDBOX_APPLICATION.md)

## Development
- [Developer Guide](DEVELOPER_GUIDE.md) · [API Reference](API_REFERENCE.md)
- [Fuzzing Strategy](FUZZING.md) · [CI Execution Strategy](CI_EXECUTION_STRATEGY.md)
- [Distro Packaging](PACKAGING.md) · [Vendored Dependencies](VENDORED_DEPENDENCIES.md)
- [Rust-parser Shadow & Consensus Runbook](RUST_PARSER_SHADOW.md)
- man page: [man/aegisbpf.1.md](man/aegisbpf.1.md)

## Soak & Testing
- [Extended Soak Testing Guide](SOAK_TESTING_GUIDE.md) · [24-Hour AWS Soak Results](SOAK_24H.md)
- [Real Workload Performance Testing](REAL_WORKLOAD_TESTING.md)

## Roadmap & Reference
- [Roadmap to World-Class eBPF Excellence](ROADMAP_TO_EXCELLENCE.md) · [30-Day Quick Wins](QUICK_WINS_30_DAYS.md)
- [Upgrade and Migration Guide](UPGRADE.md) · [Changelog](CHANGELOG.md)
- [aegis-next User Guide](aegis-next-guide.md)
- [Branch Protection Baseline](BRANCH_PROTECTION.md) · [Helm Enforce Gating Contract](HELM_ENFORCE_GATING_CONTRACT.md)
- [Support Policy](SUPPORT_POLICY.md)
