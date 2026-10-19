# Public Security Evidence Matrix (AegisBPF)

This is an **evidence index**, not an audit report or a certification. A command's presence in a test script does not establish that it ran successfully on a privileged BPF-LSM kernel. Use the **specific CI run URL, tested commit, environment and artifacts** to judge each claim.

## Interpretation

- **Design/specification**: a documented goal or contract, not proof.
- **Automated test**: executable test logic exists, but may be skipped or fail on a given run.
- **Hardware-backed result**: a linked, successful run on a machine with BPF LSM genuinely enabled; include kernel, distro and commit.
- **Independent assessment**: a report prepared by an external reviewer with scope, methods, findings and dates. **None is published as of 2026-10-18**.

## Claims, backing tests, and gaps

| Claim / risk | Design reference | Test or evidence source | Evidence still needed before external assurance |
|---|---|---|---|
| File path and inode denial returns `EPERM` | [Claims C1–C2](ENFORCEMENT_CLAIMS.md) · [Guarantees](GUARANTEES.md) | `scripts/e2e_enforcement_proofs.sh`, `scripts/e2e_file_enforcement_matrix.sh`; [E2E workflow](../.github/workflows/e2e.yml) | Successful BPF-LSM job URL, inode/errno result, kernel information, regression on the supported matrix |
| Cgroup allowlist and scoping | [Claims C3](ENFORCEMENT_CLAIMS.md) · [Threat Model](THREAT_MODEL.md) | `scripts/e2e_enforcement_proofs.sh`, `scripts/e2e_namespace_matrix.sh` | Negative tests proving rules do not leak into other cgroups/namespaces |
| IPv4 deny / bind deny | [Claims C4–C5](ENFORCEMENT_CLAIMS.md) | `scripts/e2e_enforcement_proofs.sh`; [E2E workflow](../.github/workflows/e2e.yml) | Observed policy-associated errno on both allowed and denied cases; separate IPv6 and socket-hook coverage |
| Startup break-glass vs runtime emergency disable | [Claims C6, C9](ENFORCEMENT_CLAIMS.md) · [Emergency controls](EMERGENCY_CONTROL_CONTRACT.md) | `scripts/e2e_enforcement_proofs.sh`; [Recovery runbook](RUNBOOK_RECOVERY.md) | Demonstrated reversal, teardown, recovery after daemon failure, and an operator-reviewed runbook |
| Deadman TTL and survival allowlist | [Claims C7–C8](ENFORCEMENT_CLAIMS.md) | `scripts/e2e_enforcement_proofs.sh`; [CI strategy](CI_EXECUTION_STRATEGY.md) | Timed evidence, negative tests and a privileged runner artifact |
| OverlayFS copy-up and alias handling | [Threat Model](THREAT_MODEL.md) · [Bypass Catalog](BYPASS_CATALOG.md) | `scripts/e2e_fs_matrix.sh`; [Guarantees](GUARANTEES.md) | Reproduce the asynchronous re-propagation window, bound its impact, show surviving bypasses |
| BPF object / signed policy integrity | [Hardening](HARDENING.md) · [Security Audit](SECURITY_AUDIT.md) | [Quality Gates](QUALITY_GATES.md) and repo test inventory | Independent review of key trust, cryptographic API assumptions and release artifact provenance |
| Kernel/distro compatibility | [Compatibility](COMPATIBILITY.md) | [E2E workflow](../.github/workflows/e2e.yml) · [Evidence catalog](EVIDENCE.md) | Dated runs across target distro/kernel/architecture; skips and unsupported hooks explicitly listed |
| Operational reliability and performance | [Quality Gates](QUALITY_GATES.md) · [Production Readiness](PRODUCTION_READINESS.md) | Soak/performance jobs documented in [Evidence](EVIDENCE.md) | Independent reproduced soak results, workload description and recorded rollback failure cases |

## Verification protocol

For each reported run, record:

1. Immutable source commit SHA, test script revision and relevant compiled BPF object hash.
2. Runner type, `uname -a`, distro, architecture, `/sys/kernel/security/lsm`, `/sys/kernel/btf/vmlinux`, cgroup mode, bpftool/libbpf versions.
3. Exact CLI/policy and baseline allow outcome **before** deny installation.
4. Observed return value and errno of the denied operation; a timeout, missing service, `EACCES`, or skipped job is not interchangeable with expected `EPERM`.
5. Release postures: audit vs enforce; degraded-mode reasoning; expected and observed cleanup/rollback.
6. Full workflow URL and retained artifact IDs/checksums. Mark expired/missing CI artifacts **unverified**.
7. Reviewer identity, independence, date, findings, remediations and retests, if present.

## What this document must never be used to claim

- A LinuxLinks, Kube Today or DevSecOps Talks mention is not a security audit.
- Passing standard hosted CI is **not** proof of an enforcing BPF-LSM kernel; the hardware-backed jobs may be capacity-gated or skipped.
- An internal document titled [Security Audit](SECURITY_AUDIT.md) is **not** an independent third-party audit.
- A successful local demo proves only the operation, kernel, and policy under test.
- The absence of published independent findings does not mean a codebase has no vulnerabilities.

See [External Validation](EXTERNAL_VALIDATION.md), [Disclosure Policy](../SECURITY.md) and [Independent Review Brief](INDEPENDENT_REVIEW_BRIEF.md).
