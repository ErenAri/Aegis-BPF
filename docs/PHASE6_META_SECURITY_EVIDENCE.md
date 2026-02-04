# Phase 6 Meta-Security Evidence

This page captures evidence for **Phase 6: Agent meta-security** from
`docs/MATURITY_PROGRAM.md`.

## Gate-to-evidence mapping

| Phase-6 gate | Evidence |
|---|---|
| Signing lifecycle tests cover add/rotate/revoke + anti-rollback | `KeyLifecycleTest.RotateAndRevokeTrustedSigningKeys`, `CmdPolicyApplySignedTest.RejectsRollbackBundleVersion` |
| Release pipeline emits SBOM + signed artifacts + provenance attestations | `.github/workflows/release.yml` (`Generate SBOM`, `Sign artifacts with Cosign`, `actions/attest-build-provenance`) |
| Capability requirements minimized, documented, validated | `SECURITY.md` minimum-capability table and `packaging/systemd/aegisbpf.service` `CapabilityBoundingSet`/`AmbientCapabilities` |

## CI evidence links

- Release pipeline:
  - https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/workflows/release.yml
- Security pipeline:
  - https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/workflows/security.yml
- Key-rotation drill:
  - https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/workflows/key-rotation-drill.yml
