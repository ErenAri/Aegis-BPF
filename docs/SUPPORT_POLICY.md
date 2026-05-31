# AegisBPF Support Policy

This document defines release support windows, compatibility commitments, and
deprecation guarantees for production deployments.

## Release Model

- Versioning follows SemVer: `MAJOR.MINOR.PATCH`.
- Release channels:
  - **Stable:** normal production releases.
  - **LTS:** designated yearly minor release with extended support.

## Support Windows

- Stable support: current minor (**N**) and previous minor (**N-1**).
- LTS support: 18 months of security/critical fixes.
- Security fixes are prioritized for all supported releases.

## Compatibility Commitments

- Supported architectures: `x86_64`, `aarch64`.
- Supported distros (initial production target):
  - Ubuntu 22.04+
  - Ubuntu 24.04+
  - RHEL 9+
- Supported kernel families:
  - 5.14+
  - 5.15+
  - 6.1+
  - 6.5+
- Policy format compatibility:
  - Current agent accepts policy `version=1` through `version=6`.
  - `version=6` is required for cgroup-scoped deny sections.
  - Backward compatibility for N-1 policies is required in CI.

## Deprecation Policy

- Deprecations are announced in release notes and changelog.
- Deprecated behavior remains for at least **two minor releases**.
- Removal requires:
  1. migration guidance in `docs/UPGRADE.md`,
  2. replacement path documented,
  3. explicit removal notice in release notes.

## End-of-Life (EOL)

- Unsupported releases receive no security or bug fixes.
- Users should upgrade to a supported minor before filing incidents.

## Incident and Security Expectations

- Incident response runbook: `docs/INCIDENT_RESPONSE.md`
- Key rotation/revocation runbook: `docs/KEY_MANAGEMENT.md`
- Security disclosure process: `SECURITY.md`
