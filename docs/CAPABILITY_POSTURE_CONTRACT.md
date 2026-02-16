# Capability/Posture Contract

Status: **normative**

This document is the canonical contract for node capability posture, enforce
gating behavior, and anti-drift checks between runtime code, schema, evaluator,
and Helm defaults.

## Canonical Artifacts

- Runtime report: `/var/lib/aegisbpf/capabilities.json`
- JSON schema: `config/schemas/capabilities_v1.json`
- Posture evaluator: `scripts/evaluate_capability_posture.py`
- Runtime producer: `src/daemon.cpp`

## Schema Contract

- `schema_version`: integer compatibility anchor (currently `1`)
- `schema_semver`: semantic contract version (currently `1.2.0`)
- Consumers must reject malformed payloads and treat unknown versions as
  non-compliant posture.

## Required Top-Level Fields

`capabilities.json` must include:

- `schema_version`
- `schema_semver`
- `generated_at_unix`
- `kernel_version`
- `capability`
- `audit_only`
- `enforce_capable`
- `enforce_blockers`
- `runtime_state`
- `lsm_enabled`
- `core_supported`
- `features`
- `hooks`
- `policy`
- `requirements`
- `requirements_met`
- `exec_identity`
- `state_transitions`

## Enforce Blockers

`enforce_blockers` is authoritative for why enforce posture is not achievable.
Known blocker codes:

- `CAPABILITY_AUDIT_ONLY`
- `BPF_LSM_DISABLED`
- `CORE_UNSUPPORTED`
- `BPFFS_UNMOUNTED`
- `NETWORK_HOOK_UNAVAILABLE`
- `EXEC_IDENTITY_UNAVAILABLE`
- `EXEC_RUNTIME_DEPS_HOOK_UNAVAILABLE`
- `IMA_APPRAISAL_UNAVAILABLE`

## Runtime State Contract

Valid `runtime_state` values:

- `ENFORCE`
- `AUDIT_FALLBACK`
- `DEGRADED`

`requirements_met` is mandatory and must include:

- `network`
- `exec_identity`
- `exec_runtime_deps`
- `ima_appraisal`

## No Pretend Enforce Invariant

If enforce prerequisites are unmet:

- `fail-closed` mode: daemon must refuse enforce startup.
- `audit-fallback` mode: daemon must switch to audit mode and emit state-change
  reason code.

No valid path may claim effective enforce behavior while unmet blockers exist.

## Helm Defaults Contract

Helm defaults must preserve fail-closed posture semantics:

- `agent.enforceGateMode=fail-closed`
- `agent.requireEnforceReadiness=true`
- `deployment.mode=auto` (audit-first unless explicitly promoted)
- enforce placement constrained by `enforceNodeSelector`

## CI Contract Gates

The following checks must stay green for release quality:

- capability/posture cross-file drift check
- schema/sample validation
- Helm posture contract check
- observability contract check
- guarantees contract check
