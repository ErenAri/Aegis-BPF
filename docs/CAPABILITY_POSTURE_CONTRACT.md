# Capability/Posture Contract

Status: **normative**

This document is the canonical contract for node capability posture, enforce
gating behavior, and anti-drift checks between runtime code, schema, evaluator,
and Helm defaults.

## Canonical Artifacts

- Runtime report: `/var/lib/aegisbpf/capabilities.json`
- JSON schema: `config/schemas/capabilities_v1.json`
- Posture evaluator: `scripts/evaluate_capability_posture.py`
- Runtime producer: `src/daemon.cpp`, `src/daemon_policy_gate.cpp`,
  `src/daemon_posture.cpp`

## Schema Contract

- `schema_version`: integer compatibility anchor (currently `1`)
- `schema_semver`: semantic contract version (currently `1.8.0`)
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
- `future_lsm`
- `next_gen_bpf`
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
- `ENFORCE_SIGNAL`
- `AUDIT_FALLBACK`
- `DEGRADED`

`ENFORCE_SIGNAL` is the Tier-3 signal-fallback posture: on a host without
BPF-LSM, when the operator opts in with `--enforce-fallback=signal` and the
kernel can deliver `bpf_send_signal` (tracepoints + bpf syscall), the daemon
enforces by **asynchronously killing** a process that performs a denied
`open()`/`connect()` rather than degrading to audit-only. It is strictly weaker
than `ENFORCE` (no synchronous `-EPERM`) and is **distinct from it** so the
No-Pretend invariant holds: `enforce_capable` remains `false` (the
`BPF_LSM_DISABLED` blocker is still reported) and the daemon never claims
`ENFORCE` while it cannot synchronously deny.

`requirements_met` is mandatory and must include:

- `network`
- `exec_identity`
- `exec_runtime_deps`
- `ima_appraisal`

`future_lsm` is mandatory and must include:

- `active_lsms`
- `landlock`
- `landlock_abi`
- `ipe`
- `fs_verity`
- `bpf_token`

These fields are posture evidence, not enforce blockers by themselves. They
let Kubernetes automation and auditors distinguish today's BPF-LSM enforcement
posture from future LSM composition readiness.

`next_gen_bpf` is mandatory and must include:

- `arena`
- `user_ringbuf`
- `sched_ext`
- `open_coded_iterators`
- `xattr_kfuncs`
- `bpf_send_signal_task`
- `binary_auth`

These fields are posture evidence for graduating `prototype/aegis-next`
concepts into mainline: arena-backed provenance, zero-copy policy delivery,
sched_ext quarantine, targeted signal delivery, and fs-verity/xattr-backed
binary authorization.

## No Pretend Enforce Invariant

If enforce prerequisites are unmet:

- `fail-closed` mode: daemon must refuse enforce startup.
- `audit-fallback` mode: daemon must switch to audit mode and emit state-change
  reason code.

No valid path may claim effective enforce behavior while unmet blockers exist.

The failure-mode contract must cover the concrete no-pretend cases:

- Silent partial attach metadata is fatal; the daemon must not continue when
  expected and attached hook counts diverge.
- Missing policy-required network hooks or IMA appraisal must fail closed in
  `fail-closed` mode and emit a state-change reason code.
- When `audit-fallback` mode is explicitly selected, `capabilities.json` must
  report `audit_only=true`, `enforce_capable=false`, `AUDIT_FALLBACK`, and the
  specific unmet blocker such as `NETWORK_HOOK_UNAVAILABLE`.

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
