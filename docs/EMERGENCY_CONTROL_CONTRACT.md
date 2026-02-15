# Emergency Control Contract

This document defines the **guarantees** and **operational contract** for
emergency enforcement bypass in AegisBPF.

## Goals

- **Single-command** emergency brake to bypass enforcement immediately.
- **No daemon restart** required for the bypass to take effect.
- **Crash-safe:** bypass state survives daemon crash/restart as long as bpffs pins
  remain mounted.
- **Auditable:** every transition is recorded with who/when/why.
- **Bounded:** audit trail is rotated with capped retention (no unbounded growth).

## Non-Goals

- This is **not an authorization system**. If an attacker has root or equivalent
  cluster privileges, they can toggle emergency state.
- This is **not a reboot-persistent** control (bpffs pins are typically cleared
  on reboot unless your deployment restores them).
- This does not prevent kernel compromise or privileged container escapes.

## Primary Control: `emergency_disable`

### Semantics (Kernel)

`emergency_disable=1` forces **audit behavior** in BPF LSM hooks:
- Deny decisions are bypassed (no `EPERM`).
- Audit/telemetry still emits (events, metrics, counters).

This is intentionally **bypass enforcement only** (visibility is preserved).

### Where It Lives

- Stored in the pinned `agent_config` map (field: `emergency_disable`).
- Checked early in every enforcement path.

## Operator Interface

### CLI

- Disable enforcement:
  - `aegisbpf emergency-disable --reason "TICKET=INC-1234 <short description>"`
- Re-enable enforcement:
  - `aegisbpf emergency-enable --reason "TICKET=INC-1234 mitigation complete"`
- Inspect current state:
  - `aegisbpf emergency-status --json`

`--reason` is required.

Optional hardening:
- `--reason-pattern <regex>` enforces a local policy (for example requiring a
  ticket id) before accepting the toggle.

### Audit Trail (Node-Local)

Files (default paths):
- State snapshot: `/var/lib/aegisbpf/control_state.json`
- Append-only log: `/var/lib/aegisbpf/control_log.jsonl`
- Lock: `/var/lib/aegisbpf/control.lock`

Each **transition** records:
- timestamp (unix seconds)
- uid, pid
- node name (best-effort via `AEGIS_NODE_NAME`, else hostname)
- action (`disable` / `enable`)
- previous + new state
- sanitized reason (length-capped)
- `reason_sha256` = SHA256 of the **raw reason bytes before sanitization**

Rotation is performed **pre-write** and retention is capped by:
- `AEGIS_CONTROL_LOG_MAX_BYTES`
- `AEGIS_CONTROL_LOG_MAX_FILES`

### Concurrency

All state/log writes are guarded by an exclusive `flock()` on
`/var/lib/aegisbpf/control.lock` to prevent corruption from concurrent toggles.

### Spam Guard

- No-op toggles (setting a state that is already active) are ignored and do not
  append to the log.
- Storm detection is exposed via metrics:
  - `aegisbpf_emergency_toggle_transitions_total`
  - `aegisbpf_emergency_toggle_storm_active`

## Related Mechanisms

Break-glass marker files (`/etc/aegisbpf/break_glass` and
`/var/lib/aegisbpf/break_glass`) force audit-only posture at the daemon level.

Operational guidance:
- Prefer `emergency-disable` for **rapid response + audit trail**.
- Keep break-glass marker files as a last-resort fallback if you cannot reach
  the CLI/daemon control plane.

## Minimal Procedure (Recommended)

1. Approval (incident commander + security).
2. Disable: `aegisbpf emergency-disable --reason "TICKET=..."`
3. Verify:
   - `aegisbpf emergency-status --json`
   - `aegisbpf health`
4. Mitigate root cause.
5. Re-enable: `aegisbpf emergency-enable --reason "TICKET=..."`
6. Verify enforcement resumed (health + a small deny probe).

