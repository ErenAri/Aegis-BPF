# Phase 3 Operational Safety Evidence

This page captures evidence for **Phase 3: Operational safety** from
`docs/MATURITY_PROGRAM.md`.

## Gate-to-evidence mapping

| Phase-3 gate | Evidence |
|---|---|
| Safe rollout controls (audit/canary/break-glass) | `.github/workflows/canary.yml`, `.github/workflows/go-live-gate.yml`, `scripts/canary_gate.sh`, `docs/CANARY_RUNBOOK.md`, `docs/runbooks/RECOVERY_break_glass.md` |
| SIGKILL behind compile/runtime gates, default off, rate-limited | `-DENABLE_SIGKILL_ENFORCEMENT=ON` (build gate), `run --enforce-signal=kill --allow-sigkill` (runtime gate), existing escalation controls `--kill-escalation-threshold` + `--kill-escalation-window-seconds` |
| Canary guardrail against self-DoS | `scripts/canary_gate.sh` rejects `ENFORCE_SIGNAL=kill` unless `ALLOW_SIGKILL_CANARY=1` |
| Guardrail regression tests for kill gating | `TracingTest.DaemonRunGuardsSigkillBehindBuildAndRuntimeFlags`, `cli_run_rejects_sigkill_without_allow_gate` |
| No silent partial attach states (false-green prevention) | `daemon_run` logs `Attach contract validation failed` and hard-fails when attach metadata from `attach_all` is incomplete; regression test `TracingTest.DaemonRunRejectsSilentPartialAttachContract` |
| Break-glass fail-safe behavior covered by tests | `TracingTest.DaemonRunForcesAuditOnlyWhenBreakGlassActive` |
| Rollback path load-tested with <5s target | `PolicyRollbackTest.RollbackControlPathCompletesWithinFiveSecondsUnderLoad` (1,000 rollback attempts, enforced under 5s budget) |
| Agent crash behavior tested + documented | `.github/workflows/incident-drill.yml`, `scripts/collect_incident_bundle.sh`, `docs/INCIDENT_RESPONSE.md`, `docs/runbooks/INCIDENT_agent_crash.md` |

## Notes

- Default builds keep SIGKILL enforcement disabled unless explicitly enabled at
  configure time.
- Runtime use of SIGKILL requires explicit operator acknowledgement with
  `--allow-sigkill`.
- Daemon startup hard-fails if attach metadata reports fewer active file hooks
  than requested (prevents false-green "process alive, enforcement inactive"
  states).
- Incident drill artifacts are uploaded in CI for recovery-path auditability.
