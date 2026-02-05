# Staging Canary Runbook

This runbook defines how to run staged canary validation before production
release.

## Preconditions

- Staging host mirrors production kernel, cgroup, bpffs, and systemd settings.
- BPF LSM is enabled (`grep -qw bpf /sys/kernel/security/lsm`).
- Candidate binary is built and available as `./build/aegisbpf`.
- No system service instance is already running (`systemctl is-active aegisbpf`).

## Phase 1: Audit canary

Run an audit-only pass first to evaluate false positives without process
termination.

```bash
sudo AEGIS_BIN=./build/aegisbpf \
  PHASE=audit \
  DURATION_SECONDS=300 \
  MAX_RINGBUF_DROPS=100 \
  MAX_EVENT_DROP_RATIO_PCT=0.1 \
  MIN_TOTAL_DECISIONS=100 \
  MAX_RSS_GROWTH_KB=65536 \
  scripts/canary_gate.sh
```

Collect evidence:
- canary log
- health snapshot
- metrics before/after
- false-positive review notes

## Phase 2: Enforce canary

Use `SIGTERM` as the default staged enforcement signal.

```bash
sudo AEGIS_BIN=./build/aegisbpf \
  PHASE=enforce \
  ENFORCE_SIGNAL=term \
  DURATION_SECONDS=300 \
  MAX_RINGBUF_DROPS=100 \
  MAX_EVENT_DROP_RATIO_PCT=0.1 \
  MIN_TOTAL_DECISIONS=100 \
  MAX_RSS_GROWTH_KB=65536 \
  scripts/canary_gate.sh
```

Collect evidence:
- enforce canary log
- blocked-event review (legitimate vs false positive)
- restart and rollback behavior

Safety guard:
- `scripts/canary_gate.sh` rejects `ENFORCE_SIGNAL=kill` unless
  `ALLOW_SIGKILL_CANARY=1` is explicitly set.
- Treat kill-mode canary as exceptional containment testing only, never as the
  standard rollout path.

## Rollback drill

During canary, execute one rollback drill:

1. Apply candidate policy in staging.
2. Trigger a controlled failure case.
3. Validate rollback behavior and post-rollback health.
4. Capture `aegisbpf health --json` and `aegisbpf metrics` output.

## Exit criteria

Canary is considered pass only when:

- Audit and enforce canary phases pass.
- Ring buffer drops, drop ratio, and RSS growth stay below thresholds.
- No critical false positives remain unresolved.
- Rollback drill is validated.

Record final status in the release notes or change ticket.
