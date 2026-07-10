# 168-hour enforce-mode soak (laptop, v0.9.0)

A **7-day continuous BPF-LSM enforcement soak** on real hardware. The agent ran
in `--enforce` mode the entire time with an in-band enforcement canary: a
dedicated file (`/var/tmp/aegis-soak-canary`) was denied, and a read of it was
attempted on every poll — **any** successful read counts as a missed enforcement
decision and fails the soak.

## Result: PASS

| Metric | Value |
|---|---|
| Mode / duration | `enforce` (`--enforce-signal=none`), **604800 s = 168 h** |
| Window (UTC) | 2026-07-03 14:50:18 → 2026-07-10 14:50:28 |
| Build | v0.9.0, commit `dcd6128`, `aegisbpf 0.9.0` |
| Host / kernel | Linux 6.17, x86_64, BPF-LSM active |
| Workers | 16 (tight-loop file reads) + UDP network workload |
| **Enforcement canary** | **0 misses / 57,310 checks** — deny held 100% |
| **RSS growth** | **+784 KB** over 7 days (51,096 → 51,880 KB); budget was 131,072 KB |
| Enforcement decisions | **7,131,132,679** this run (7.13 B) |
| Suspend interruptions | **none** (`suspend_detected: false`) |
| Daemon crashes | 0 (clean exit 0) |

**What this demonstrates:** over a full week of continuous enforcement and 7.1
billion decisions, the agent never once let the denied path through, never
crashed, and grew its RSS by under 1 MB — no memory leak, no enforcement drift.

## Telemetry drops are expected here (and decoupled from enforcement)

`max_drop_ratio_pct` ≈ 21.7% and `ringbuf_drops` are **by design**: the 16
workers read the canary in a tight loop, generating events far faster than the
ring buffer can drain. Telemetry (event emission) is intentionally decoupled from
the enforcement decision (`-EPERM`) — the canary result (0 misses) is the proof
that dropping *telemetry* never drops *enforcement*. This decoupling is exercised
directly in [`../backpressure-saturation-laptop/`](../backpressure-saturation-laptop/).
The telemetry-drop gates were therefore neutralized for this run; the pass
criteria were **enforcement-canary misses = 0, RSS within budget, and daemon
survival**.

## Files

- `soak_summary.json` — machine-readable metrics (`pass: true`).
- `soak.log` — trimmed run log (the 54,957 identical "daemon.log rotated"
  disk-watchdog lines are elided; rotation kept disk bounded for the full run).
- Host snapshot: `kernel.txt`, `lsm.txt`, `cpu.txt`, `os-release.txt`,
  `memory-{start,end}.txt`, `version.txt`, `commit.txt`, `start_utc.txt`,
  `finish_utc.txt`, `exit_code.txt`.

## Reproduce

```
sudo scripts/soak_laptop_168h.sh          # enforce, 168h, private canary, own evidence dir
sudo scripts/soak_status.sh               # live one-shot snapshot while it runs
```

The wrapper overrides the harness default `SOAK_BLOCK_PATH=/etc/hosts` with a
throwaway canary so enforce mode never denies a system path host-wide.
