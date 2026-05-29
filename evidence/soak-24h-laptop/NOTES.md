# Laptop 24h soak — aborted at ~14.5 h

Status: **aborted** (disk full — not an AegisBPF defect)
Start: 2026-04-18 15:34:13 UTC
Stop:  2026-04-19 06:06:59 UTC (approx)
Elapsed: ~14 h 30 min / 24 h

## Observed while it was running

- **RSS stable.** Initial 50,804 kB → 49,956 kB at ~14.5 h (actually
  down 848 kB; well inside noise). No memory leak signal across
  16 workers + UDP workload on 20-thread i9-13900H.
- **No crashes.** `aegisbpf run --audit` PID stayed up the whole time.
- **systemd-inhibit** held sleep/idle/lid-switch/shutdown the whole time
  as intended. Governor stayed locked to `performance`.

## Why it was stopped

Laptop thermals + we hit a real harness bug: `scripts/soak_reliability.sh`
captures the daemon's full stdout+stderr into `/tmp/.../daemon.log` with
no rate limit (line 115):

```
"${AEGIS_BIN}" run ${DAEMON_MODE_FLAG} --ringbuf-bytes=... >"${DAEMON_LOG}" 2>&1 &
```

At 16 workers on a fast host, daemon log output grew to **~280 GB** in
~14.5 hours, filling the root filesystem. The aegisbpf daemon itself
has flat RSS; the growth is disk-side log capture, not a process leak.

On the AWS `t2.micro` run (4 workers, slower host), the same harness
produced negligible daemon log growth.

## Action items (not in this commit — follow-up PR)

1. **Cap / rotate the daemon.log capture** in `soak_reliability.sh`:
   - Pipe through `head -c <N>` or `logrotate`, or
   - Route daemon stdout to `/dev/null` when it's not being inspected,
     or add a `--log-level` flag that suppresses per-event logging.
2. **Add a pre-flight disk-free check** so the harness bails out before
   filling the root filesystem.
3. **Add a watchdog** that kills the soak if `/` drops below a threshold.

## What was preserved

- Initial host snapshot (kernel / LSM / CPU / OS-release / memory)
- `start_utc.txt` — start timestamp
- `soak.log` — first few lines of the reliability harness
- `tmux-final.txt` — final captured tmux pane (showing stable state)
- Original CPU governor saved to `original-governor.txt` for restore

No `soak_summary.json` because the reliability harness only writes that
on normal completion.
