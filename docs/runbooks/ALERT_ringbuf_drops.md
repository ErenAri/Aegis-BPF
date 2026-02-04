# ALERT: Ring Buffer Drops

## Alert Description and Severity
- **Alert names:** `AegisBPFRingbufDrops`, `AegisBPFHighRingbufDrops`, `AegisBPFEventLossSLOViolation`,
  `AegisBPFNetworkRingbufDrops`, `AegisBPFNetworkEventLossSLOViolation`
- **Severity:** warning/critical depending on threshold
- **Impact:** security events are being lost; observability and forensics coverage degrade.

## Diagnostic Steps
1. Confirm drop counters:
   - `aegisbpf metrics | grep -E 'ringbuf_drops'`
2. Compare event rate vs drop rate in the same window.
3. Check CPU/memory pressure on the host.
4. Validate event consumer output (stdout/journald pipeline).

## Resolution Procedures
1. Increase ring buffer size (`--ringbuf-bytes`) for high-volume environments.
2. Enable sampling (`--event-sample-rate`) during overload windows.
3. Reduce noisy debug collection (avoid persistent `--detailed` metrics scraping).
4. Verify downstream log pipeline backpressure and recover normal throughput.

## Escalation Path
1. On-call SRE for runtime capacity actions.
2. Security engineer if sustained event loss breaches SLO for >15m.
3. Platform team if rollout/config defaults must change globally.

## Post-Incident Checklist
- [ ] Document peak drop rate and duration
- [ ] Record effective mitigation
- [ ] Update sizing guidance for affected environment
- [ ] Add regression test or load profile if issue is repeatable
