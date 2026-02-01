# Upgrade and Migration Guide

This guide covers safe upgrades, rollback, and pinned map migrations.

## Before you upgrade
- Back up applied policy and state:
  - `sudo aegisbpf policy show > /var/lib/aegisbpf/policy.backup`
  - `sudo aegisbpf policy export /var/lib/aegisbpf/policy.export`
  - `sudo aegisbpf stats` (optional snapshot)
- If you enforce policy integrity, compute the new sha256 ahead of time.

## Upgrade steps
1. Install the new binary or package.
2. If systemd units changed: `sudo systemctl daemon-reload`
3. Restart the agent: `sudo systemctl restart aegisbpf`
4. Verify prerequisites: `sudo aegisbpf health`

## Pinned map layout migration
AegisBPF stores a layout version in the pinned `agent_meta` map. If the agent
reports a layout mismatch, reset pinned state and re-apply policy.

Recovery:
1. `sudo systemctl stop aegisbpf`
2. `sudo aegisbpf block clear`
3. Re-apply policy:
   - `sudo aegisbpf policy apply /etc/aegisbpf/policy.conf --reset`
   - Add `--sha256` or `--sha256-file` if you enforce integrity.
4. Start the service.

## Policy format versions
Current policy format is `version=1`.
- Validate new files with `policy lint` before applying.
- For risky changes, roll out in audit mode first by setting
  `AEGIS_MODE=--audit` in `/etc/default/aegisbpf`.

## Rollback
- Policy rollback: `sudo aegisbpf policy rollback`
- Package rollback: reinstall the previous package, then restart the service.

Applied policy snapshots are stored at `/var/lib/aegisbpf/policy.applied` and
`/var/lib/aegisbpf/policy.applied.prev`.
