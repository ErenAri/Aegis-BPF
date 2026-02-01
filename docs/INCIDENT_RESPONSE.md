# Incident Response Runbook

This runbook assumes the agent is managed by systemd and events are emitted as
JSON either to stdout or journald.

## Quick triage
- Service status: `systemctl status aegisbpf`
- Logs (journald): `journalctl -u aegisbpf -n 200 --no-pager`
- Health check: `sudo aegisbpf health`
- Block counters: `sudo aegisbpf stats` or `sudo aegisbpf metrics`

## Identify the offender
Events include `pid`, `ppid`, `cgid`, `comm`, `path`, and `action`.
- `policy show` to view the active policy.
- `block list` to inspect deny entries.
- `policy export` to map allowlisted cgroups to paths.

## Mitigation options
1. Temporary allowlist: `sudo aegisbpf allow add /sys/fs/cgroup/<service>`
2. Remove a deny entry: `sudo aegisbpf block del /path`
3. Update the policy and re-apply: `sudo aegisbpf policy apply <file> --reset`
4. Switch to audit mode:
   - Edit `/etc/default/aegisbpf` and set `AEGIS_MODE=--audit`
   - `sudo systemctl restart aegisbpf`
5. Emergency stop: `sudo systemctl stop aegisbpf`

## Evidence collection
- `journalctl -u aegisbpf --since "<time>" > /var/lib/aegisbpf/aegisbpf.log`
- `sudo aegisbpf policy show > /var/lib/aegisbpf/policy.applied.backup`
- `sudo aegisbpf metrics --out /var/lib/aegisbpf/metrics.prom`
- `sudo aegisbpf stats > /var/lib/aegisbpf/stats.txt`
- `sudo aegisbpf policy export /var/lib/aegisbpf/policy.export`
