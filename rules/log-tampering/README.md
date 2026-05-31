# Log Tampering

Write-protects system log files and shell history to preserve forensic
evidence and prevent attackers from covering their tracks.

## Threat model

One of the first post-exploitation actions is covering tracks by:

- Truncating or deleting `/var/log/auth.log` to remove login evidence.
- Clearing `/var/log/wtmp` so `last` shows no record of the intrusion.
- Wiping `~/.bash_history` or symlinking it to `/dev/null`.
- Deleting specific audit log entries to hide privilege escalation.

This pack makes all major log files and history files read-only at the
kernel level. Log daemons (syslog, journald) that need write access
should be exempted via `allow_cgroup`.

## Coverage

- MITRE: T1070.002 (Clear Linux Logs), T1070.003 (Clear Command History)
- Scope: auth logs, syslog, journal, audit logs, login databases, shell history
- Out of scope:
  - Application-specific logs (nginx, apache, postgres)
  - Remote log forwarding (attackers cannot tamper with logs already shipped
    to a SIEM)
  - Non-root user shell history files

## False-positive vectors

- Log rotation (logrotate) will be blocked from rotating protected files.
  Exempt logrotate's cgroup or the log daemon's cgroup via `allow_cgroup`.
- Syslog/rsyslog/journald must be exempted to continue writing logs.
  Add their cgroups to `allow_cgroup`.
- Manual log cleanup during maintenance will be blocked. Pause enforcement
  for the maintenance window.
- Shell history appends during normal interactive use will be blocked for
  root. Exempt root's login cgroup if history preservation is desired
  over tamper-proofing.

## How to install

```sh
sudo aegisbpf policy validate rules/log-tampering/log-tampering.conf
sudo aegisbpf policy apply rules/log-tampering/log-tampering.conf --reset
```
