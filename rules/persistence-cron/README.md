# Persistence: Cron

Write-protects cron and at scheduler configuration directories to block
one of the most common Linux persistence mechanisms.

## Threat model

After gaining access, attackers frequently install cron jobs to maintain
persistence across reboots and service restarts. Common patterns include:

- Adding a line to `/etc/crontab` that downloads and executes a payload
  every few minutes.
- Dropping a file into `/etc/cron.d/` that looks like a legitimate package
  cron job.
- Using `crontab -e` as root to install a per-user cron job in
  `/var/spool/cron/`.
- Scheduling one-shot `at` jobs to re-establish C2 after a delay.

This pack makes all scheduler configuration read-only, blocking new job
installation at the filesystem layer.

## Coverage

- MITRE: T1053.003 (Cron), T1053.001 (At)
- Scope: write-protection of all standard cron/at configuration paths
- Out of scope:
  - Systemd timers (covered by the `persistence-systemd` pack)
  - In-process scheduling (application-level cron libraries)

## False-positive vectors

- Legitimate cron job installation via `crontab -e` or package manager
  post-install scripts will be blocked. Pause enforcement or use
  `allow_cgroup` during maintenance windows.
- Configuration management tools (Ansible cron module, Puppet cron
  resource) need their cgroup exempted.
- Package upgrades that ship cron drop-ins (e.g., logrotate) will fail
  to install their cron jobs until enforcement is paused.

## How to install

```sh
sudo aegisbpf policy validate rules/persistence-cron/persistence-cron.conf
sudo aegisbpf policy apply --reset rules/persistence-cron/persistence-cron.conf
```
