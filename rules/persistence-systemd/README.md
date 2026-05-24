# Persistence: Systemd

Write-protects systemd unit files, legacy init scripts, and boot-time
configuration to block service-based persistence mechanisms.

## Threat model

Systemd service persistence is the modern equivalent of the SysV init
backdoor. Attackers create or modify unit files to:

- Install a new service that starts a reverse shell or re-downloads
  malware on every boot.
- Modify an existing service's `ExecStart` to run attacker code before
  or instead of the legitimate daemon.
- Drop a systemd generator that dynamically creates units at boot,
  surviving manual unit file cleanup.
- Write to `/etc/rc.local` for a quick-and-dirty boot persistence path.

This pack write-protects all standard systemd unit directories and legacy
init paths.

## Coverage

- MITRE: T1543.002 (Systemd Service), T1037 (Boot/Logon Init Scripts)
- Scope: write-protection of systemd unit dirs, init.d, rc.local, generators
- Out of scope:
  - Systemd timers used as cron replacements (use `persistence-cron` pack)
  - User-session systemd units in home directories (`~/.config/systemd/`)
  - Container-internal systemd (uncommon but possible)

## False-positive vectors

- Package installation and upgrades that ship systemd units will fail to
  write their unit files. Pause enforcement during package maintenance or
  exempt the package manager's cgroup with `allow_cgroup`.
- `systemctl enable/disable` creates symlinks in `/etc/systemd/system`
  and will be blocked. Exempt admin sessions as needed.
- Configuration management tools that manage systemd units (Ansible
  systemd module) require cgroup exemption.

## How to install

```sh
sudo aegisbpf policy validate rules/persistence-systemd/persistence-systemd.conf
sudo aegisbpf policy apply --reset rules/persistence-systemd/persistence-systemd.conf
```
