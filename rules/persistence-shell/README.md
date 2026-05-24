# Persistence: Shell Profiles

Write-protects shell profile and environment files to block persistence
via malicious commands injected into login/interactive shell initialization.

## Threat model

Shell profile persistence is simple and effective: the attacker appends a
command to `/root/.bashrc` or `/etc/profile.d/backdoor.sh` that runs every
time the user (or any user) opens a shell. Common payloads include:

- A reverse-shell one-liner triggered on every interactive login.
- Environment variable manipulation (`LD_PRELOAD`, `PATH` poisoning) to
  hijack future command execution.
- Modifying `/etc/shells` to enable login for service accounts that are
  normally locked (e.g., `www-data`).

This pack write-protects all standard shell profile locations and the
global environment configuration.

## Coverage

- MITRE: T1546.004 (Unix Shell Configuration Modification)
- Scope: global profiles, root shell profiles, /etc/environment, /etc/shells
- Out of scope:
  - Non-root user shell profiles (`/home/*/.bashrc`). Add these paths
    explicitly for each interactive user account.
  - Fish, tcsh, or other non-bash/zsh shell configurations.

## False-positive vectors

- Dotfile management tools (chezmoi, stow, yadm) that update root's
  shell profiles will be blocked. Exempt their process cgroup.
- Package post-install scripts that drop files into `/etc/profile.d/`
  will fail. Pause enforcement during package upgrades.
- Interactive editing of `/root/.bashrc` for legitimate customization
  will be blocked. Exempt admin sessions as needed.

## How to install

```sh
sudo aegisbpf policy validate rules/persistence-shell/persistence-shell.conf
sudo aegisbpf policy apply --reset rules/persistence-shell/persistence-shell.conf
```
