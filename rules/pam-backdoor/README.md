# PAM Backdoor

Write-protects PAM (Pluggable Authentication Modules) configuration files
and module binaries to prevent authentication backdoor insertion.

## Threat model

PAM backdoors are one of the most dangerous Linux persistence mechanisms
because they operate at the authentication layer itself:

- **Module replacement**: Replacing `pam_unix.so` with a trojanized version
  that accepts a hardcoded "skeleton key" password for any account while
  still authenticating legitimate users normally.
- **Module injection**: Adding a `pam_exec.so` line to `/etc/pam.d/sshd`
  that runs an attacker script on every SSH login, capturing credentials.
- **Config modification**: Changing `/etc/pam.d/sudo` to add
  `auth sufficient pam_permit.so`, granting passwordless sudo to everyone.
- **Security policy tampering**: Modifying `/etc/security/access.conf` to
  allow login from attacker IP ranges.

A PAM backdoor survives password changes, key rotations, and most standard
incident response playbooks that focus on removing SSH keys or killing
processes.

## Coverage

- MITRE: T1556.003 (Pluggable Authentication Modules)
- Scope: PAM configuration (/etc/pam.d), PAM module binaries (all standard
  library paths for x86_64), security policy files (/etc/security/*)
- Out of scope:
  - PAM modules in non-standard locations
  - In-memory PAM module patches (rare, requires ptrace -- see
    `kernel-tampering` pack)
  - NSS (Name Service Switch) module tampering

## False-positive vectors

- Package manager updates to PAM modules (libpam-modules, pam) will be
  blocked. Exempt the package manager's cgroup via `allow_cgroup` or
  pause enforcement during upgrades.
- Authentication configuration changes (adding LDAP/Kerberos/SSSD PAM
  modules) will be blocked. Exempt the configuration management cgroup.
- Security hardening tools (pam_pwquality configuration, fail2ban PAM
  integration) that modify /etc/pam.d/ or /etc/security/ need exemption.
- User password changes via `passwd` may be blocked if they trigger writes
  to /etc/security/. Test in audit mode first.

## How to install

```sh
sudo aegisbpf policy validate rules/pam-backdoor/pam-backdoor.conf
sudo aegisbpf policy apply --reset rules/pam-backdoor/pam-backdoor.conf
```
