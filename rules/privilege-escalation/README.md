# Privilege Escalation

Protects sudo and PAM configuration from unauthorized modification and
blocks well-known privilege escalation enumeration and exploitation tools.

## Threat model

Privilege escalation on Linux typically follows a two-step pattern:

1. **Enumeration**: Run a tool like LinPEAS or Linux Exploit Suggester to
   identify misconfigurations (writable SUID binaries, sudo rules, cron
   jobs running as root).
2. **Exploitation**: Abuse the found misconfiguration to gain root access,
   then modify sudoers or PAM to maintain elevated access.

This pack defends both stages:
- Write-protects sudo, PAM, polkit, and security limits configuration.
- Blocks execution of common enumeration and exploitation tools at their
  typical staging paths.

## Coverage

- MITRE: T1548.001 (Setuid and Setgid Permissions), T1548.003 (Sudo and Sudo Caching)
- Scope: sudoers, PAM, polkit config protection; known privesc tool blocking
- Out of scope:
  - Kernel exploits for privilege escalation (see `kernel-tampering` pack)
  - SUID binary abuse on legitimately installed binaries (GTFOBins)
  - Container breakout escalation (see `container-escape` pack)

## False-positive vectors

- Legitimate sudo configuration changes (`visudo`) will be blocked.
  Exempt admin sessions or pause enforcement during changes.
- PAM module installation during package upgrades will fail. Exempt the
  package manager's cgroup.
- Security auditors running LinPEAS or similar tools during authorized
  assessments need cgroup exemption.

## How to install

```sh
sudo aegisbpf policy validate rules/privilege-escalation/privilege-escalation.conf
sudo aegisbpf policy apply --reset rules/privilege-escalation/privilege-escalation.conf
```
