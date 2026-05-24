# File Integrity

Write-protects critical system binary and library directories to prevent
trojanization of OS utilities and dynamic linker hijacking.

## Threat model

Replacing or modifying system binaries is one of the most effective
persistence and stealth techniques:

- **Binary replacement**: Replacing `/usr/bin/ls` or `/usr/bin/ps` with a
  trojanized version that hides attacker processes/files while functioning
  normally for all other operations.
- **PATH hijacking**: Dropping a malicious binary with a common name into
  a directory that appears earlier in PATH.
- **Library hijacking**: Replacing a shared library in `/usr/lib/` to
  inject code into every process that links against it.
- **ld.so.preload poisoning**: Adding a malicious library to
  `/etc/ld.so.preload` so it is loaded into every dynamically-linked
  process on the system.

This pack write-protects all standard binary and library directories plus
the dynamic linker configuration.

## Coverage

- MITRE: T1036.005 (Match Legitimate Name or Location), T1574 (Hijack Execution Flow)
- Scope: /usr/bin, /usr/sbin, /bin, /sbin, /usr/local/bin, /usr/local/sbin,
  /usr/lib, /lib, /etc/ld.so.conf, /etc/ld.so.preload
- Out of scope:
  - Application-specific binary directories (/opt/*, /srv/*)
  - Python/Ruby/Node module directories
  - Container-image layers (immutable by design)

## False-positive vectors

- **Package management**: apt, yum, dnf, and all package managers write to
  these directories during install/upgrade. This is the primary false-positive
  source. Exempt the package manager's cgroup via `allow_cgroup` or pause
  enforcement during maintenance.
- **Software installation**: pip, npm, go install, cargo install that target
  /usr/local/bin will be blocked. Use cgroup exemption for CI/CD.
- **ldconfig**: Updating the linker cache writes to /etc/ld.so.cache (not
  protected) but reads /etc/ld.so.conf (protected). ldconfig itself will
  function; only modifying the conf files is blocked.
- This is an aggressive pack. Deploy in audit mode for at least 48 hours
  before enforcing.

## How to install

```sh
sudo aegisbpf policy validate rules/file-integrity/file-integrity.conf
sudo aegisbpf policy apply --reset rules/file-integrity/file-integrity.conf
```
