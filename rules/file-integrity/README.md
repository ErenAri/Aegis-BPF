# File Integrity

## Threat model
Prevents modification of critical system binaries in `/usr/bin`, `/usr/sbin`,
`/bin`, `/sbin`, and `/usr/local/bin`. Attackers commonly replace legitimate
binaries with trojanized versions (T1036.005) or hijack shared library loading
paths (T1574).

## Coverage
- MITRE: T1036.005 (Match Legitimate Name or Location)
- MITRE: T1574 (Hijack Execution Flow)
- Scope: read-only protection on system binary directories

## False-positive vectors
- Package manager updates (`apt-get upgrade`, `dnf update`) write to protected paths
- Manual software installation to `/usr/local/bin`
- Workaround: temporarily disable the pack during maintenance windows

## How to install
```sh
sudo aegisbpf policy validate rules/file-integrity/file-integrity.conf
sudo aegisbpf policy apply --reset rules/file-integrity/file-integrity.conf
```
