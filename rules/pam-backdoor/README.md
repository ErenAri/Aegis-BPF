# PAM Backdoor

## Threat model
Attackers insert malicious PAM modules or modify PAM configuration to
intercept credentials or bypass authentication entirely. A modified
`pam_unix.so` or a rogue entry in `/etc/pam.d/common-auth` can grant
passwordless root access to any user.

## Coverage
- MITRE: T1556.003 (Pluggable Authentication Modules)
- Scope: read-only protection on PAM config dirs, security config, and PAM
  shared library directories

## False-positive vectors
- Package manager updates to `libpam-*` packages
- Adding new PAM modules (e.g., `pam_google_authenticator`)
- System hardening scripts modifying `/etc/security/limits.conf`
- Workaround: temporarily disable during maintenance

## How to install
```sh
sudo aegisbpf policy validate rules/pam-backdoor/pam-backdoor.conf
sudo aegisbpf policy apply --reset rules/pam-backdoor/pam-backdoor.conf
```
