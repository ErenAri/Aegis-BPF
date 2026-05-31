# Pack: ssh-hardening

Locks down the SSH server's configuration surface and the
`authorized_keys` files attackers most frequently abuse to backdoor a
host.

## What it protects

| Path                                                      | Why                                                      | MITRE ATT&CK |
| --------------------------------------------------------- | -------------------------------------------------------- | ------------ |
| `/etc/ssh/sshd_config`, `sshd_config.d/`                  | Re-enable password auth, weaken ciphers, allow root login | T1556        |
| `/etc/pam.d/sshd`                                         | Bypass PAM auth chain                                    | T1556        |
| `*/systemd/system/ssh{,d}.service`                        | Substitute the daemon binary or args                     | T1543.002    |
| `/root/.ssh/authorized_keys{,2}`                          | Drop a permanent backdoor key                            | T1098.004    |

`protect_path` makes these read-only for non-allow-listed callers; the
`sshd` daemon and `systemd` itself remain functional.

## Threat model

Persistence after a privilege escalation typically uses one of:

- Adding an attacker public key to `/root/.ssh/authorized_keys`.
- Editing `sshd_config` to enable password auth or root login, then
  `systemctl reload ssh`.
- Replacing the systemd unit so the next reboot starts a backdoored
  binary instead of the system `sshd`.

This pack closes those routes at the file-access layer.

## Coverage and limitations

- **Covers**: filesystem-level tamper of the listed paths.
- **Out of scope**:
  - Per-operator `~/.ssh/authorized_keys` for non-root accounts.
    Extend the `protect_path` list to enumerate every interactive
    operator's homedir explicitly.
  - In-memory `sshd` patches (rare; defeated by signature checks on
    the binary itself — see `protect_runtime_deps`).
  - Secrets exfiltration of host keys; that is covered by the
    `secrets-protection` pack.

## False-positive vectors

| Workflow                                          | Affected entry                          |
| ------------------------------------------------- | --------------------------------------- |
| `ssh-copy-id` from a trusted operator             | `/root/.ssh/authorized_keys`            |
| `apt-get` upgrading `openssh-server`              | `*/systemd/system/ssh{,d}.service`      |
| Configuration management (Ansible, Puppet, Salt)  | `/etc/ssh/sshd_config`                  |

Either pause AegisBPF (`systemctl stop aegisbpf`) for legitimate
config-management runs, or use `allow_cgroup` to exempt the
config-management agent's cgroup.

## Install

```sh
sudo aegisbpf policy validate rules/ssh-hardening/ssh-hardening.conf
sudo aegisbpf policy apply rules/ssh-hardening/ssh-hardening.conf --reset
sudo aegisbpf run --audit
# 24h audit. If clean, enforce.
```

Enumerate every interactive operator's `authorized_keys` before
applying:

```sh
for h in /home/*; do
  test -f "$h/.ssh/authorized_keys" && echo "$h/.ssh/authorized_keys"
done >> /etc/aegisbpf/policy.d/ssh-hardening-extra.conf
```
