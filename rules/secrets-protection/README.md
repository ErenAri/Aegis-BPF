# Pack: secrets-protection

Blocks all access to on-disk credential material that attackers reach
for during the privilege-escalation and discovery phases.

## What it blocks

| Category               | Files                                                       | MITRE ATT&CK |
| ---------------------- | ----------------------------------------------------------- | ------------ |
| OS auth databases      | `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`               | T1003.008    |
| SSH host keys          | `/etc/ssh/ssh_host_*_key`                                   | T1552.004    |
| Auth + login logs      | `/var/log/auth.log`, `/var/log/secure`, wtmp/btmp/lastlog   | T1070.002    |
| AWS / Azure / GCP creds| `/root/.aws/credentials` etc. (root profile only)           | T1552.001    |
| Docker / Kube configs  | `/root/.docker/config.json`, `/root/.kube/config`           | T1552.001    |
| K8s service account    | `/var/run/secrets/kubernetes.io/serviceaccount/`            | T1552.005    |
| Kerberos keytabs       | `/etc/krb5.keytab`                                          | T1558.003    |

## Threat model

A workload is compromised; the attacker has shell as a non-privileged
or root user inside a container or on the host. They begin
*Credential Access* (T1003, T1552, T1555) by reading well-known files.
This pack blocks those reads at the LSM layer, so even root cannot
exfiltrate the contents — only authorized callers (sshd, sudo, the
OOM-killer's normal pathways) reach them at all.

## Coverage and limitations

- **Covers**: literal-path reads of well-known credential files by
  any uid.
- **Out of scope**:
  - Per-user credential stores (`~/.aws/credentials` for non-root).
    Add those for each operator account that has cloud creds.
  - Application-specific secret stores (HashiCorp Vault unseal keys,
    `/etc/foo/secrets.yaml`). Add those per deployment.
  - Memory-resident secrets harvested via `/proc/<pid>/maps`. The
    `kernel-tampering` pack's `deny_ptrace` covers most variants.

## False-positive vectors

| Workflow                                                | Affected entry                                  |
| ------------------------------------------------------- | ----------------------------------------------- |
| `useradd`, `passwd`, `chage` (writes to shadow)         | `/etc/shadow`, `/etc/gshadow`                   |
| `kubeadm join`                                          | `/var/run/secrets/kubernetes.io/serviceaccount/`|
| `aws s3` from root shell                                | `/root/.aws/credentials`                        |
| `journalctl --rotate`                                   | `/var/log/auth.log`, `/var/log/secure`          |

For systems where these workflows are part of normal operation, edit
out the offending entries before applying. The dry-run audit step is
mandatory.

## Install

```sh
sudo aegisbpf policy validate rules/secrets-protection/secrets-protection.conf
sudo aegisbpf policy apply rules/secrets-protection/secrets-protection.conf --reset
sudo aegisbpf run --audit
# 24h audit. If clean, enforce.
```
