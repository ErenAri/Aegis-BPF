# Credential Access

Blocks execution of credential dumping tools and protects credential
databases from unauthorized access.

## Threat model

After gaining initial access, attackers attempt to harvest credentials
for lateral movement. Common approaches on Linux include:

- Running MimiPenguin to extract cleartext passwords from process memory
  (GDM, sshd, Apache).
- Using LaZagne to recover credentials from browsers, mail clients, and
  configuration files.
- Reading `/etc/shadow` directly and cracking password hashes offline.
- Sniffing network traffic with tshark/tcpdump to capture credentials
  transmitted in cleartext or via NTLM.

This pack blocks known credential dumping tools at their standard paths
and write-protects the shadow password database.

## Coverage

- MITRE: T1003 (OS Credential Dumping), T1040 (Network Sniffing)
- Scope: blocks known cred-dumping binaries, protects shadow files,
  restricts sniffing tools
- Out of scope:
  - Custom or renamed credential dumping tools
  - In-memory credential theft via ptrace (see `kernel-tampering` pack)
  - Application-level credential stores (browser profiles, keyrings)

## False-positive vectors

- Security teams running authorized penetration tests with these tools
  will be blocked. Exempt their cgroup during the engagement.
- Network troubleshooting with tshark will be blocked. The tcpdump binary
  is protect-only (not denied), so reads are still possible.
- The `unshadow` utility from John the Ripper may be present on security
  audit hosts. Remove its entry if this is a dedicated audit machine.

## How to install

```sh
sudo aegisbpf policy validate rules/credential-access/credential-access.conf
sudo aegisbpf policy apply rules/credential-access/credential-access.conf --reset
```
