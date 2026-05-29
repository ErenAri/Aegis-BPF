# Data Exfiltration

Blocks common data exfiltration tools and protects sensitive data directories
from unauthorized access. This is an intentionally aggressive pack --
review the false-positive section carefully before deployment.

## Threat model

After compromising a host and escalating privileges, attackers exfiltrate
valuable data using:

- File transfer tools (rclone, rsync, ftp) to move data to external
  storage or attacker infrastructure.
- Encoding utilities (base32, xxd) to prepare data for exfiltration via
  DNS tunneling or HTTP parameter stuffing.
- Direct access to database data directories, TLS private keys, or
  backup archives.

This pack blocks known exfiltration tools and write-protects high-value
data directories. Note that curl and wget are intentionally NOT blocked
here due to extreme false-positive rates; use network-level controls for
those.

## Coverage

- MITRE: T1048 (Exfiltration Over Alternative Protocol), T1567 (Exfiltration Over Web Service)
- Scope: rclone, rsync, FTP clients, encoding tools, data directory protection
- Out of scope:
  - curl/wget (too many legitimate uses; use network egress controls instead)
  - DNS tunneling (requires network-level detection)
  - Exfiltration via legitimate cloud APIs
  - Steganographic exfiltration

## False-positive vectors

- Backup systems using rsync will be blocked. This is a significant
  false-positive source. Exempt backup cgroups via `allow_cgroup` or
  remove the rsync entry if rsync-based backups are in use.
- Cloud sync tools using rclone (e.g., rclone to S3 for backups) need
  exemption.
- Database administrators accessing data directories directly will be
  blocked. Exempt DBA sessions.
- Let's Encrypt certificate renewal (certbot) accesses /etc/letsencrypt
  and needs cgroup exemption.

## How to install

```sh
sudo aegisbpf policy validate rules/data-exfiltration/data-exfiltration.conf
sudo aegisbpf policy apply --reset rules/data-exfiltration/data-exfiltration.conf
```
