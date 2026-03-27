# PCI DSS 4.0 — AegisBPF Control Mapping

This document maps PCI DSS v4.0 requirements to AegisBPF capabilities,
demonstrating how AegisBPF supports cardholder data environment (CDE)
protection in payment processing infrastructure.

## Applicable Requirements

### Requirement 1 — Install and Maintain Network Security Controls

| Requirement | Description | AegisBPF Capability | Implementation |
|-------------|-------------|---------------------|----------------|
| 1.2.5 | All services, protocols, and ports allowed are identified, approved, and have a defined business need | **Full** | `deny_port` rules explicitly enumerate blocked ports/protocols. Direction-aware rules distinguish egress, bind, listen, accept, and sendmsg. Policy files document approved services. |
| 1.3.1 | Inbound traffic to the CDE is restricted to only that which is necessary | **Partial** | Network deny rules block unauthorized inbound connections. `deny_ip` and `deny_cidr` restrict source addresses at the socket syscall level. |
| 1.3.2 | Outbound traffic from the CDE is restricted to only that which is necessary | **Full** | Egress deny rules (`deny_port:tcp:egress`, `deny_cidr:egress`) enforce outbound restrictions. Blocks data exfiltration channels (FTP, IRC, Telnet). |
| 1.4.2 | Inbound traffic from untrusted networks to trusted networks is controlled | **Full** | `deny_cidr` rules enforce network segmentation at kernel level. Socket hooks intercept all TCP/UDP connection attempts before they complete. |

### Requirement 2 — Apply Secure Configurations

| Requirement | Description | AegisBPF Capability | Implementation |
|-------------|-------------|---------------------|----------------|
| 2.2.5 | All insecure services, protocols, and ports are disabled or secured | **Full** | `deny_port` blocks FTP (20/21), Telnet (23), unencrypted SMTP (25), and other insecure protocols. See `examples/policies/compliance-pci-dss.conf`. |
| 2.2.7 | All non-console administrative access is encrypted | **Partial** | Can block unencrypted remote access protocols (Telnet, rsh). SSH key protection via `deny_path /root/.ssh/id_*`. |

### Requirement 6 — Develop and Maintain Secure Systems and Software

| Requirement | Description | AegisBPF Capability | Implementation |
|-------------|-------------|---------------------|----------------|
| 6.3.3 | All security vulnerabilities are addressed | **Partial** | Policy hot-reload enables rapid mitigation of CVEs. Deny rules can block access to vulnerable library paths within minutes of disclosure. |
| 6.4.1 | Public-facing web applications are protected against attacks | **Partial** | Network deny rules can restrict outbound connections from web-facing workloads. Cgroup-based isolation limits attack surface per service. |

### Requirement 7 — Restrict Access to System Components

| Requirement | Description | AegisBPF Capability | Implementation |
|-------------|-------------|---------------------|----------------|
| 7.2.1 | Access control model is defined and includes coverage for all system components | **Full** | Declarative policy files define access control for file, network, and kernel operations. `allow_cgroup` provides workload-level access grants. |
| 7.2.2 | Access is assigned to users, including privileged users, based on job classification and function | **Partial** | Cgroup-based allowlisting maps to service identities. Per-namespace policies in Kubernetes provide role-based enforcement. |
| 7.2.5 | All application and system accounts and related access privileges are assigned and managed | **Full** | Exec identity verification restricts which binaries execute. `deny_path /etc/shadow`, `/etc/gshadow` protects credential stores. |

### Requirement 8 — Identify Users and Authenticate Access

| Requirement | Description | AegisBPF Capability | Implementation |
|-------------|-------------|---------------------|----------------|
| 8.3.1 | All user access to system components for users and administrators is authenticated | **Partial** | Exec identity verification (`allow_exec_inode`) authenticates binaries at the kernel level. Process lineage (exec_id, parent_exec_id) provides process-level attribution. |
| 8.3.2 | Strong cryptography is used to render all authentication factors unreadable during transmission and storage | **Partial** | `deny_path` protects credential files (/etc/shadow, database configs). Network deny rules block unencrypted authentication protocols. |
| 8.6.2 | Passwords/passphrases for application and system accounts are not hardcoded | **Partial** | File deny rules can protect config files containing credentials. Example: `deny_path /etc/mysql/debian.cnf`. |

### Requirement 10 — Log and Monitor All Access

| Requirement | Description | AegisBPF Capability | Implementation |
|-------------|-------------|---------------------|----------------|
| 10.2.1 | Audit logs are enabled and active for all system components | **Full** | All security events emitted as structured JSON. BPF hooks generate audit records at kernel boundary. Ring buffer ensures continuous event capture. |
| 10.2.1.1 | Audit logs capture all individual user access to cardholder data | **Full** | `deny_path` and `deny_inode` hooks log all access attempts to protected files, including PID, UID, process name, and cgroup path. |
| 10.2.1.2 | Audit logs capture all actions taken by any individual with root or administrative privileges | **Full** | All enforcement actions are logged regardless of UID. Process lineage tracking identifies privilege escalation chains. |
| 10.2.1.5 | Audit logs capture all changes to identification and authentication credentials | **Full** | `deny_path /etc/shadow`, `/etc/gshadow`, `/etc/pam.d/*` log all access attempts to authentication stores. |
| 10.2.2 | Audit logs record: user identification, type of event, date and time, success or failure, origination of event, identity or name of affected data/component | **Full** | Events include: PID, UID (user ID), event type, kernel timestamp, action (blocked), comm (process name), path/IP (affected resource), cgroup (origination). |
| 10.3.1 | Read access to audit log files is limited to those with a job-related need | **Full** | Ring buffer is kernel-side (tamper-resistant from userspace). `deny_path /var/log/audit/*` protects log files from unauthorized access. |
| 10.3.2 | Audit log files are protected from modifications and unauthorized access | **Full** | BPF ring buffer in kernel memory is tamper-resistant. Priority buffer ensures enforcement events have guaranteed delivery. Config directory permissions validated on startup. |
| 10.3.3 | Audit log files are promptly backed up to a centralized log server | **Full** | SIEM integrations (Splunk HEC, Elastic ECS) forward events in real-time. OpenTelemetry OTLP exporter enables centralized trace collection. |
| 10.4.1 | Audit logs are reviewed at least once daily | **Partial** | Prometheus alerting rules provide automated review. Grafana dashboards enable visual audit log review. SIEM integration supports scheduled review workflows. |
| 10.5.1 | Retain audit log history for at least 12 months | **Partial** | AegisBPF generates events; retention is managed by downstream systems (Splunk, Elastic, S3 archival). Journald retention configurable. |

### Requirement 11 — Test Security of Systems and Networks Regularly

| Requirement | Description | AegisBPF Capability | Implementation |
|-------------|-------------|---------------------|----------------|
| 11.3.1 | Internal vulnerability scans are performed | **Partial** | Policy conflict detection identifies security gaps. Capability report (`aegisbpf capabilities`) provides posture assessment. |
| 11.5.1 | File integrity monitoring (FIM) or change detection mechanisms are deployed | **Full** | BPF LSM hooks detect all file access at kernel level. `deny_inode` rules track access to specific file inodes. Block events provide change detection evidence. |
| 11.5.1.1 | FIM/change detection alerts on unauthorized modifications to critical files | **Full** | All blocked access attempts generate immediate events with full process attribution. Prometheus alerting rules trigger on block rate anomalies. |
| 11.5.2 | Network intrusion detection / intrusion prevention mechanisms are deployed | **Full** | Socket hooks monitor all TCP/UDP traffic. Network deny rules function as kernel-level IPS. Block events include source/destination IP, port, protocol, and direction. |

## Example PCI DSS Policy

See `examples/policies/compliance-pci-dss.conf` for a ready-to-deploy
policy implementing the controls above.

## Audit Evidence Matrix

| PCI Requirement | AegisBPF Artifact | Collection Command |
|-----------------|-------------------|-------------------|
| Req 1 (Network) | Active network deny rules | `aegisbpf policy show \| grep deny_port\|deny_ip\|deny_cidr` |
| Req 7 (Access) | Active file deny rules | `aegisbpf policy show \| grep deny_path\|deny_inode` |
| Req 8 (Auth) | Exec identity config | `aegisbpf capabilities --json \| jq '.exec_identity'` |
| Req 10 (Logging) | Event sample | `journalctl -u aegisbpf --since "24 hours ago" \| head -100` |
| Req 10 (Integrity) | Policy hash | `cat /etc/aegisbpf/policy.applied.sha256` |
| Req 11 (FIM) | Block statistics | `aegisbpf stats --detailed` |
| Req 11 (IDS) | Network block stats | `aegisbpf metrics \| grep net_block` |

## Legend

| Rating | Meaning |
|--------|---------|
| **Full** | AegisBPF directly implements this requirement |
| **Partial** | AegisBPF contributes but may need complementary tools |
