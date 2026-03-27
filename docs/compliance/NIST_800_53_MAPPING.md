# NIST SP 800-53 Rev. 5 — AegisBPF Control Mapping

This document maps NIST SP 800-53 Rev. 5 security controls to AegisBPF
capabilities, demonstrating how AegisBPF supports federal compliance
requirements for information system security.

## Access Control (AC)

| Control | Title | AegisBPF Capability | Implementation |
|---------|-------|---------------------|----------------|
| AC-3 | Access Enforcement | **Full** | BPF LSM hooks enforce deny rules at kernel level. `file_open` and `inode_permission` hooks block unauthorized file access before syscall completion. |
| AC-3(8) | Revocation of Access Authorizations | **Full** | Policy hot-reload via `aegisbpf policy apply` immediately revokes access without restart. Shadow map swap ensures atomic policy updates. |
| AC-4 | Information Flow Enforcement | **Full** | Network deny rules (`deny_ip`, `deny_port`, `deny_cidr`) enforce information flow boundaries at the socket syscall level. |
| AC-6 | Least Privilege | **Partial** | Cgroup-based allowlisting (`allow_cgroup`) restricts which processes can bypass deny rules. Exec identity verification ensures only known-good binaries receive elevated trust. |
| AC-6(1) | Authorize Access to Security Functions | **Full** | `deny_bpf` policy prevents unauthorized BPF program loading. `deny_module_load` prevents kernel module insertion. |
| AC-6(9) | Log Use of Privileged Functions | **Full** | All block events include process identity, cgroup path, and exec lineage. Kernel block events (ptrace, module_load, bpf) are logged with full attribution. |
| AC-17 | Remote Access | **Partial** | Network deny rules can restrict SSH, VPN, and remote management protocol access. |

## Audit and Accountability (AU)

| Control | Title | AegisBPF Capability | Implementation |
|---------|-------|---------------------|----------------|
| AU-2 | Event Logging | **Full** | All security-relevant events (blocks, exec, network denials, kernel security) are emitted as structured JSON events via ring buffer. |
| AU-3 | Content of Audit Records | **Full** | Events include: timestamp, PID, PPID, process lineage (`exec_id`, `parent_exec_id`), cgroup path, action taken, rule type, and optional K8s identity (pod, namespace, service account). |
| AU-3(1) | Additional Audit Information | **Full** | Forensic events include: UID/GID, binary inode/device, exec stage, verified_exec status, and exec_identity_known flag. |
| AU-6 | Audit Record Review, Analysis, and Reporting | **Partial** | Prometheus metrics (`aegisbpf metrics`) provide aggregate analysis. Grafana dashboards enable visual review. SIEM integrations (Splunk, Elastic) support automated analysis. |
| AU-8 | Time Stamps | **Full** | Events use kernel monotonic clock (`bpf_ktime_get_ns()`) for ordering. `start_time` enables process lifetime correlation. |
| AU-9 | Protection of Audit Information | **Full** | Ring buffer is kernel-side (tamper-resistant from userspace). Priority buffer ensures enforcement events survive telemetry shedding. Backpressure metrics expose event loss. |
| AU-12 | Audit Record Generation | **Full** | BPF hooks generate audit records at the kernel boundary, before any userspace process can interfere. Dual-path backpressure ensures critical events have priority delivery. |

## Configuration Management (CM)

| Control | Title | AegisBPF Capability | Implementation |
|---------|-------|---------------------|----------------|
| CM-5 | Access Restrictions for Change | **Full** | Config directory permissions are validated on startup (`validate_config_directory_permissions`). Break-glass mechanism provides emergency policy override with full audit trail. |
| CM-6 | Configuration Settings | **Full** | Policy files are declarative INI with version tracking. `policy.applied` and `policy.applied.sha256` provide configuration state attestation. |
| CM-7 | Least Functionality | **Full** | Deny rules explicitly define allowed functionality. Everything not in an allow_cgroup is subject to deny rules. Kernel module and BPF program loading can be disabled. |

## Identification and Authentication (IA)

| Control | Title | AegisBPF Capability | Implementation |
|---------|-------|---------------------|----------------|
| IA-9 | Service Identification and Authentication | **Partial** | Exec identity verification (`allow_exec_inode`, binary hash allowlists) provides binary-level authentication. K8s identity enrichment adds pod/namespace/service account attribution. |

## Incident Response (IR)

| Control | Title | AegisBPF Capability | Implementation |
|---------|-------|---------------------|----------------|
| IR-4 | Incident Handling | **Full** | Block events with full process lineage enable incident investigation. Priority ring buffer ensures enforcement events survive high-volume attacks. State change events provide degradation timeline. |
| IR-5 | Incident Monitoring | **Full** | Real-time monitoring via ring buffer events. Prometheus metrics for aggregate monitoring. Grafana Threat Hunting dashboard for anomaly detection. |
| IR-6 | Incident Reporting | **Full** | SIEM integrations (Splunk HEC, Elastic ECS) enable automated incident reporting. Journald integration provides system-level audit trail. |

## System and Communications Protection (SC)

| Control | Title | AegisBPF Capability | Implementation |
|---------|-------|---------------------|----------------|
| SC-4 | Information in Shared Resources | **Partial** | Cgroup isolation ensures per-tenant policy enforcement in multi-tenant environments. |
| SC-7 | Boundary Protection | **Full** | Network deny rules (`deny_ip`, `deny_cidr`, `deny_port`) enforce network boundaries at the socket syscall level. Socket connect, bind, listen, accept, and sendmsg hooks provide comprehensive coverage. |
| SC-7(5) | Deny by Default / Allow by Exception | **Full** | AegisBPF's deny-list model blocks specified resources. Combined with exec identity's allowlist model, this provides deny-by-default for unauthorized processes. |

## System and Information Integrity (SI)

| Control | Title | AegisBPF Capability | Implementation |
|---------|-------|---------------------|----------------|
| SI-3 | Malicious Code Protection | **Full** | File access deny rules prevent execution of known-malicious binaries. Network deny rules block C2 channels and mining pool connections. Kernel hooks prevent ptrace injection and module loading. |
| SI-4 | System Monitoring | **Full** | Real-time kernel-level monitoring of file access, network connections, process execution, ptrace, module loading, and BPF program loading. |
| SI-4(2) | Automated Tools and Mechanisms for Real-Time Analysis | **Full** | BPF programs execute at kernel boundary with nanosecond-level response time. Hook latency is tracked and exposed via Prometheus metrics. |
| SI-4(4) | Inbound and Outbound Communications Traffic | **Full** | Socket hooks monitor all TCP/UDP traffic. Direction-aware rules distinguish egress, bind, listen, accept, and sendmsg. |
| SI-4(5) | System-Generated Alerts | **Full** | Prometheus alerting rules (`prometheus-alerts.yml`) provide automated alerts for: high block rate, ring buffer drops, degraded state, map capacity, hook latency, and policy integrity. |
| SI-7 | Software, Firmware, and Information Integrity | **Full** | BPF object hash verification (`aegis.bpf.sha256`) ensures BPF program integrity. Exec identity verification ensures binary integrity. Layout version checking prevents map schema drift. |
| SI-16 | Memory Protection | **Partial** | `deny_ptrace` prevents process memory inspection/modification. `deny_bpf` prevents BPF-based memory access. |

## Legend

| Rating | Meaning |
|--------|---------|
| **Full** | AegisBPF directly implements this control |
| **Partial** | AegisBPF contributes to this control but may need complementary tools |
| **—** | Not applicable or not implemented |

## Audit Evidence Collection

For compliance audits, the following AegisBPF artifacts serve as evidence:

1. **Policy files**: `policy.applied`, `policy.applied.sha256` — Configuration baseline
2. **Capability report**: `capabilities.json` — Runtime posture attestation
3. **Prometheus metrics**: `aegisbpf metrics` — Operational status
4. **Health check**: `aegisbpf health --json` — System integrity verification
5. **Event logs**: Structured JSON via stdout/journald — Audit trail
6. **Grafana dashboards**: Visual audit evidence for review boards
