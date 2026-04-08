# ISO/IEC 27001:2022 — AegisBPF Control Mapping

This document maps ISO/IEC 27001:2022 Annex A controls to AegisBPF
capabilities, demonstrating how AegisBPF supports organizations pursuing
ISO 27001 certification.

## Annex A — Information Security Controls

### A.5 Organizational Controls

| Control | Title | AegisBPF Capability | Evidence |
|---------|-------|---------------------|----------|
| A.5.15 | Access Control | **Full** | BPF LSM hooks enforce deny rules at kernel level. `allow_cgroup` restricts which workloads bypass deny rules. Policy files document access control intent. |
| A.5.23 | Information Security for Cloud Services | **Partial** | Kubernetes identity enrichment (pod, namespace, service account) provides workload-level attribution in cloud-native deployments. |
| A.5.25 | Assessment and Decision on Information Security Events | **Full** | All block events include full process lineage, cgroup path, and K8s identity for security event triage. Priority ring buffer ensures enforcement events survive high-volume attacks. |
| A.5.28 | Collection of Evidence | **Full** | Structured JSON events via ring buffer provide forensic-grade audit trail. Events include timestamps (kernel monotonic clock), process identity (PID, PPID, exec_id), file identity (inode, device), and K8s context. |

### A.7 Physical Controls

| Control | Title | AegisBPF Capability | Evidence |
|---------|-------|---------------------|----------|
| A.7.4 | Physical Security Monitoring | **—** | Not applicable (AegisBPF operates at OS kernel level). |

### A.8 Technological Controls

| Control | Title | AegisBPF Capability | Evidence |
|---------|-------|---------------------|----------|
| A.8.2 | Privileged Access Rights | **Full** | `deny_bpf` prevents unauthorized BPF program loading. `deny_module_load` prevents kernel module insertion. `deny_ptrace` prevents process memory access. |
| A.8.3 | Information Access Restriction | **Full** | `deny_path` and `deny_inode` rules restrict file access at kernel level. Inode-first policy evaluation provides O(1) lookup regardless of rule count. |
| A.8.4 | Access to Source Code | **Partial** | File deny rules can protect source code repositories. Example: `deny_path /opt/repos/.git/config`. |
| A.8.5 | Secure Authentication | **Partial** | Exec identity verification (`allow_exec_inode`, binary hash allowlists) ensures only known-good binaries execute. Protects credential stores via `deny_path /etc/shadow`. |
| A.8.6 | Capacity Management | **Full** | `aegisbpf footprint` estimates memory requirements. Prometheus metrics expose map utilization. Grafana dashboards provide capacity planning views. |
| A.8.7 | Protection Against Malware | **Full** | File deny rules prevent execution of known-malicious binaries. Network deny rules block C2 channels and mining pool connections. Kernel hooks prevent code injection (ptrace, module loading). |
| A.8.8 | Management of Technical Vulnerabilities | **Partial** | Policy hot-reload enables rapid response to CVE disclosures. Example: `deny_path /usr/lib/vulnerable-lib.so` applied in ~115 ms (median on the 2026-04-08 reference host) without agent restart. |
| A.8.9 | Configuration Management | **Full** | Declarative INI policy files with version tracking. `policy.applied.sha256` provides configuration integrity attestation. Break-glass mechanism for emergency override with audit trail. |
| A.8.15 | Logging | **Full** | All security events emitted as structured JSON. Ring buffer provides kernel-side tamper resistance. SIEM integrations (Splunk, Elastic) for centralized log management. |
| A.8.16 | Monitoring Activities | **Full** | Real-time kernel-level monitoring of file access, network connections, process execution, ptrace, module loading, and BPF program loading. Prometheus metrics + Grafana dashboards. |
| A.8.20 | Networks Security | **Full** | Network deny rules (`deny_ip`, `deny_cidr`, `deny_port`) enforce network boundaries at socket syscall level. Direction-aware rules for egress, bind, listen, accept, and sendmsg. |
| A.8.22 | Segregation of Networks | **Full** | CIDR-based deny rules enforce network segmentation. Combined with cgroup allowlisting, provides per-tenant network isolation. |
| A.8.23 | Web Filtering | **Partial** | Port-based deny rules can block HTTP/HTTPS to specific destinations. IP and CIDR rules can block access to known-bad web infrastructure. |
| A.8.24 | Use of Cryptography | **Partial** | BPF object hash verification (`aegis.bpf.sha256`) ensures program integrity. Ed25519 policy signature verification available. |
| A.8.25 | Secure Development Lifecycle | **Partial** | 200+ unit tests, fuzzing, ASAN/UBSAN/TSAN sanitizer support, CI/CD with coverage tracking. Security-hardened build flags (`-D_FORTIFY_SOURCE=2`, `-fstack-protector-strong`, PIE). |
| A.8.28 | Secure Coding | **Partial** | C++20 with RAII patterns (BpfState), Result<T> error handling, no raw pointer arithmetic. Static analysis via compiler warnings (`-Wall -Wextra -Werror` in release builds). |

## Audit Evidence Artifacts

For ISO 27001 certification audits, produce the following AegisBPF evidence:

### Statement of Applicability (SoA) Evidence

| SoA Item | AegisBPF Artifact | How to Collect |
|----------|-------------------|----------------|
| Access control policy | `policy.applied` | `cat /etc/aegisbpf/policy.applied` |
| Policy integrity | `policy.applied.sha256` | `cat /etc/aegisbpf/policy.applied.sha256` |
| Runtime posture | `capabilities.json` | `aegisbpf capabilities --json` |
| System health | Health check output | `aegisbpf health --json` |
| Operational metrics | Prometheus exposition | `aegisbpf metrics` |
| Event audit trail | JSON events | `journalctl -u aegisbpf --since "30 days ago"` |
| Capacity report | Footprint estimate | `aegisbpf footprint --deny-inodes=N` |

### Continuous Monitoring Evidence

```bash
# Generate ISO 27001 evidence snapshot
aegisbpf health --json > evidence/health-$(date +%Y%m%d).json
aegisbpf capabilities --json > evidence/capabilities-$(date +%Y%m%d).json
cp /etc/aegisbpf/policy.applied evidence/policy-$(date +%Y%m%d).conf
sha256sum evidence/policy-$(date +%Y%m%d).conf > evidence/policy-$(date +%Y%m%d).sha256
```

## Legend

| Rating | Meaning |
|--------|---------|
| **Full** | AegisBPF directly implements this control |
| **Partial** | AegisBPF contributes to this control but may need complementary tools |
| **—** | Not applicable or not implemented |
