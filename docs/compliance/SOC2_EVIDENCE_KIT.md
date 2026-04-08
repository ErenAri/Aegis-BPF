# SOC 2 Type II — AegisBPF Evidence Kit

This document maps SOC 2 Trust Services Criteria (TSC) to AegisBPF
capabilities and provides guidance for collecting audit evidence during
SOC 2 Type II examinations.

## Trust Services Criteria Mapping

### CC6 — Logical and Physical Access Controls

| Criteria | Description | AegisBPF Capability | Evidence Collection |
|----------|-------------|---------------------|---------------------|
| CC6.1 | Logical access security software, infrastructure, and architectures | **Full** | BPF LSM hooks enforce deny rules at the kernel boundary, below all userspace access control layers. Policy files define access control intent declaratively. |
| CC6.2 | Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users | **Partial** | Exec identity verification (`allow_exec_inode`) restricts which binaries can execute. `allow_cgroup` limits which process groups bypass deny rules. |
| CC6.3 | The entity authorizes, modifies, or removes access to data, software, and other protected information assets | **Full** | Policy hot-reload via `aegisbpf policy apply` immediately changes access rights. `policy.applied.sha256` provides change tracking. Break-glass mechanism provides emergency override with audit trail. |
| CC6.6 | Logical access security measures against threats from sources outside its system boundaries | **Full** | Network deny rules (`deny_ip`, `deny_cidr`, `deny_port`) enforce boundaries at socket syscall level. Direction-aware rules for egress filtering. |
| CC6.8 | The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software | **Full** | File deny rules prevent malicious binary execution. `deny_module_load` prevents kernel module insertion. `deny_bpf` prevents unauthorized BPF programs. `deny_ptrace` prevents code injection. |

### CC7 — System Operations

| Criteria | Description | AegisBPF Capability | Evidence Collection |
|----------|-------------|---------------------|---------------------|
| CC7.1 | Detection and monitoring procedures to identify changes to configurations, security vulnerabilities, and introduction of malicious software | **Full** | Real-time kernel-level monitoring of all file access, network connections, process execution, and kernel security events. State change events track configuration modifications. |
| CC7.2 | The entity monitors system components and the operation of those components for anomalies | **Full** | Prometheus metrics expose operational telemetry. Grafana dashboards visualize anomalies. PrometheusRule alerts on: high block rate, ring buffer drops, degraded state, map capacity. |
| CC7.3 | The entity evaluates security events to determine whether they could or have resulted in a failure to meet objectives | **Full** | Block events with full process lineage enable incident investigation. Priority ring buffer ensures enforcement events survive attack volume. SIEM integrations enable automated correlation. |
| CC7.4 | The entity responds to identified security incidents by executing defined response activities | **Full** | Policy hot-reload enables rapid incident response (~115 ms median on the 2026-04-08 reference host, no agent restart). Break-glass toggle for emergency enforcement changes. Network deny rules can isolate compromised workloads in real-time. |

### CC8 — Change Management

| Criteria | Description | AegisBPF Capability | Evidence Collection |
|----------|-------------|---------------------|---------------------|
| CC8.1 | The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures | **Full** | Declarative policy files (INI format) support version control (Git). Policy conflict detection validates changes pre-flight. `policy.applied.sha256` provides change attestation. |

### A1 — Availability

| Criteria | Description | AegisBPF Capability | Evidence Collection |
|----------|-------------|---------------------|---------------------|
| A1.1 | The entity maintains, monitors, and evaluates current processing capacity and use of system components to manage capacity demand | **Full** | `aegisbpf footprint` estimates memory requirements. Map utilization metrics track capacity. Grafana Policy Health dashboard provides visual capacity planning. |
| A1.2 | The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data backup, and recovery infrastructure | **Partial** | Atomic policy swap (shadow map technique) ensures zero-downtime updates. Enforcement survives agent restart (BPF programs persist). Break-glass mechanism provides recovery path. |

## Evidence Collection Procedures

### Daily Automated Evidence

```bash
#!/bin/bash
# SOC 2 daily evidence collection script
# Schedule via cron: 0 2 * * * /opt/aegisbpf/scripts/soc2-evidence.sh

EVIDENCE_DIR="/var/log/aegisbpf/soc2-evidence/$(date +%Y/%m)"
mkdir -p "$EVIDENCE_DIR"
DATE=$(date +%Y%m%d)

# CC6.1 — Access control policy snapshot
cp /etc/aegisbpf/policy.applied "$EVIDENCE_DIR/policy-$DATE.conf"
sha256sum "$EVIDENCE_DIR/policy-$DATE.conf" > "$EVIDENCE_DIR/policy-$DATE.sha256"

# CC7.1 — System health attestation
aegisbpf health --json > "$EVIDENCE_DIR/health-$DATE.json"

# CC7.2 — Operational metrics snapshot
aegisbpf metrics > "$EVIDENCE_DIR/metrics-$DATE.prom"

# A1.1 — Capability and capacity report
aegisbpf capabilities --json > "$EVIDENCE_DIR/capabilities-$DATE.json"

echo "SOC 2 evidence collected: $EVIDENCE_DIR"
```

### Quarterly Review Evidence

| Review Item | Command | Reviewer Action |
|-------------|---------|-----------------|
| Policy change log | `git log --oneline -- policy/` | Verify all changes have approval |
| Block event summary | Query Prometheus: `sum(increase(aegisbpf_block_stats_blocks[90d]))` | Document trends |
| False positive analysis | Review Grafana Threat Hunting dashboard | Document false positive rate |
| Capacity utilization | Review Grafana Policy Health dashboard | Plan capacity changes |
| Incident correlation | Review SIEM alerts tagged `aegisbpf` | Document incident response |

### Annual Audit Evidence Package

For the SOC 2 Type II examination, prepare:

1. **Policy change history** — Git log of all policy modifications with approver
2. **Uptime report** — Prometheus query: `avg_over_time(aegisbpf_enforce_capable[365d])`
3. **Block statistics** — Annual summary of enforcement actions by category
4. **Incident log** — All state change events (degraded, recovery) with timestamps
5. **Capacity report** — Map utilization trends over 12 months
6. **Integration health** — SIEM connectivity and data completeness metrics

## Complementary Controls

AegisBPF provides strong technical controls but should be complemented with:

| Area | Complementary Tool | Purpose |
|------|-------------------|---------|
| Identity management | SSO/IAM provider | User authentication (AegisBPF handles process/binary identity) |
| Vulnerability scanning | Trivy, Grype | CVE detection (AegisBPF enforces access restrictions) |
| Image signing | Cosign, Notary | Supply chain verification (AegisBPF verifies exec identity at runtime) |
| Network policy | Cilium, Calico | L3/L4 CNI policy (AegisBPF adds kernel-level enforcement) |
| Secrets management | Vault, SOPS | Credential rotation (AegisBPF protects credential files) |
