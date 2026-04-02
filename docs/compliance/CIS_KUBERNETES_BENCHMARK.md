# CIS Kubernetes Benchmark v1.8 — AegisBPF Alignment

This document maps CIS Kubernetes Benchmark v1.8 recommendations to
AegisBPF policy capabilities and provides enforcement examples for
each applicable control.

## Applicable Controls

### 1.1 Control Plane Configuration — API Server

| CIS Control | Recommendation | AegisBPF Enforcement | Policy Section |
|-------------|----------------|---------------------|----------------|
| 1.1.1 | Ensure API server pod spec permissions are restricted | **Full** | `deny_path /etc/kubernetes/manifests/kube-apiserver.yaml` prevents unauthorized modification of API server pod spec. |
| 1.1.2 | Ensure API server pod spec ownership is set to root:root | **Partial** | File deny rules prevent non-root access; ownership enforcement requires complementary OS-level controls. |
| 1.1.3–1.1.12 | Ensure controller manager, scheduler, and etcd configs are restricted | **Full** | `deny_path` rules cover all control plane config files. See `examples/policies/cis-kubernetes-benchmark.conf`. |
| 1.1.19 | Ensure PKI directory and file permissions are restricted | **Full** | `deny_path /etc/kubernetes/pki/` rules protect all PKI certificates and keys. |
| 1.1.21 | Ensure Kubernetes PKI key file permissions are restricted | **Full** | `deny_path /etc/kubernetes/pki/*.key` protects private key files from unauthorized access. |

### 1.2 API Server

| CIS Control | Recommendation | AegisBPF Enforcement | Policy Section |
|-------------|----------------|---------------------|----------------|
| 1.2.5 | Ensure --kubelet-certificate-authority is set | **Partial** | Cannot enforce API server flags directly; protects the CA certificate file via `deny_path`. |
| 1.2.16 | Ensure admission control plugin PodSecurityPolicy is set | **—** | Replaced by Pod Security Standards in K8s 1.25+. AegisBPF provides runtime enforcement complement. |

### 4.1 Worker Node Configuration

| CIS Control | Recommendation | AegisBPF Enforcement | Policy Section |
|-------------|----------------|---------------------|----------------|
| 4.1.1 | Ensure kubelet service file permissions are restricted | **Full** | `deny_path /etc/systemd/system/kubelet.service.d/` protects kubelet service configuration. |
| 4.1.5 | Ensure --kubeconfig kubelet.conf permissions are set | **Full** | `deny_path /etc/kubernetes/kubelet.conf` prevents unauthorized access to kubelet credentials. |
| 4.1.6 | Ensure --kubeconfig kubelet.conf ownership is set | **Partial** | AegisBPF prevents read access; ownership enforcement is complementary. |
| 4.1.9 | Ensure kubelet --config file permissions are set | **Full** | File deny rules protect kubelet config from unauthorized modification. |
| 4.1.10 | Ensure kubelet --config file ownership is set | **Partial** | Complementary with OS-level controls. |

### 4.2 Kubelet

| CIS Control | Recommendation | AegisBPF Enforcement | Policy Section |
|-------------|----------------|---------------------|----------------|
| 4.2.1 | Ensure --anonymous-auth is set to false | **—** | API server flag; not enforceable via AegisBPF. |
| 4.2.6 | Ensure --protect-kernel-defaults is set | **Full** | AegisBPF provides kernel-level protection beyond what kubelet flag offers. `deny_module_load`, `deny_ptrace`, `deny_bpf` enforce kernel integrity. |

### 5.1 RBAC and Service Accounts

| CIS Control | Recommendation | AegisBPF Enforcement | Policy Section |
|-------------|----------------|---------------------|----------------|
| 5.1.1 | Ensure cluster-admin role is only used where required | **Partial** | K8s identity enrichment tracks service account in block events. Combined with SIEM alerts, can detect misuse of cluster-admin. |
| 5.1.5 | Ensure default service accounts are not actively used | **Partial** | K8s identity enrichment includes service account in events. Policy can restrict default service account cgroups. |
| 5.1.6 | Ensure Service Account Tokens are not mounted in pods that do not need them | **Full** | `deny_path /var/run/secrets/kubernetes.io/serviceaccount/token` prevents unauthorized token access. |

### 5.2 Pod Security Standards

| CIS Control | Recommendation | AegisBPF Enforcement | Policy Section |
|-------------|----------------|---------------------|----------------|
| 5.2.1 | Ensure Privileged containers are not used | **Partial** | AegisBPF enforces at kernel level regardless of container privilege. `deny_ptrace`, `deny_module_load`, `deny_bpf` restrict privileged operations. |
| 5.2.2 | Ensure hostPID is not set | **Partial** | `deny_ptrace` prevents cross-PID-namespace process manipulation even if hostPID is enabled. |
| 5.2.3 | Ensure hostNetwork is not set | **Partial** | Network deny rules apply regardless of network namespace. AegisBPF hooks operate at syscall level. |
| 5.2.6 | Ensure allowPrivilegeEscalation is set to false | **Full** | `deny_ptrace` prevents ptrace-based privilege escalation. `deny_module_load` and `deny_bpf` prevent kernel-level privilege escalation. |
| 5.2.7 | Ensure root containers do not run | **Partial** | Block events include UID for root detection. Combined with cgroup policy, can restrict root container execution. |

### 5.7 Network Policies

| CIS Control | Recommendation | AegisBPF Enforcement | Policy Section |
|-------------|----------------|---------------------|----------------|
| 5.7.1 | Ensure network policies are configured for every namespace | **Full** | AegisBPF network deny rules apply kernel-level enforcement complementing K8s NetworkPolicy. Covers gaps where CNI enforcement may not apply. |
| 5.7.2 | Ensure default deny all ingress traffic | **Partial** | Network deny rules can implement default-deny for specific ports. Combined with cgroup allowlisting, provides workload-level deny-by-default. |

## Pre-Built Policy

See `examples/policies/cis-kubernetes-benchmark.conf` for a comprehensive
policy implementing all applicable controls above.

## Validation Script

```bash
#!/bin/bash
# Validate AegisBPF CIS Kubernetes Benchmark compliance
# Usage: ./validate-cis.sh

PASS=0
FAIL=0
WARN=0

check() {
    local control="$1"
    local desc="$2"
    local cmd="$3"

    if eval "$cmd" >/dev/null 2>&1; then
        echo "PASS  $control  $desc"
        ((PASS++))
    else
        echo "FAIL  $control  $desc"
        ((FAIL++))
    fi
}

warn() {
    local control="$1"
    local desc="$2"
    echo "WARN  $control  $desc (requires complementary controls)"
    ((WARN++))
}

echo "=== AegisBPF CIS Kubernetes Benchmark Validation ==="
echo

# 1.1 Control plane configs
check "1.1.1" "API server pod spec protected" \
    "aegisbpf policy show 2>/dev/null | grep -q 'kube-apiserver.yaml'"
check "1.1.19" "PKI directory protected" \
    "aegisbpf policy show 2>/dev/null | grep -q '/etc/kubernetes/pki'"

# 4.1 Worker node
check "4.1.5" "Kubelet credentials protected" \
    "aegisbpf policy show 2>/dev/null | grep -q 'kubelet.conf'"

# 5.1 Service accounts
check "5.1.6" "Service account tokens protected" \
    "aegisbpf policy show 2>/dev/null | grep -q 'serviceaccount/token'"

# 5.2 Pod security
check "5.2.6" "Ptrace denied (privilege escalation)" \
    "aegisbpf capabilities --json 2>/dev/null | grep -q '\"deny_ptrace\":true'"
check "5.2.6b" "Module load denied (kernel escalation)" \
    "aegisbpf capabilities --json 2>/dev/null | grep -q '\"deny_module_load\":true'"
check "5.2.6c" "BPF denied (BPF escalation)" \
    "aegisbpf capabilities --json 2>/dev/null | grep -q '\"deny_bpf\":true'"

# 5.7 Network
check "5.7.1" "Network deny rules active" \
    "aegisbpf capabilities --json 2>/dev/null | grep -qE '\"deny_port_count\":[1-9]|\"deny_ip_count\":[1-9]|\"deny_cidr_count\":[1-9]'"

# Runtime checks
check "RUNTIME" "AegisBPF is running" \
    "pgrep -x aegisbpf"
check "RUNTIME" "AegisBPF is healthy" \
    "aegisbpf health --json 2>/dev/null | grep -q '\"healthy\":true'"

echo
echo "=== Results: $PASS passed, $FAIL failed, $WARN warnings ==="
```

## Legend

| Rating | Meaning |
|--------|---------|
| **Full** | AegisBPF directly enforces this recommendation |
| **Partial** | AegisBPF contributes; complementary controls recommended |
| **—** | Not applicable to runtime enforcement |
