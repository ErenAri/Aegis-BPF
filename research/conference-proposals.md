# Conference Talk Proposals

## Talk 1: eBPF Summit 2026

**Title:** AegisBPF: Sub-Microsecond Security Enforcement with eBPF LSM Hooks

**Abstract (200 words):**

Runtime security enforcement in containerized environments requires intercepting
security-relevant system calls without introducing prohibitive latency. Most eBPF
security tools focus on detection, leaving enforcement to external components that
add latency and introduce TOCTOU windows.

AegisBPF takes a different approach: enforcement decisions happen entirely in
eBPF LSM hooks, using O(1) inode-based hash map lookups instead of path-based
string matching. This achieves 0.1–0.5 µs added latency per file operation
(10–50x lower than comparable tools), with no increase in per-operation overhead
regardless of rule count.

In this talk, we'll cover:
- Why inode-first policy evaluation is faster than path-based approaches
- How dual-path backpressure ensures enforcement events are never lost
- Atomic policy hot-reload using BPF map shadow swapping
- Real-world deployment patterns in production Kubernetes clusters
- Live demo: blocking a crypto-miner container with zero false positives

Attendees will learn practical techniques for building high-performance eBPF
security tools, including BPF map selection strategies, verifier-friendly coding
patterns, and production reliability techniques.

**Duration:** 25 minutes + 5 min Q&A
**Format:** Technical deep-dive with live demo
**Speaker bio:** [AegisBPF maintainer]

---

## Talk 2: KubeCon + CloudNativeCon 2026

**Title:** From Detection to Enforcement: Kernel-Level Container Security with AegisBPF

**Abstract (200 words):**

Container security tools have traditionally focused on detection: alerting when
suspicious behavior occurs, but not preventing it. This leaves a critical gap
between detection and response — time during which attackers can exfiltrate data,
establish persistence, or escalate privileges.

AegisBPF bridges this gap with kernel-level enforcement using eBPF LSM hooks.
Deny rules are evaluated inside the kernel before syscalls complete, providing
true prevention rather than just detection. Combined with Kubernetes-native
identity enrichment (pod, namespace, service account), AegisBPF provides
workload-aware security enforcement.

This talk covers:
- Architecture: BPF LSM hooks for file, network, and kernel security
- Kubernetes integration: CRD operator, identity enrichment, Helm deployment
- Compliance: How AegisBPF maps to NIST 800-53, CIS K8s Benchmark, and PCI DSS
- Operational experience: Policy management, hot-reload, break-glass mechanisms
- Live demo: Deploying AegisBPF on a running cluster, applying policies,
  and blocking a simulated attack

The audience will learn how to add kernel-level enforcement to their security
stack, complementing existing detection tools like Falco with true prevention.

**Duration:** 35 minutes + 5 min Q&A
**Track:** Security + Identity
**Format:** Architecture overview + live demo

---

## Talk 3: USENIX Security 2027 (Poster/Workshop)

**Title:** Inode-First Policy Evaluation for Low-Overhead eBPF Security Enforcement

**Abstract (300 words):**

eBPF-based security tools face a fundamental tension: comprehensive monitoring
requires hooking high-frequency system calls (file_open, socket_connect), but
the per-invocation overhead of policy evaluation limits practical deployability
on latency-sensitive workloads.

We identify path resolution as the primary bottleneck in existing approaches.
Tools that evaluate policies based on file paths must traverse the dentry cache
and perform string comparisons for each rule on each hook invocation. With
thousands of deny rules, this overhead becomes significant.

We present an inode-first policy evaluation strategy that pre-resolves file paths
to (inode, device) pairs at policy-apply time, storing them in O(1) BPF hash maps.
At enforcement time, the hook extracts the inode and device from the kernel's
file structure (a constant-time pointer dereference) and performs a single hash
map lookup. Path resolution is deferred to logging, not enforcement.

Our evaluation on production workloads shows:
- 0.1–0.5 µs per file_open (vs 2–8 µs for path-based approaches)
- Constant overhead regardless of rule count (1 to 100,000 rules)
- 15 MB memory footprint (vs 45–120 MB for comparable tools)
- Zero enforcement gap during policy updates (atomic shadow map swap)

We further introduce a dual-path backpressure architecture separating enforcement
telemetry from audit events, guaranteeing zero enforcement-event loss under load.

Our open-source implementation (AegisBPF) includes 200+ tests, multi-architecture
support (x86_64, ARM64), and Kubernetes-native deployment with CRD-based policy
management.

**Format:** Poster session or workshop talk (15 min)

---

## Talk 4: DevSecCon / BSides

**Title:** Blocking Container Escapes at the Kernel Boundary with eBPF

**Abstract (150 words):**

Container escapes exploit weaknesses in namespace isolation, often leveraging
kernel vulnerabilities (CVE-2022-0185, CVE-2024-21626) or privileged operations
(ptrace, kernel module loading). Traditional container security focuses on
image scanning and network policy, leaving runtime kernel operations unmonitored.

AegisBPF blocks container escape attempts at the kernel boundary using eBPF LSM
hooks. We demonstrate blocking:
- ptrace-based code injection (MITRE T1055)
- Kernel module loading (T1547.006)
- BPF program tampering (T1562.001)
- Credential file theft (T1552.001)

Live demo: We'll show a simulated container escape attempt being blocked in
real-time, with forensic event attribution showing the full attack chain.

**Duration:** 20 minutes
**Format:** Attack demo + defense walkthrough
**Audience:** Security practitioners, red teamers, DevSecOps engineers
