# NIST SP 800-190 — AegisBPF Container-Security Mapping

NIST SP 800-190 ("Application Container Security Guide") enumerates the
major threat categories for container deployments and the countermeasures
expected from a production platform. This document maps each applicable
800-190 countermeasure to the AegisBPF capability that satisfies (or
contributes to) it.

AegisBPF is a **host-level, kernel-enforced** container-security layer:
it runs in the host PID/cgroup namespace and attaches BPF LSM hooks to
observe and block actions performed by containerized workloads. It does
not replace image scanning or registry controls; it complements them by
enforcing behaviour at runtime.

## Scope

- NIST SP 800-190, §4 "Container Technology Architecture Tiers"
- NIST SP 800-190, §5 "Major Risks" and §6 "Countermeasures for Major
  Risks" — the primary mapping target below.

Items where AegisBPF is **out of scope** (image registry, image build,
orchestrator RBAC) are listed explicitly so the picture is honest.

## §6.1 Image Risks

| 800-190 Countermeasure | AegisBPF Coverage | Notes |
|---|---|---|
| 6.1.1 Image vulnerabilities | **—** | Image scanning is out of scope. Pair AegisBPF with Trivy / Grype / Clair. |
| 6.1.2 Image configuration defects | **Partial** | `deny_path` on `/etc/shadow`, cloud creds, runtime sockets mitigates common mis-mounted hostPath exposure at runtime (see `examples/policies/container-hardening.conf`). |
| 6.1.3 Embedded malware | **Partial** | `allow_exec_inode` / exec-identity allowlists refuse execution of unknown binaries, so malware embedded in an image fails to execute even if the image ships. Requires IMA or inode pinning (kernel 6.1+). |
| 6.1.4 Embedded clear-text secrets | **—** | Static secret discovery belongs in image scanning. AegisBPF only acts at runtime. |
| 6.1.5 Use of untrusted images | **Partial** | Runtime deny of untrusted binaries via exec-identity. Image-level trust (signatures) belongs to the registry/admission controller. |

## §6.2 Registry Risks

AegisBPF is **out of scope** for registry-tier countermeasures (6.2.1
insecure connections, 6.2.2 stale images, 6.2.3 insufficient
authentication/authorization). These belong to the registry and
admission control. AegisBPF does not gate image pulls.

## §6.3 Orchestrator Risks

| 800-190 Countermeasure | AegisBPF Coverage | Notes |
|---|---|---|
| 6.3.1 Unbounded administrative access | **Partial** | Break-glass and deadman TTL controls bound emergency administrative actions with full audit (`docs/EMERGENCY_CONTROL_CONTRACT.md`). RBAC itself stays with the orchestrator. |
| 6.3.2 Unauthorized access | **Partial** | `deny_path` on kubelet/etcd/kube-apiserver configs (`examples/policies/cis-kubernetes-benchmark.conf`) prevents orchestrator configuration tampering from within compromised workloads. |
| 6.3.3 Poorly separated inter-container traffic | **Partial** | Per-cgroup policy scoping and `deny_ip` / `deny_cidr` / `deny_port` rules enforce east-west restrictions at the socket syscall level. Not a substitute for CNI network policy. |
| 6.3.4 Mixing workload sensitivity levels | **Partial** | `allow_cgroup` lets policy apply only to specific tenants/cgroups. Host-tier separation is up to the orchestrator. |
| 6.3.5 Orchestrator node trust | **—** | Node attestation (TPM / measured boot) is out of scope. |

## §6.4 Container Risks

This is the primary AegisBPF target area.

| 800-190 Countermeasure | AegisBPF Coverage | Notes |
|---|---|---|
| 6.4.1 Vulnerabilities within the runtime software | **Partial** | `deny_path` on `/run/containerd/containerd.sock`, `/var/run/docker.sock`, `/run/crio/crio.sock` blocks container-runtime-socket abuse by compromised workloads — closing the most common escape primitive. |
| 6.4.2 Unbounded network access from containers | **Full** | `socket_connect`, `socket_bind`, `socket_listen`, `socket_accept`, `socket_sendmsg` LSM hooks enforce direction-aware egress/ingress rules. Cloud metadata (169.254.169.254) is blocked by default in the hardening template. |
| 6.4.3 Insecure container runtime configurations | **Partial** | `deny_module_load`, `deny_bpf`, `deny_ptrace` cover privilege-escalation paths that misconfigured `--privileged` / `CAP_SYS_MODULE` containers otherwise enable. Does not prevent the misconfig itself; prevents exploitation. |
| 6.4.4 App vulnerabilities | **Full (blast-radius)** | AegisBPF does not patch app CVEs, but reduces blast radius: exploited processes still cannot read `/etc/shadow`, load kernel modules, inject via ptrace, or connect to blocked egress. Event stream provides forensic trail. |
| 6.4.5 Rogue containers | **Full** | Exec-identity (`allow_exec_inode`) refuses unknown binaries. Block events with cgroup + K8s identity enrichment (pod / namespace / service account) expose lateral movement and previously unseen exec lineage. |

## §6.5 Host OS Risks

| 800-190 Countermeasure | AegisBPF Coverage | Notes |
|---|---|---|
| 6.5.1 Large attack surface | **Partial** | Host hardening (minimal distro, disabled services) is the operator's job. AegisBPF ships seccomp (`--seccomp`), AppArmor, and SELinux profiles for its own process (see `SECURITY.md`). |
| 6.5.2 Shared kernel | **Full** | Kernel-security hooks (`deny_module_load`, `deny_bpf`, `deny_ptrace`) directly address shared-kernel abuse: a compromised container cannot tamper with the kernel surface used by co-tenants. |
| 6.5.3 Host OS component vulnerabilities | **—** | OS patching is out of scope. |
| 6.5.4 Improper user access rights | **Partial** | `deny_path` on `/etc/shadow`, `/etc/sudoers`, SSH keys prevents credential theft even when workload uid=0. |
| 6.5.5 Host OS file system tampering | **Full** | File-open, inode-permission, mount, rename, unlink, link, symlink LSM hooks enforce host-filesystem integrity. Inode-based denies (`deny_inode`) resist bind-mount / symlink evasion. |

## Deployment Guidance

For an SP 800-190-aligned deployment:

1. Start with `examples/policies/container-hardening.conf` as the
   baseline (covers §6.1.2, §6.4.1, §6.4.2, §6.5.2, §6.5.4, §6.5.5).
2. Layer `examples/policies/cis-kubernetes-benchmark.conf` on top for
   §6.3.2 coverage of control-plane configs.
3. Enable `--seccomp` for self-protection of the agent (§6.5.1).
4. Require signed policy bundles with `--require-signature` and rotate
   per `docs/KEY_MANAGEMENT.md` (§6.3.1 administrative control).
5. Pipe events to a SIEM (`docs/SIEM_INTEGRATION.md`) so §6.4.4 blast-
   radius events are retained for forensics.

## Known Gaps vs SP 800-190

These items 800-190 expects but AegisBPF does **not** provide:

- Image vulnerability scanning (§6.1.1, §6.1.4)
- Registry authentication / TLS (§6.2)
- Orchestrator RBAC (§6.3.1)
- CNI network policy (§6.3.3, as a substitute)
- Node attestation / measured boot (§6.3.5)
- OS patching (§6.5.3)

These are left to purpose-built tools (Trivy, Harbor, Kyverno, Calico,
Keylime, unattended-upgrades) and are **not** AegisBPF roadmap items.

## Legend

| Rating | Meaning |
|--------|---------|
| **Full** | AegisBPF directly satisfies this countermeasure |
| **Partial** | AegisBPF contributes but should be combined with other tools |
| **—** | Out of scope for AegisBPF |

## References

- NIST SP 800-190, "Application Container Security Guide"
  <https://csrc.nist.gov/pubs/sp/800/190/final>
- `docs/compliance/NIST_800_53_MAPPING.md` — general federal controls
- `docs/compliance/CIS_KUBERNETES_BENCHMARK.md` — CIS mapping
- `docs/THREAT_MODEL.md` — authoritative AegisBPF threat scope
