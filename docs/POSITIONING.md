# AegisBPF Positioning & Professional-Product Roadmap

*Last reviewed: April 2026*

This document is the single source of truth for **where AegisBPF sits in the
eBPF runtime-security landscape**, **which standards it aligns to**, **which
limitations are real**, and **what ships between now and v1.0 GA**. It is
written for contributors, adopters evaluating the project, and CNCF / audit
reviewers.

---

## 1. Category & positioning statement

> **AegisBPF is the enforcement-first eBPF runtime security engine for Linux
> workloads.** Unlike Falco and Tracee (detection-only) or Tetragon
> (signal-based `SIGKILL` enforcement), AegisBPF uses BPF-LSM `-EPERM` returns
> with IMA-backed exec identity for deterministic, in-kernel prevention, and
> ships with first-class OverlayFS copy-up handling, dual-stack CIDR network
> deny, cgroup-scoped policy, and a dedicated priority ring buffer for
> forensic-grade evidence.

The category we compete in: **eBPF Workload Enforcement Platform**. We are
not a HIDS (Falco / Tracee), not a tracing tool (Cilium Hubble / Pixie), and
not an eBPF program manager (bpfman). We enforce policy at the kernel, with
enough observability to produce audit evidence.

### The four-axis map

```
                              ENFORCE
                                │
                    KubeArmor   │   Tetragon (signal)
                   ┌────────────┼────────────┐
                   │  AegisBPF  │  AegisBPF  │
          POLICY ──┼────────────┼────────────┼── OBSERVE
          (static) │            │            │  (pattern-match)
                   │            │            │
                   │   (none)   │  Falco     │
                   │            │  Tracee    │
                   └────────────┼────────────┘
                                │
                              DETECT
```

Orthogonally, **cluster scope**:

```
  Single-node LSM ── Per-workload (cgroup) ── Cluster CRD ── Multi-cluster fleet
  AppArmor/SELinux   KubeArmor/AegisBPF      Tetragon/AegisBPF  (no OSS yet)
```

AegisBPF today: **enforce × policy × per-workload/cluster**. The gap to
close for v1.0 is the rightmost column — multi-cluster / fleet.

---

## 2. Competitive one-liners

| Project | Category | Maturity | Superpower | Main weakness vs AegisBPF |
|---|---|---|---|---|
| **Falco** | Detect-only HIDS | CNCF Graduated (Feb 2024) | Huge rule library, MITRE ATT&CK tags on 46+ container rules, SIEM ecosystem | No enforcement; userspace rule engine adds ~+38% overhead on file I/O |
| **Tetragon** | Observe + Enforce | Cilium sub-project, GA v1.0 (late 2025) | TracingPolicy CRD, signal-based enforce (SIGKILL), argv/ancestry, Isovalent commercial backing | Signal override is racy vs LSM `-EPERM`; policy surface is syscall-shaped |
| **Tracee** (Aqua) | Forensics + detect | Stable | 330+ syscalls out-of-box, Rego/OPA signatures, deep forensic events | 2–4× CPU vs Tetragon in high-volume envs, detect-only |
| **KubeArmor** | Enforce-first | CNCF Sandbox | AppArmor/SELinux/BPF-LSM unified backend, edge/IoT focus | Higher latency (15–176 ms depending on policy) |
| **bpfman** | eBPF *manager* (infra, not security) | CNCF Sandbox (Jun 2024) | OCI-packaged signed eBPF programs, BPF Token + RBAC, non-root loading | Not a security product — complementary to AegisBPF |

---

## 3. Standards we align to

### 3.1 Kernel / eBPF

| Standard | Notes |
|---|---|
| **BPF LSM** (`CONFIG_BPF_LSM`, kernel ≥ 5.7; static-key gated since 6.12) | 15 hooks attached today |
| **CO‑RE + BTF** | Min kernel 5.15; loads on heterogeneous hosts without rebuild |
| **Sleepable LSM hooks** (`lsm.s/`) | Only `bprm_check_security` today; expand where hooks permit |
| **BPF Tokens** (kernel 6.9+) | Target: non-root daemon post-init |
| **Kernel BPF signature verification** (`CONFIG_BPF_SIG`) | Target when upstream stabilizes |
| **Landlock** (FS + net + signal + Unix-socket scoping in 6.12) | Target: self-sandbox the daemon |
| **seccomp-bpf** | Allowlist shipped today |

### 3.2 Supply chain

| Standard | Target |
|---|---|
| **SLSA v1.0 L3** | `slsa-github-generator` in `release.yml`, hermetic build, isolated signing key |
| **Sigstore / cosign** | Sign all release tarballs, container images, BPF objects; publish Rekor inclusion proofs |
| **SBOM** | SPDX 2.3 + CycloneDX 1.6 (shipping); add per-release VEX |
| **OpenSSF Best Practices Badge** | Gold target; required for CNCF Sandbox |
| **OpenSSF Scorecard** | ≥ 8.0 target |
| **Reproducible builds** | Pin clang/llvm; deterministic BPF bytecode |

### 3.3 Security-content standards

| Standard | Status | Work |
|---|---|---|
| **MITRE ATT&CK for Containers / Linux** | Roadmap | Every rule carries `attack.tactic` + `attack.technique` fields |
| **CIS Kubernetes Benchmark v1.8/1.9** | ✅ mapping shipped | Ship a CRD pack for one-command compliance |
| **NIST SP 800‑53 Rev 5** | ✅ mapping shipped | Deepen for FedRAMP/DoD buyers |
| **NIST SP 800‑190** | Roadmap | Container security control mapping |
| **PCI‑DSS 4.0** | ✅ mapping shipped (Req 10/11) | Pre-built evidence pack |
| **ISO/IEC 27001:2022** | ✅ mapping shipped | — |
| **SOC 2 Type II** | ✅ evidence kit | — |
| **OCSF 1.1.0** | ◐ shipped for File + Network Activity | `--event-format=ocsf` on `aegisbpfd run` emits OCSF JSON for `BlockEvent` (File Activity 1001) and `NetBlockEvent` (Network Activity 4001). Process Activity (1007) for `ExecEvent` and forensic Process Activity for `ForensicEvent` remain on roadmap. See `docs/SIEM_INTEGRATION.md` §OCSF and `src/ocsf_formatter.cpp`. |
| **ECS (Elastic Common Schema)** | ✅ formatter | Promote to first-class |
| **CEF** | Roadmap | Splunk-friendly alt format |
| **STIX 2.1 / TAXII** | Roadmap | Ingest threat-intel → auto-deny rules |

### 3.4 CNCF maturity ladder

| Stage | Requirements | AegisBPF today |
|---|---|---|
| **Sandbox** | OpenSSF Badge, governance doc, CoC, TOC sponsor | Pre-application (need badge, external maintainer, TOC sponsor) |
| **Incubating** | Multi-org maintainers, named production adopters, release cadence | Need 3 adopters on record, 2+ maintainers from different orgs |
| **Graduated** | 3rd-party audit, backward-compat policy, cross-industry adoption | Audit planned pre-v1.0 |

---

## 4. Honest limitations

Ordered by user-impact. Each has a tracked roadmap item.

### 4.1 Fundamental (eBPF / kernel)

1. **TOCTOU on path-based rules.** Pathname → inode resolution can be swapped
   between `inode_permission` and `file_open`. Path rules are
   **detection-grade**; inode/hash rules are **prevention-grade**.
   *Mitigation:* auto-derive inode rules from path rules at load time with
   a watcher. See [`GUARANTEES.md`](GUARANTEES.md).
2. **Verifier complexity limits** (1M insn, 4K stack). Large rulesets hit
   this. *Mitigation:* policy compiler that partitions into tail-called
   programs. Tetragon already does this.
3. **No kernel-module fallback.** Explicit non-goal. Falco deprecated theirs
   in v0.38; we follow the modern consensus.
4. **`socket_listen` / `socket_recvmsg` are kernel-version-gated.** Runtime
   probed. Target: emit a machine-readable capability report at startup,
   surface as an operator `Status` condition.
5. **Ring-buffer backpressure policy is implicit.** We count drops but don't
   expose `drop | sample | overflow-to-disk` policy to operators.

### 4.2 Architectural

6. **Single-node control plane.** No fleet view across clusters. *Biggest
   feature gap vs commercial CWPPs.* Target: gRPC + SPIFFE agent protocol,
   Postgres-backed API, federated CRDs.
7. **Policy language is INI + CRD only.** No CEL/Rego expressions, no
   parent-process or label selectors in match criteria. Target: **CEL**
   (Kubernetes-native, aligns with admission policies).
8. **No event dedup / aggregation on the agent.** High-rate events ship
   individually. Target: bounded time-window dedup (Falco-style
   `-o events.rate`).
9. **No response actions.** Blocking is enforcement; *responses* (quarantine
   pod, kill tree, freeze cgroup, rotate creds, pause deployment) are a
   separate muscle. Target: pluggable response engine subscribed to the
   priority ringbuf.
10. ~~**No policy simulation / dry-run diffing.**~~ **Shipped:** `aegisbpf
    simulate <events.jsonl>|- --policy <candidate.conf> [--per-event] [--json]`
    replays an audit-mode JSONL event stream against a candidate enforce
    policy and reports what would change. Reuses the live daemon's allow/deny
    precedence via a shared `evaluate_event_against_policy()` helper so
    simulator verdicts cannot drift from runtime decisions. Network event
    simulation is deferred to a follow-up.

### 4.3 Distribution / ops

11. **No distro packages.** No Ubuntu PPA, Fedora COPR, OpenSUSE OBS, Arch
    AUR. Target: at least the first three.
12. **No signed container images on a public registry.** Target:
    `ghcr.io/ErenAri/aegisbpf` + cosign.
13. **Helm chart ships; OperatorHub / OpenShift catalog listings do not.**
14. **No Windows story.** `ebpf-for-windows` is real; v2.0 consideration.
    macOS is a permanent non-goal.
15. **Daemon runs as root for its full lifetime.** Should drop to
    `CAP_BPF + CAP_PERFMON + CAP_SYS_RESOURCE` after init (kernel 5.8+
    split). Combined with Landlock self-sandbox this becomes a genuine
    differentiator.

### 4.4 Testing / evidence

16. **168 h soak evidence not yet published.** 24 h AWS soak is clean;
    laptop 24 h soak aborted at ~14.5 h due to a harness bug (daemon stdout
    filled disk — not an AegisBPF defect; RSS was flat). FedRAMP expects
    30-day continuous evidence.
17. **No chaos testing.** What happens if the BPF object is corrupted
    mid-run, or the ringbuf is detached, or a new LSM loads after us?
18. **Performance SLO unpublished.** Benchmarks exist; commitments do not.
    Target: "p99 hook latency ≤ X µs at Y events/s under Z workers,
    tested weekly."
19. **Fuzzing covers policy parser only.** Extend to IPC, event-schema
    consumers, operator webhook.
20. **No third-party security audit.** Non-negotiable for CNCF Graduated
    and enterprise RFPs.

### 4.5 Positioning / go-to-market

21. **No named adopters.** CNCF Incubation requires three.
22. **No community rule library.** Falco's is its moat. Target:
    `aegisbpf/rules` repo with MITRE-tagged, community-contributed deny
    bundles (cryptominers, reverse shells, CIS Kubernetes packs).
23. **Single-maintainer project.** Professional procurement and CNCF both
    require multi-maintainer, multi-org stewardship.

---

## 5. Roadmap to v1.0 GA

Four milestones, each with a clear exit criterion that maps to a category
of buyer. Dates are directional, not commitments.

### 5.1 Phase 1 — "Serious OSS project"

*Exit: adopter can `apt install aegisbpf` on Ubuntu 24.04 and trust the binary.*

- SLSA L3 via `slsa-github-generator`; cosign-sign all artifacts; OpenSSF
  Best Practices gold badge; Scorecard ≥ 8.0; VEX alongside SBOM.
- Ubuntu PPA, Fedora COPR, OpenSUSE OBS, Arch AUR packages.
- Hardened systemd unit (`ProtectSystem=strict`,
  `CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE`,
  `SystemCallFilter=@system-service`).
- Daemon post-init capability drop; Landlock self-sandbox; published
  seccomp profile artifact.
- Fix soak harness bug (cap `daemon.log`, disk pre-flight, watchdog).
- Publish 168 h bare-metal soak evidence.
- Governance: `GOVERNANCE.md`, `MAINTAINERS.md` with ≥ 1 external
  maintainer.

### 5.2 Phase 2 — "Enterprise-credible"

*Exit: a Fortune-500 SOC can pilot AegisBPF and tick compliance boxes.*

- MITRE ATT&CK tags on every built-in rule.
- CIS Kubernetes v1.9 + NIST SP 800‑190 bundled CRD sets.
- OCSF 1.1 + CEF output formats.
- `aegisbpf/rules` community repo with validated PR workflow.
- CEL-based selectors in policy language.
- Policy compiler + `aegisbpf policy explain`.
- `aegisbpf simulate --since 24h policy.yaml` (audit → enforce diff).
- Pluggable response engine.
- BTFhub fallback for RHEL 8 / Amazon Linux 2 / Ubuntu 20.04.
- Published third-party security audit report.
- Weekly-regressed p50/p99 hook-latency SLO gate in CI.

### 5.3 Phase 3 — "Platform, not agent"

*Exit: one control plane manages 50+ clusters with signed policy distribution.*

- `aegisbpf-cp` multi-tenant control plane (gRPC + SPIFFE, Postgres).
- Signed policy bundles distributed via OCI registry + Sigstore.
- Canary → 10% → 100% phased rollout.
- Unified `AegisPolicy v1beta1` CRD with CEL, ATT&CK metadata, response
  actions.
- Web console promoted to authenticated SPA (OIDC) with audit log, policy
  versioning, live event stream.
- Evidence store: append-only signed event log (Sigstore Rekor + local
  parquet).
- OperatorHub + Red Hat Catalog listings.
- STIX 2.1 ingestion → auto-deny rule generation.
- riscv64 release target.

### 5.4 Phase 4 — "CNCF Incubation & GA"

*Exit: AegisBPF 1.0 GA + CNCF Sandbox or Incubating acceptance.*

- Version 1.0.0 with stable `v1` CRDs, documented backward-compat policy,
  12-month LTS branch.
- Three named adopter case studies (CNCF Incubation minimum).
- Two maintainers from different organizations besides the founder.
- CNCF TOC sponsor identified; sandbox application filed.
- Published conformance test suite for downstream integrators.
- Contributor ladder (Committer / Maintainer / TOC roles); monthly
  community meeting; mailing list; Slack.

---

## 6. Next-week priorities (concrete)

1. **Fix the soak harness bug** that filled disk on the laptop 24 h run.
2. **Add MITRE ATT&CK tags** to built-in rules.
3. **Turn on `slsa-github-generator`** in `release.yml` — jumps from SLSA L1
   to L3 for release artifacts.
4. **Stand up OpenSSF Best Practices badge** and OpenSSF Scorecard action.
5. **Publish an Ubuntu PPA** of the current binary.
6. **Write a `GOVERNANCE.md`** + `MAINTAINERS.md` with an `external-maintainer`
   slot flagged open for a PR from a second contributor.

None of this is research. All of it is execution against a well-known
checklist.

---

## 7. References

- Kernel BPF LSM: https://docs.kernel.org/bpf/prog_lsm.html
- Sleepable LSM hooks (LWN): https://lwn.net/Articles/837118/
- Landlock (kernel docs): https://docs.kernel.org/admin-guide/LSM/landlock.html
- SLSA v1.0: https://slsa.dev/spec/v1.0/levels
- CNCF graduation criteria: https://github.com/cncf/toc/blob/main/process/graduation_criteria.md
- Tetragon enforcement docs: https://tetragon.io/docs/concepts/enforcement/
- Falco MITRE ATT&CK mapping: https://falco.org/blog/falco-mitre-attack/
- bpfman: https://bpfman.io/
