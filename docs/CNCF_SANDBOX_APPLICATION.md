# CNCF Sandbox Application — AegisBPF

This document is a **submission-ready draft** of the AegisBPF application
to the CNCF Sandbox. It mirrors the questions on the official
[Sandbox Application form](https://github.com/cncf/sandbox/issues/new?template=application.yml)
and pre-populates each field from existing project documentation so that
filing the actual issue is a copy-and-paste exercise.

> ⚠️ **Pre-submission blockers** (must be resolved before filing the
> application — see [§Submission readiness](#submission-readiness) below):
>
> 1. Identify a CNCF TOC sponsor.
> 2. Add **at least one external maintainer** (different organization
>    than the founder). Tracked in [`MAINTAINERS.md`](../MAINTAINERS.md).
> 3. ~~Decision: keep MIT or relicense to Apache-2.0.~~ ✅ **Resolved
>    2026-04-25 in #98**: project is now licensed under
>    [Apache License 2.0](../LICENSE), aligning with every CNCF
>    project in this category (Falco, Tetragon, Tracee, KubeArmor,
>    bpfman) and obtaining the §3 explicit patent grant.
> 4. Sign the [Contribution Agreement](https://github.com/cncf/foundation/blob/main/agreements/Sample%20Contribution%20Agreement%20(2025).pdf)
>    once the application reaches that stage.
>
> The form fields below can be filled today; the three remaining
> blockers above determine *when* the application can actually be
> submitted.

---

## Basic project information

### Project summary

Enforcement-first eBPF runtime security agent for Linux workloads —
in-kernel file, network, and exec deny via BPF-LSM with IMA-backed
trusted exec, OverlayFS copy-up handling, and signed cgroup-scoped
policy.

### Project description

AegisBPF is an open-source eBPF runtime security agent that **prevents**
unauthorized file, network, and process activity in the Linux kernel
using BPF Linux Security Module (LSM) hooks rather than detecting
events post-facto. Where Falco and Tracee observe and alert, and
Tetragon enforces via signal injection (which is racy versus syscalls
that have already taken effect), AegisBPF returns `-EPERM` from
`security_*` LSM hooks before the action completes — the same primitive
the kernel itself uses to enforce SELinux and AppArmor.

The project ships a single C++20 daemon, a Go-based Kubernetes operator
with an htmx web console, and 15 BPF programs covering file (`file_open`,
`inode_permission`, `inode_copy_up`), exec (`bprm_check_security` with
optional IMA-backed hash trust on kernel 6.1+), network (`socket_connect`,
`bind`, `listen`, `accept`, `sendmsg`, `recvmsg`), and selected kernel
hooks (`ptrace`, `module_load`, `bpf` syscall). It includes
deterministic LSM-based enforcement with a configurable signal escalation
path, an emergency break-glass with deadman TTL, signed policy bundles
(Ed25519), per-cgroup deny rules, a dedicated 4 MB priority ring buffer
for forensic-grade evidence, and SLSA v1.0 Build L3 provenance with
cosign-signed release artifacts.

The gap AegisBPF closes in the cloud-native ecosystem is a
**deterministic**, **enforcement-first**, **per-workload** eBPF security
engine that does not require AppArmor/SELinux fallback paths, ships
container-aware OverlayFS handling out of the box, and produces
audit-grade evidence by default. It complements (not replaces) Falco
(detection), Tetragon (signal-based enforcement), and bpfman (eBPF
program lifecycle management).

---

## Project details

| Field | Value |
|---|---|
| Org repo URL | N/A (single repo) |
| Project repo URL | <https://github.com/ErenAri/Aegis-BPF> |
| Additional repos | None yet (planned: `aegisbpf/rules` community rule library) |
| Website URL | <https://github.com/ErenAri/Aegis-BPF> (project site planned) |
| Roadmap | <https://github.com/ErenAri/Aegis-BPF/blob/main/docs/POSITIONING.md#5-roadmap-to-v10-ga> |
| Roadmap context | The roadmap is published as `docs/POSITIONING.md` §5 with four phases: Phase 1 "Serious OSS project" (distribution/hardening), Phase 2 "Enterprise-credible" (compliance + community rule library + simulation), Phase 3 "Platform, not agent" (multi-cluster control plane, signed OCI policy bundles), Phase 4 "CNCF Incubation & GA". `docs/ROADMAP_TO_EXCELLENCE.md` is a parallel document focused on industry recognition, performance leadership, and academic validation. The next-six-months priorities are listed in `docs/POSITIONING.md` §6. |
| Contributing guide | <https://github.com/ErenAri/Aegis-BPF/blob/main/CONTRIBUTING.md> |
| Code of Conduct | <https://github.com/ErenAri/Aegis-BPF/blob/main/CODE_OF_CONDUCT.md> (Contributor Covenant) |
| Adopters | <https://github.com/ErenAri/Aegis-BPF/blob/main/ADOPTERS.md> _(file exists; named adopters being recruited — see "Adoption" below)_ |
| Maintainers | <https://github.com/ErenAri/Aegis-BPF/blob/main/MAINTAINERS.md> |
| Governance | <https://github.com/ErenAri/Aegis-BPF/blob/main/GOVERNANCE.md> |
| Security policy | <https://github.com/ErenAri/Aegis-BPF/blob/main/SECURITY.md> |
| License | Apache License 2.0 (relicensed from MIT in #98 on 2026-04-25). `NOTICE` file at repo root carries third-party attribution per Apache-2.0 §4(d). |
| Communication channels | GitHub Issues + GitHub Discussions; community Slack/Discord planned post-Sandbox |
| Public meeting cadence | Not yet established (planned post-Sandbox) |

---

## Cloud native context

### Why this project belongs in CNCF

Cloud-native security telemetry has converged on eBPF — Falco
(Graduated, 2024), Tetragon (Cilium sub-project, parent Graduated),
KubeArmor (Sandbox), and bpfman (Sandbox) all use it. The category is
mature; what's still missing is a **deterministic enforcement-first**
agent that produces audit-grade evidence without compromising on
container compatibility (OverlayFS), kernel-version compatibility (CO-RE
+ BTF), or operational safety (deadman TTL, break-glass, signed
policies). KubeArmor is the closest peer but takes the opposite
portability bet — it routes through whichever LSM is available
(AppArmor / SELinux / BPF-LSM); AegisBPF is BPF-LSM-first by design,
which is the direction the kernel community itself is moving (BPF-LSM
is now static-key-gated since kernel 6.12, and BPF Token landed in 6.9
to enable unprivileged BPF program loading).

The CNCF would benefit because AegisBPF:

1. Closes a **real container-escape bypass** (`inode_copy_up`
   propagation) that no other agent in the landscape addresses.
2. Demonstrates **integrated supply-chain hardening** (SLSA v1.0 L3
   provenance, cosign keyless signing, SPDX + CycloneDX SBOMs, Sigstore
   Rekor) end-to-end on every release.
3. Ships **first-class compliance evidence** for NIST 800-53, NIST
   800-190, ISO 27001, SOC 2, PCI-DSS 4.0, CIS Kubernetes, and MITRE
   ATT&CK — useful as a worked example for other projects.
4. Is **complementary** to Falco / Tetragon / Tracee / bpfman: it
   enforces where they detect, and runs alongside without conflict.

### Cloud native fit

AegisBPF is designed for Kubernetes-first deployment:

- DaemonSet via Helm chart (`helm/aegisbpf/`).
- Validating admission webhook with selector-based filtering and
  merged-policy reconciler.
- `AegisPolicy` and `AegisClusterPolicy` `v1alpha1` CRDs.
- Embedded htmx web console (`--enable-console` on the operator).
- Prometheus metrics + Grafana dashboard pack (4 dashboards) +
  PrometheusRule alerting.
- OpenTelemetry OTLP exporter.
- SIEM-ready output formats (custom JSON + Elastic ECS today; OCSF +
  CEF on roadmap).

Standalone bare-metal and systemd-managed deployments are equally
supported (`packaging/systemd/aegisbpf.service`).

### Existing TAG engagement

None yet. Planned approach: present at the CNCF TAG-Security or
TAG-Runtime monthly meeting prior to (or as part of) the Sandbox
review process, per the CNCF Sandbox process guidance.

---

## Project status

### Current maturity

- **Released:** v0.5.1 (2026-04-23) on GitHub Releases with cosign
  keyless signatures, SLSA v1.0 Build L3 provenance attestations, SPDX
  2.3 + CycloneDX 1.6 SBOMs, signed Docker image at
  `ghcr.io/erenari/aegis-bpf`, and signed `.deb` / `.rpm` packages.
- **Tests:** 217+ unit + contract tests passing (`ctest`); kernel-matrix
  e2e on virtme-ng; nightly fuzz across 5 libFuzzer targets;
  performance gate on every release with self-hosted runner.
- **Hardening:** seccomp-bpf allowlist, Landlock self-sandbox (opt-in
  `--landlock`), FORTIFY_SOURCE=2, stack-protector-strong, PIE, full
  RELRO, atomic-write file persistence, Ed25519-signed break-glass
  tokens.
- **CI:** 38 GitHub Actions workflows including kernel-matrix, perf SLO
  gate, MITRE ATT&CK schema gate, BPF compiler matrix (clang 14/15/16/17),
  reproducibility check, scorecard, security scanning, weekly comparison
  vs Falco + Tetragon.
- **Compliance evidence:** see `docs/compliance/` — NIST SP 800-53 Rev. 5,
  ISO/IEC 27001:2022, SOC 2 Type II evidence kit, PCI DSS 4.0, CIS
  Kubernetes Benchmark v1.8, MITRE ATT&CK tag schema with CI
  enforcement, OpenSSF Best Practices self-assessment (Passing tier
  met; pending formal submission).

### Adoption

**Honest current state:** AegisBPF is a young project (first commit
2026-01-11). The `ADOPTERS.md` file exists with the contribution
template; named adopters are actively being recruited to meet the bar
for CNCF Incubation. The project's own staging deployment and
self-hosted CI runners count as eat-our-own-dogfood usage but are not
listed as third-party adopters.

This is the largest gap to address between Sandbox and Incubation. The
Sandbox application itself does not require named adopters — the
[Sandbox README](https://github.com/cncf/sandbox#readme) establishes
that Sandbox is for early-stage projects with growth potential — but
this is disclosed honestly to the TOC.

### Maintainers and governance

- **Active maintainer:** Eren Arı ([@ErenAri](https://github.com/ErenAri)),
  Independent. Project lead, BPF programs, daemon, release.
- **Vendor neutrality:** project is independently maintained; not
  controlled by or affiliated with any company. No commercial product
  is built around the project.
- **Governance:** [`GOVERNANCE.md`](../GOVERNANCE.md) defines
  Maintainer / Reviewer / Contributor / Security Team roles, lazy
  consensus for routine changes, RFC + 2-maintainer approval for
  breaking changes, branch protection on `main` with required status
  checks, CODEOWNERS enforcement on sensitive paths, signed-tag
  requirement for releases.
- **Pre-submission gap:** [`MAINTAINERS.md`](../MAINTAINERS.md) actively
  solicits a co-maintainer from a different organization. CNCF
  Incubation requires this; it is not a Sandbox blocker but is
  disclosed as a near-term commitment.

---

## CNCF policies

| Policy | AegisBPF posture |
|---|---|
| [IP Policy (Charter §11)](https://github.com/cncf/foundation/blob/main/charter.md#11-ip-policy) | Project is single-license Apache-2.0 (relicensed from MIT in #98 on 2026-04-25). All contributions to date are by the project lead; the only other contributor entries are GitHub Copilot and dependabot bots, which do not assert IP. |
| [Allowlist license policy for dependencies](https://github.com/cncf/foundation/blob/main/policies-guidance/allowed-third-party-license-policy.md) | Direct dependencies: libbpf (LGPL-2.1 / BSD-2-Clause), TweetNaCl (vendored, public domain), Go modules in operator (mostly BSD-3 / Apache-2.0 / MIT). SBOM (`sbom/` and `release/sbom.spdx.json`) enumerates every transitive dependency with license metadata; no copyleft-only or non-allowlisted licenses present. |
| Code of Conduct | Contributor Covenant (`CODE_OF_CONDUCT.md`). |
| Trademark | "AegisBPF" name is unregistered today; the project is willing to follow CNCF naming and trademark guidance upon acceptance. |

---

## Contact information

| Role | Name | Email | GitHub |
|---|---|---|---|
| Primary contact | Eren Arı | _(to fill in submission)_ | [@ErenAri](https://github.com/ErenAri) |
| Contribution Agreement signatory | Eren Arı | _(to fill in submission)_ | [@ErenAri](https://github.com/ErenAri) |
| Security contact | per [`SECURITY.md`](../SECURITY.md) | per `SECURITY.md` | per `SECURITY.md` |

---

## Additional information

- **Differentiation in this category:** see
  [`README.md` §"Where AegisBPF is uniquely differentiated today"](../README.md#where-aegisbpf-is-uniquely-differentiated-today)
  and [`docs/POSITIONING.md` §2 "Competitive one-liners"](POSITIONING.md#2-competitive-one-liners).
- **Honest limitations:** see [`docs/POSITIONING.md` §4 "Honest
  limitations"](POSITIONING.md#4-honest-limitations) (23 numbered items
  with mitigation status).
- **Reproducible competitive benchmarks:** the
  `.github/workflows/comparison.yml` workflow runs head-to-head against
  Falco and Tetragon on a self-hosted bare-metal runner weekly.
  Methodology is at [`docs/COMPETITIVE_BENCH_METHODOLOGY.md`](COMPETITIVE_BENCH_METHODOLOGY.md);
  results are in [`docs/PERFORMANCE_COMPARISON.md`](PERFORMANCE_COMPARISON.md).

---

## Submission readiness

This is a self-honest checklist of what to do *before* submitting the
form:

| # | Item | Status | Owner |
|---|---|:---:|---|
| 1 | Identify CNCF TOC sponsor | ❌ | maintainer |
| 2 | Recruit ≥1 maintainer from a different org | ❌ | maintainer |
| 3 | Decide on license (MIT vs Apache-2.0) and document | ✅ | resolved in #98 (2026-04-25) — Apache License 2.0 |
| 4 | Confirm IP provenance for all current contributions | ✅ | maintainer (single contributor to date) |
| 5 | Verify all CNCF dependency licenses are allowlisted | ✅ | SBOMs in `sbom/` |
| 6 | OpenSSF Best Practices Badge — formal submission | ◐ | self-assessment complete in `docs/compliance/OPENSSF_BEST_PRACTICES.md`; needs formal submission to bestpractices.dev |
| 7 | OpenSSF Scorecard score ≥ 7.0 | ✅ | `.github/workflows/scorecard.yml` publishes weekly |
| 8 | TAG engagement (TAG-Security or TAG-Runtime) | ❌ | schedule presentation |
| 9 | Public roadmap document | ✅ | `docs/POSITIONING.md` §5 |
| 10 | Adopters file | ✅ | `ADOPTERS.md` (template; needs first named entry) |
| 11 | Trademark guidance reviewed | ◐ | unregistered; accept CNCF guidance |
| 12 | Contribution Agreement reviewed and signatory identified | ❌ | maintainer to review and sign |

When items 1, 2, 3, 8, and 12 above are complete, the application form
can be filed verbatim from the content of this document.

---

## References

- CNCF Sandbox process: <https://github.com/cncf/sandbox>
- TOC project lifecycle: <https://github.com/cncf/toc/blob/main/process/README.md>
- Contribution Agreement template: <https://github.com/cncf/foundation/blob/main/agreements/Sample%20Contribution%20Agreement%20(2025).pdf>
- Sandbox application form: <https://github.com/cncf/sandbox/issues/new?template=application.yml>
- TOC Slack channel for questions: `#toc` on Cloud Native Computing Foundation Slack
- AegisBPF positioning and roadmap: [`docs/POSITIONING.md`](POSITIONING.md)
- AegisBPF OpenSSF self-assessment: [`docs/compliance/OPENSSF_BEST_PRACTICES.md`](compliance/OPENSSF_BEST_PRACTICES.md)
