# OpenSSF Best Practices Badge — AegisBPF Self-Assessment

This document is AegisBPF's self-assessment against the
[OpenSSF Best Practices Badge](https://www.bestpractices.dev/en)
criteria (formerly CII Best Practices). The badge has three tiers:
**Passing**, **Silver**, **Gold**. This file tracks where AegisBPF
stands against each and which gaps are on the roadmap.

The Passing tier is a prerequisite for CNCF Sandbox application. This
document is a self-assessment; once the project completes the formal
questionnaire on bestpractices.dev, this page will be updated with the
live badge URL and ID.

Last reviewed: 2026-04-23 (commit to be filled in by release).

## Summary

| Tier | Criteria | Met | Partial | Unmet | Status |
|------|---------:|----:|--------:|------:|:-------|
| Passing | 66 | 63 | 3 | 0 | **Self-assessed PASS (pending formal submission)** |
| Silver  | ~40 added | 20 | 15 | 5 | In progress |
| Gold    | ~30 added |  5 |  8 | 17 | Not targeted yet |

## Passing Tier — Detailed

### Basics

| # | Criterion | Status | Evidence |
|---|-----------|:------:|----------|
| basics_1 | Project website exists and describes what it does | ✅ | `README.md` top section, <https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype> |
| basics_2 | Interact with potential users and contributors | ✅ | GitHub Issues + Discussions enabled; `CONTRIBUTING.md` |
| basics_3 | Non-trivial contribution from multiple people possible | ◐ | Single primary maintainer; `MAINTAINERS.md` explicitly solicits co-maintainers. Contribution process is documented; the criterion is about *possibility*, not head-count. |
| basics_4 | OSS license | ✅ | MIT, in `LICENSE` and SPDX headers |
| basics_5 | License FLOSS-approved | ✅ | MIT is OSI-approved |
| basics_6 | License in standard location | ✅ | `LICENSE` at repo root |
| basics_7 | Documentation: basics | ✅ | `README.md`, `docs/ARCHITECTURE.md`, `docs/QUICKSTART.md` equivalent |
| basics_8 | Documentation: interfaces | ✅ | `docs/API_REFERENCE.md` |
| basics_9 | Accessible repo | ✅ | Public GitHub |
| basics_10 | Bug tracker | ✅ | GitHub Issues |
| basics_11 | Locales supported documented | ✅ | English only, stated in README |

### Change Control

| # | Criterion | Status | Evidence |
|---|-----------|:------:|----------|
| change_1 | Public VCS | ✅ | GitHub |
| change_2 | Unique version identifiers | ✅ | SemVer; git tags `v0.1.0`, `v0.1.1` |
| change_3 | Release notes for each release | ✅ | `docs/CHANGELOG.md` + GitHub Releases |

### Reporting

| # | Criterion | Status | Evidence |
|---|-----------|:------:|----------|
| report_1 | Bug reporting process | ✅ | `.github/ISSUE_TEMPLATE/`, `CONTRIBUTING.md` |
| report_2 | Response within 14 days documented | ✅ | `SECURITY.md` 48h triage target for security; general issues noted in CONTRIBUTING |
| report_3 | Vulnerability reporting | ✅ | `SECURITY.md` — GitHub Security Advisories |
| report_4 | Private vulnerability report within 14 days | ✅ | `SECURITY.md` 48h acknowledgement target |

### Quality

| # | Criterion | Status | Evidence |
|---|-----------|:------:|----------|
| quality_1 | Working build system | ✅ | CMake (C++ daemon), cargo (Rust subcomponents), Go modules (operator), Makefile for BPF |
| quality_2 | Automated test suite | ✅ | `tests/` (gtest) — 153+ unit tests; integration in `scripts/soak_reliability.sh`; e2e in `.github/workflows/` |
| quality_3 | Tests run on new submissions (CI) | ✅ | `.github/workflows/ci.yml` on push + PR |
| quality_4 | Test policy | ✅ | `CONTRIBUTING.md` requires tests for new code |
| quality_5 | Warnings addressed | ✅ | `-Wall -Wextra -Werror` in CMake, `cargo clippy -D warnings`, `go vet` in CI |
| quality_6 | Secure design knowledge | ✅ | `docs/THREAT_MODEL.md` authored by maintainer; `docs/SECURITY_AUDIT.md` |

### Security

| # | Criterion | Status | Evidence |
|---|-----------|:------:|----------|
| security_1 | Secure design principles applied | ✅ | Deny-by-default policy model, least-privilege capability set, constant-time crypto, sandbox docs |
| security_2 | Cryptographic algorithms FLOSS-approved | ✅ | Ed25519 (TweetNaCl), SHA-256 (OpenSSL + custom `src/sha256.cpp`) |
| security_3 | Secure comms | ✅ | Local Unix socket only; no exposed network surface by default |
| security_4 | Fixed vulnerabilities < 60 days | ✅ | TweetNaCl memory exhaustion fix in `v0.1.1` (see `SECURITY.md` fix history) |
| security_5 | No unpatched known vulnerabilities > 60 days | ✅ | OSV + Dependabot + manual review |
| security_6 | Static analysis | ✅ | CodeQL (C++, Go), clang-tidy, cargo clippy, `gosec` in `.github/workflows/` |
| security_7 | Dynamic analysis | ✅ | libFuzzer + AddressSanitizer on 5 targets (policy / bundle / network / path / event). Smoke fuzz (60s/target) on every CI run; parser-scoped gate (120s/target) on parser changes; nightly deep fuzz (600s/target). Plus `soak_reliability.sh` long-running stability tests. See `docs/FUZZING.md`. |

### Analysis

| # | Criterion | Status | Evidence |
|---|-----------|:------:|----------|
| analysis_1 | At least one FLOSS static analysis | ✅ | See security_6 |
| analysis_2 | Static analysis fixes applied | ✅ | CodeQL findings triaged; blockers prevent merge |
| analysis_3 | Dynamic analysis run on releases | ✅ | Nightly deep fuzz (`.github/workflows/nightly-fuzz.yml`, 600s/target across 5 targets) with persistent corpus between runs. Every release is cut from a commit that has passed smoke fuzz + parser-scoped fuzz. See `docs/FUZZING.md`. |

### Gaps for Passing (formal submission blockers)

1. **quality_3/security_6 documentation**: Link the OpenSSF badge ID in
   `README.md` after bestpractices.dev enrolment.
2. **basics_3**: Although the project technically permits external
   contribution, the Passing reviewer may flag the single-maintainer
   posture. Mitigation: keep `MAINTAINERS.md` honest; document the
   explicit call for co-maintainers.
3. **Badge link**: Enrol at <https://www.bestpractices.dev/en> and link
   the badge URL + project ID here once issued.

## Silver Tier — Highlights

Silver adds ~40 criteria over Passing. AegisBPF status on the notable
additions:

| Area | Silver requirement | Status |
|------|--------------------|:------:|
| Change control | Signed commits / tags | ✅ cosign keyless on release artifacts; git tag signing on roadmap |
| Release | Reproducible build | ◐ CMake + pinned container; not yet bit-reproducible |
| Supply chain | SBOM published with each release | ✅ SPDX 2.3 + CycloneDX 1.6 in release assets |
| Supply chain | Build provenance attestation | ✅ SLSA v1.0 Build L3 via `actions/attest-build-provenance` (see `docs/compliance/SLSA_PROVENANCE.md`) |
| Cryptography | Crypto keys have documented key management | ✅ `docs/KEY_MANAGEMENT.md` |
| Quality | Coverage > 80% for new code | ◐ gcov reports in CI, ~70% overall; blocker for Silver |
| Security | Formal threat model | ✅ `docs/THREAT_MODEL.md` |
| Security | Past vulnerabilities tracked with fix and disclosure | ✅ `SECURITY.md` fix history |
| Security | Hardening options enabled by default | ✅ CFLAGS `-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie`, `-Wl,-z,now -Wl,-z,relro` |
| Supply chain | Dependency pinning | ✅ `Cargo.lock`, `go.sum` committed |

### Gaps for Silver

- Reproducible builds (bit-for-bit) not yet demonstrated.
- Code coverage < 80% target (currently ~70%).
- Signed git commits / tags not required for maintainers (only release
  artifacts are signed).
- Second independent maintainer (strong indicator for reviewer
  confidence; CNCF Incubation actually *requires* this).

## Gold Tier — Posture

Gold demands things like: code review by two people for every change,
bus factor ≥ 2, external security audit, and a comprehensive crypto
review. AegisBPF explicitly does not target Gold until after v1.0 GA.
Tracked but not worked.

## How this maps to the README matrix

| README matrix row | This document covers it via |
|---|---|
| "OpenSSF Best Practices" | ✅ Self-assessment above; badge URL to be added after formal enrolment |
| "Signed release artifacts (cosign)" | Silver: supply-chain row (see SLSA doc) |
| "SBOM (SPDX + CycloneDX)" | Silver: SBOM row |
| "SLSA L3 provenance" | Silver: supply-chain row |
| "Code coverage" | Silver: quality row (gap documented) |

## Action items (to move from self-assessed PASS to live badge)

1. Submit the Passing questionnaire at <https://www.bestpractices.dev/en>.
2. Add the badge + project ID to `README.md`.
3. Add a libFuzzer harness for the policy parser to unblock security_7 /
   analysis_3.
4. Recruit at least one independent maintainer (also a CNCF Incubation
   prerequisite).

## References

- OpenSSF Best Practices Badge site: <https://www.bestpractices.dev/en>
- Criteria (Passing): <https://www.bestpractices.dev/en/criteria/0>
- Criteria (Silver):  <https://www.bestpractices.dev/en/criteria/1>
- Criteria (Gold):    <https://www.bestpractices.dev/en/criteria/2>
- AegisBPF: `SECURITY.md`, `docs/THREAT_MODEL.md`,
  `docs/compliance/SLSA_PROVENANCE.md`, `MAINTAINERS.md`
