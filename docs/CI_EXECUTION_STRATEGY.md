# CI Execution Strategy

This document defines how AegisBPF executes privileged/kernel-dependent checks
reliably in CI.

## Why this exists

Security correctness claims are invalid without deterministic kernel e2e
evidence. Hosted CI alone is not sufficient for BPF LSM portability testing.

## Strategy

Primary model:
- **GitHub-hosted runners** for fast compile/unit/lint/security checks.
- **Self-hosted kernel runners** for privileged e2e and kernel-matrix tests.

Fallback model:
- VM-based workflow with pinned kernel images if self-hosted capacity is
  unavailable.

## Runner classes

- `ubuntu-22.04`, `ubuntu-24.04` (hosted):
  - build/test/sanitizers/lint/security/coverage/benchmark
- `self-hosted,bpf-lsm`:
  - privileged e2e (`.github/workflows/e2e.yml`)
- `self-hosted,kernel-*`:
  - kernel matrix (`.github/workflows/kernel-matrix.yml`)
- `self-hosted,perf`:
  - perf regression evidence (`.github/workflows/perf.yml`)
- `self-hosted,bpf-lsm`:
  - soak reliability evidence (`.github/workflows/soak.yml`)

## Runner setup (self-hosted)

Use the helper script on **each runner host** (must run as root):

```bash
sudo REPO=ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype \
  RUNNER_NAME=kernel-6.8-host \
  LABELS=kernel-6.8,bpf-lsm \
  scripts/setup_self_hosted_runner.sh
```

Example labels:
- `kernel-6.8` (Ubuntu 22.04 HWE host)
- `kernel-6.1` (Debian 12 host)
- `kernel-5.14` (RHEL 9 host)
- `kernel-6.5` (Ubuntu 24.04 host)
- `bpf-lsm` (privileged e2e + soak)
- `perf` (perf regression)

Notes:
- Runner hosts must have the **target kernel** installed and booted.
- The runner service runs as root to allow BPF and `sudo` operations.
- If you prefer a non-root service, configure passwordless `sudo` for the
  runner user and adjust `RUNNER_ALLOW_RUNASROOT=0`.

## Kernel matrix minimum

Required evidence floor:
- Ubuntu LTS family: 2 kernels
- Debian/RHEL-like family: 2 kernels
- Total >=4 kernel targets

Example target set:
- 5.14, 6.1, 6.5, 6.8

## Determinism requirements

- Pin kernel version per runner class.
- Pin test prerequisites (`bpftool`, `libbpf`, userspace deps).
- Record kernel + distro + filesystem metadata in test artifacts.
- Run privileged tests in host PID/cgroup namespaces.

## Enforcement-path PR rule

Any PR touching enforcement paths (`bpf/`, `src/bpf_ops*`, `src/policy*`,
`src/network_ops*`) must pass:
- e2e privileged tests
- kernel-matrix subset (minimum 2 kernels)

## Failure handling

- If self-hosted runners are unavailable, gate release merges and mark status
  as infrastructure-blocked (not green).
- Never treat skipped privileged checks as success.

## Artifacts to retain

- `aegisbpf health --json` output
- enforcement/audit test logs
- benchmark JSON
- compatibility summary (kernel/distro/capability outcome)

## Ownership

- Maintainers own runner health and capacity.
- Security reviewers own coverage and threat-model alignment.
- Release approvers verify evidence links before merge.
