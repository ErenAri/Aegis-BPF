# AegisBPF Product Baseline

This document defines the minimum product requirements and threat model for a
senior-level, production-ready AegisBPF agent.

## Target environment
- Linux kernel with BTF enabled and `CONFIG_BPF_LSM=y`.
- cgroup v2 mounted at `/sys/fs/cgroup`.
- bpffs mounted at `/sys/fs/bpf`.
- Supported distros: Ubuntu 22.04+ and RHEL 9+ (initial target).
- Supported architectures: x86_64 and aarch64 (initial target).

## Threat model
Assets:
- System files and protected paths that must not be accessed.
- Audit signal integrity (block events and stats).
- Policy integrity (deny/allow rules).

Trust boundaries:
- The agent runs as root and manages pinned maps in bpffs.
- Consumers of event JSON must not be trusted to make enforcement decisions.

Attacker capabilities (in scope):
- Unprivileged user-space processes attempting to read or execute protected
  files.
- Containerized workloads attempting to escape their cgroup policy.

Out of scope:
- Root compromise of the host.
- Kernel exploitation or malicious kernel modules.
- Physical access or firmware attacks.

Security goals:
- Prevent access to denied inodes when BPF LSM is enabled.
- Emit audit events for denied paths (even when only tracepoint fallback is
  available).
- Keep policy state isolated in bpffs and resist accidental corruption.

## Functional requirements
- Deny rules by inode/device and by path (for audit fallback).
- Allowlist by cgroup ID/path.
- Audit-only and enforce modes.
- Policy import/export with versioned format and validation.
- Stats: global, per-cgroup, per-inode, per-path counters.

## Non-functional requirements
- Startup: <2s cold start on supported systems.
- Overhead: <2% CPU on common server workloads (to be benchmarked).
- Failure mode: fail closed in enforce mode when BPF LSM is enabled; fail
  open with audit signal when only tracepoint fallback is available.
- Upgrade: pinned maps must be forward-compatible or require explicit reset.

## Operational requirements
- Systemd unit and env file for managed deployments.
- CI build on supported kernels with pinned dependency versions.
- Smoke tests for both enforce and audit fallback paths.
