# Enforcement Claims Matrix

Every enforcement claim must have a corresponding automated test that proves it works on a real BPF LSM kernel. This document maps claims to tests and CI jobs.

## Claims

| # | Claim | Test | CI Job |
|---|-------|------|--------|
| C1 | `deny_path /X` blocks `open("/X")` | `e2e_enforcement_proofs.sh::test_deny_path` | e2e.yml |
| C2 | `deny_inode dev:ino` blocks `open()` on that inode | `e2e_enforcement_proofs.sh::test_deny_inode` | e2e.yml |
| C3 | `allow_cgroup` bypasses deny for processes in that cgroup | `e2e_enforcement_proofs.sh::test_cgroup_bypass` | e2e.yml |
| C4 | `deny_ipv4` blocks `connect()` to that IP | `e2e_enforcement_proofs.sh::test_deny_ipv4` | e2e.yml |
| C5 | `deny_port` blocks `bind()` on that port | `e2e_enforcement_proofs.sh::test_deny_port` | e2e.yml |
| C6 | Break-glass disables enforcement | `e2e_enforcement_proofs.sh::test_break_glass` | e2e.yml |
| C7 | Deadman switch reverts to audit after TTL | `e2e_enforcement_proofs.sh::test_deadman` | e2e.yml |
| C8 | Survival allowlist prevents blocking critical binaries | `e2e_enforcement_proofs.sh::test_survival` | e2e.yml |
| C9 | Emergency disable stops all enforcement instantly | `e2e_enforcement_proofs.sh::test_emergency` | e2e.yml |

## Running Proofs Locally

Requires a kernel with BPF LSM enabled (`bpf` in `/sys/kernel/security/lsm`), root access, and a built `aegisbpf` binary.

```bash
# Build
cmake -B build -G Ninja
cmake --build build -j$(nproc)

# Run all proofs
sudo BIN=./build/aegisbpf scripts/e2e_enforcement_proofs.sh
```

## CI Integration

The enforcement proofs run in the `e2e.yml` workflow on self-hosted `bpf-lsm` runners. All claims must pass for the CI job to succeed. A claim failure means the enforcement guarantee is broken and the build is not releasable.

## What Constitutes a Passing Proof

A proof passes when:

1. The daemon starts successfully with the configured policy
2. The enforcement action is observed (file open returns EPERM, connect fails, etc.)
3. The inverse is also tested where applicable (allowed operations succeed)
4. The daemon exits cleanly after the test

A proof fails if any enforcement action does not produce the expected result, or if the daemon crashes during the test.
