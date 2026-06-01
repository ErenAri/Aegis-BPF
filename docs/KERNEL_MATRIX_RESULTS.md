# Kernel Matrix Results (Layer A: object load / verify / attach)

Real-kernel results from running `aegis.bpf.o` through the
[bpfcompat](https://github.com/ErenAri/adaptive-bpf-runtime-program) QEMU/KVM
validator across the target LTS matrix. Layer A answers *"does the object load,
verify, and attach on this kernel?"* — see [KERNEL_COMPAT_MATRIX.md](KERNEL_COMPAT_MATRIX.md)
for the two-layer model. A green here means **compatible**, not (by itself)
*enforcement-proven*; behavioral `-EPERM` proof is the
`enforcement_proof.sh` harness.

## Run provenance

- **Date:** 2026-06-01
- **Artifact:** `aegis.bpf.o` sha256 `7478611eff56c9fad68a9b43f6ecc3de25d7ea1f106b0c19ace21bc655422aa9`
- **Validator host:** Linux 6.17.0-29-generic, x86_64, KVM
- **bpfcompat:** commit `c82a147` (per-program isolated load probe)
- **Reproduce:** `AEGIS_BPFCOMPAT_DIR=<bpfcompat checkout> AEGIS_BPF_OBJ=build/aegis.bpf.o bash scripts/run_bpfcompat_matrix.sh`

## Result — required enforcement hooks load on every kernel ✅

The gate is the **required** hooks (`file_open` + `inode_permission`,
`required=true` in `hook_capabilities.cpp`). All five profiles PASS.

| Kernel | Profile | Programs loaded | Required hooks | Verdict |
|--------|---------|-----------------|----------------|---------|
| 5.15 | `ubuntu-22.04-5.15` | 20 / 22 | ok | PASS |
| 6.1  | `debian-12-6.1` | 22 / 22 | ok | PASS |
| 6.8  | `ubuntu-24.04-6.8` | 21 / 22 | ok | PASS |
| 6.12 | `oracle-linux-10-uek8-6.12` | 21 / 22 | ok | PASS |
| 6.17 | `ubuntu-25.10-6.17` | 22 / 22 | ok | PASS |

**Every BPF-LSM enforcement program — exec, file (×2), network (×6), ptrace,
module-load (×2), bpf — loads on all five kernels (5.15 → 6.17).**

## The non-universal programs (all best-effort / gated)

The < 22/22 profiles are missing only **optional** programs that AegisBPF's
loader gates by capability, so the agent still loads and enforces:

- **5.15 (20/22):** `handle_exit` (sched-exit telemetry, verifier-gated < 6.1)
  and `handle_bprm_ima_check` (sleepable IMA, gated < 6.1).
- **6.8 / 6.12 (21/22):** `handle_inode_copy_up` (overlay copy-up; optional LSM
  hook, gated when unavailable).

None are required for enforcement; their absence degrades telemetry/overlay
coverage only. This is exactly what the
[bug fixes](KERNEL_COMPAT_MATRIX.md) for `handle_execve` (was failing ≤ 6.8) and
the `handle_exit` gate were for — the agent now loads cleanly across the LTS
range.
