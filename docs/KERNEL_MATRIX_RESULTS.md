# Kernel Matrix Results (Layer A: object load / verify / attach)

Real-kernel results from running `aegis.bpf.o` through the
[bpfcompat](https://github.com/ErenAri/adaptive-bpf-runtime-program) QEMU/KVM
validator across the target LTS matrix. Layer A answers *"does the object load,
verify, and attach on this kernel?"* — see [KERNEL_COMPAT_MATRIX.md](KERNEL_COMPAT_MATRIX.md)
for the two-layer model. A green here means **compatible**, not (by itself)
*enforcement-proven*; behavioral `-EPERM` proof is the
`enforcement_proof.sh` harness.

## Run provenance

- **Date:** 2026-07-03 (re-validated for the **v0.9.0** release)
- **Release:** v0.9.0, commit `dcd6128`
- **Artifact:** `aegis.bpf.o` sha256 `a468abd5bc93e8c435c17a8636a31275cfe2eee2fc567a09ff75a6394954af40`
- **Validator:** `bpfcompat-matrix.yml` on the self-hosted KVM runner — CI run
  [28668816737](https://github.com/ErenAri/Aegis-BPF/actions/runs/28668816737) (PASS)
- **Reproduce:** `gh workflow run bpfcompat-matrix.yml --ref main`, or locally
  `AEGIS_BPFCOMPAT_DIR=<bpfcompat checkout> AEGIS_BPF_OBJ=build/aegis.bpf.o bash scripts/run_bpfcompat_matrix.sh`

## Result — required enforcement hooks load on every kernel ✅

The gate is the **required** hooks (`file_open` + `inode_permission`,
`required=true` in `hook_capabilities.cpp`). All five profiles PASS.

| Kernel | Profile | Programs loaded | Required hooks | Verdict |
|--------|---------|-----------------|----------------|---------|
| 5.15 | `ubuntu-22.04-5.15` | 20 / 22 | ok | PASS |
| 6.1  | `debian-12-6.1` | 22 / 22 | ok | PASS |
| 6.8  | `ubuntu-24.04-6.8` | 22 / 22 | ok | PASS |
| 6.12 | `oracle-linux-10-uek8-6.12` | 22 / 22 | ok | PASS |
| 6.17 | `ubuntu-25.10-6.17` | 22 / 22 | ok | PASS |

**Every BPF-LSM enforcement program — exec, file (×2), network (×6), ptrace,
module-load (×2), bpf — loads on all five kernels (5.15 → 6.17).**

## The non-universal programs (all best-effort / gated)

The < 22/22 profiles are missing only **optional** programs that AegisBPF's
loader gates by capability, so the agent still loads and enforces:

- **5.15 (20/22):** `handle_exit` (sched-exit telemetry, verifier-gated < 6.1)
  and `handle_bprm_ima_check` (sleepable IMA, gated < 6.1).

As of v0.9.0 **every other kernel loads all 22 programs**, including
`handle_inode_copy_up`. The 6.8 / 6.12 overlay-copy-up hook — which previously
failed the 6.8 verifier and left those kernels at 21/22 — now loads after the
root-cause fix in **#267** (`barrier_var()` + clamp so the return bound survives
clang's shared-tail codegen). The only remaining non-universal programs are the
two hooks that are legitimately gated below kernel 6.1.

None of these are required for enforcement; their absence degrades
telemetry/overlay coverage only. Combined with the earlier `handle_execve`
(≤ 6.8) and `handle_exit` (< 6.1) gate fixes, the agent now loads cleanly across
the entire 5.15 → 6.17 LTS range.
