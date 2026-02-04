# Phase 4 Portability Evidence

This page captures evidence for **Phase 4: Portability proof** from
`docs/MATURITY_PROGRAM.md`.

## Gate-to-evidence mapping

| Phase-4 gate | Evidence |
|---|---|
| CI matrix covers >=4 kernel targets across >=2 distro families | `.github/workflows/kernel-matrix.yml` `kernel-matrix-weekly` matrix includes kernels `5.14`, `5.15`, `6.1`, `6.5` across distro families `ubuntu`, `debian`, `rhel` |
| Runtime feature detection tests cover LSM/BTF/cgroup-v2/bpffs | `tests/test_kernel_features.cpp` verifies `check_bpf_lsm_enabled`, `check_btf_available`, `check_cgroup_v2`, and `check_bpffs_mounted` using override paths |
| Compatibility claims link to CI evidence | `docs/COMPATIBILITY.md` references this evidence pack and kernel matrix workflow |

## CI evidence links

- Kernel matrix workflow definition:
  - https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/blob/main/.github/workflows/kernel-matrix.yml
- Latest kernel matrix runs:
  - https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/workflows/kernel-matrix.yml
- Privileged e2e workflow (enforcement path):
  - https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/actions/workflows/e2e.yml

## Operator note

Self-hosted runner labels (`kernel-*`) must map to documented distro families in
your CI runner inventory. Keep this mapping under change control and update
this page if runner assignments change.
