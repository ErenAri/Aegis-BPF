# Cross-kernel enforcement matrix (local qemu/KVM VMs)

Runs AegisBPF's enforcement batteries against **four kernels** on one laptop, for free,
via qemu/KVM cloud-image VMs — no CI, no cloud spend. Each VM boots its own kernel with
BPF-LSM active and runs the same suite the host runs: `smoke_enforce`, `redteam_bypass`
(path-alias), `redteam_altread` (io_uring / handle / openat2), and
`backpressure_saturation`.

This is the coverage a single host can't give: every prior result was 6.17-only.

## Results

| kernel | distro | BPF-LSM | smoke | path-alias | alt-read | backpressure | verdict |
|---|---|---|---|---|---|---|---|
| **6.17** | Ubuntu 24.04 (HWE) — host | active | ✅ | ✅ 11/0 | ✅ 6/0 | ✅ | **PASS** |
| **6.1** | Debian 12 | active | ✅ | ✅ 11/0 | ✅ 6/0 | ✅ | **PASS** |
| **5.15** | Ubuntu 22.04 | active | ✅ | ✅ 11/0 | ✅ 6/0 | ✅ | **PASS** (after fix ↓) |
| **6.8** | Ubuntu 24.04 (GA) | active | ✅ | ✅ 11/0 | ✅ 6/0 | ✅ | **PASS** (after resilient-load fix ↓) |

Per-kernel raw JSON in `results/`; aggregate in `matrix.json`. **All four kernels now pass.**

The matrix found **two real defects** that 6.17-only testing could never surface; both are
now fixed. (The `results/kernel-6.8-*.json` `note` records the unpatched degraded behavior.)

## Finding 1 — agent would not start on any kernel < 6.1 (FIXED in this PR)

On 5.15 the agent aborted at startup:

```
Process-exit tracepoint disabled; requires kernel 6.1+ (telemetry only, enforcement unaffected)
libbpf: prog 'handle_exit': can't attach BPF program without FD (was it loaded?)
[ERROR] Failed to attach programs {error="...: Invalid argument"}
```

`prepare_and_load_bpf()` correctly disables autoload for the `handle_exit` process-exit
tracepoint on kernels < 6.1 (the verifier rejects it there; it is best-effort telemetry).
But `bpf_attach.cpp` still attached it via the **fatal** `attach_required_program()` path,
so the disabled-and-unloaded program's attach failed with EINVAL and took the *entire*
startup down — including the file/inode/exec/network enforcement hooks that load fine on
5.15. Net effect: **AegisBPF did not run at all on 5.4 / 5.10 / 5.15**, despite those
kernels fully supporting BPF-LSM enforcement.

**Fix** (`src/bpf_attach.cpp`): honor the gate — skip the `handle_exit` attach when its
autoload was disabled (`bpf_program__autoload() == false`). With the fix, 5.15 goes from
"won't start" to the clean sweep above; 6.17 is unchanged (host smoke still passes).

## Finding 2 — no enforcement on Ubuntu 24.04 LTS's GA 6.8 kernel (FIXED)

On 6.8 the BPF **verifier rejects `handle_inode_copy_up`** (the overlayfs copy-up hook):

```
At program exit the register R0 has unknown scalar value should have been in [-4095, 0]
libbpf: prog 'handle_inode_copy_up': failed to load: -EINVAL
libbpf: failed to load object 'aegis.bpf.o'
[ERROR] Failed to load BPF object ...  ->  state=DEGRADED (BPF_LOAD_FAILED)
```

BPF object load is **atomic**: one program failing verification fails the whole object, so
the agent drops to DEGRADED with **no enforcement at all**. This is not a missing hook —
`inode_copy_up` exists on 6.8 — it is a verifier-strictness difference. Notably it is
**non-monotonic**: the same object verifies on 5.15 *and* 6.17 but not on 6.8. (The host
is Ubuntu 24.04 on the 6.17 HWE kernel and passes; the *same distro* on its GA 6.8 kernel
fails — so it is purely the kernel.)

**Confirmed sole blocker + fix direction proven:** disabling only `handle_inode_copy_up`
(one line, `set_autoload(false)`) makes 6.8 load and enforce fully — smoke passes, all
hooks attach. So the whole failure is one optional overlay hook.

**Fix** (`src/bpf_ops.cpp`): resilient load. `load_bpf()` now wraps a `load_bpf_once()`
that re-runs the whole open→configure→load flow (the object is opened from a file, so a
re-open is cheap). On a load failure it retries once with known verifier-fragile *optional*
hooks (`handle_inode_copy_up`) disabled, so a single fragile optional hook can never take
down core enforcement. Required enforcement hooks (file_open / inode_permission / execve /
fork) are never in that set — if one of those is the failure, the retry fails identically
and the original error is returned. The approach generalizes to any future per-kernel
verifier quirk on any optional hook.

Validated on 6.8: the agent logs the first-attempt verifier rejection, then
*"Loaded with a verifier-fragile optional hook disabled (degraded overlay telemetry; core
enforcement unaffected)"* — and all four batteries pass (smoke, path-alias 11/0,
alt-read 6/0, backpressure PASS: 877,699 drops, **0/1600 decisions lost**). No regression
on 6.17 (host smoke still passes). Overlay copy-up **telemetry** is the only thing lost on
6.8, and only until that hook's return path is made verifiable everywhere.

## Build-portability notes (old distros; build-only, not enforcement)

Surfaced while building in-guest; none affect the shipped binary, but each blocks a
from-source build on a stock older distro and is worth a maintainer fix:

1. **Ubuntu 22.04 / cmake 3.22** — `STATIC_LIBBPF`'s `DOWNLOAD_EXTRACT_TIMESTAMP`
   FetchContent keyword needs cmake ≥ 3.24; 3.22 mis-parses it into `URL_HASH`. (pip cmake)
2. **Ubuntu 22.04 / bpftool 5.15 & clang-14** — old bpftool + clang-14 fail skeleton gen
   (`failed to find BTF for extern 'memcmp'`). The CO-RE object is kernel-independent, so
   the matrix builds userspace with `SKIP_BPF_BUILD=ON` against the host's clang-18 object.
3. **Debian 12 / GCC 12** — `-Werror=restrict` false positive in libstdc++; build with
   `clang++` instead.

## Method / reproduce

`harness/` holds the exact scripts: `boot_vm.sh` (qcow2 overlay, KVM, ssh hostfwd),
`cloud-init-user-data.txt`, `guest_setup.sh` (deps + userspace build against the host CO-RE
object), `guest_test.sh` (runs the four batteries → `km_result.json`). BPF-LSM is off by
default on these images (BTF present, `bpf` not in the LSM list) except Debian 12; enable
via a `GRUB_CMDLINE_LINUX="lsm=...,bpf"` grub.d drop-in + reboot.

## Caveats

- Four kernels (5.15 / 6.1 / 6.8 / 6.17), x86_64, one host. Not 5.4 / 5.10 / RHEL / arm64.
- The BPF object under test is the host's clang-18 CO-RE build (representative of a modern
  release build); it is kernel-independent and the same object is loaded on every guest.
- `handle_exit` gating uses a conservative 6.1 boundary from the bpfcompat matrix; the fix
  keys off the actual autoload state, not the version, so it is correct regardless.
