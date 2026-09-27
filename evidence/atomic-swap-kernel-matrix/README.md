# Atomic policy swap — real-kernel matrix (Layer B: runtime enforcement)

Layer A (`docs/KERNEL_MATRIX_RESULTS.md`) answers *"does `aegis.bpf.o` load,
verify and attach on this kernel?"*. This directory answers the question that
matters for the atomic-swap work: **can a policy transition ever expose a
mixed or partially-applied enforcement state on this kernel?**

That cannot be shown by loading an object. Each row below is a VM that booted
the named kernel with BPF-LSM active, ran a real agent in enforce mode, and
was then attacked with concurrent reloads.

## What each phase proves

| Phase | Question | Failure signal |
|---|---|---|
| `validate` | Do the primitives, the commit, the `active_slot` flip and the generation oracle behave? | any check fails |
| `stress` | Under A↔B reloads with concurrent probes, is a target **both** policies deny ever permitted? | one permitted access |
| `crash` | Killed mid-commit, does the surviving state read as exactly one generation? | a torn read |
| `leak` | Do 150 reloads retain maps, memory or pins? | unbounded growth |

The stress phase is the real detector. `/tmp/aegis_always` and `tcp/4444` are
denied in policy A *and* in policy B, so no correct implementation permits them
at any instant: before the commit A denies them, after it B denies them, and the
commit itself is one `active_slot` write with nothing in between. A single
permitted access means a state that is neither A nor B.

## Results — 6 kernels, 5.14 → 6.8, zero violations

| Kernel | Source | Runs | validate | stress (reloads / probes / violations) | crash | leak |
|---|---|---|---|---|---|---|
| 5.14.21 | mainline | 1 | pass | 14 / 2214 / **0** | 20/20, torn 0 | pass |
| **5.14.0-687.36.1.el9_8** | **AlmaLinux 9.8 vendor** | 1 | pass | 74 / 14854 / **0** | 20/20, torn 0 | pass |
| 5.15.0-131 | Ubuntu 22.04 | **3** | pass ×3 | 14 / ~2200 / **0** ×3 | 20/20, torn 0 ×3 | pass ×3 |
| 6.1.0-50 | Debian 12 | 1 | pass | 16 / 2255 / **0** | 20/20, torn 0 | pass |
| 6.5.0-060500 | mainline | **3** | pass ×3 | 14–16 / — / **0** ×3 | 20/20, torn 0 ×3 | pass ×3 |
| 6.8.0-71 | Ubuntu 24.04 | 1 | pass | 46 / 1757 / **0** | 20/20, torn 0 | pass |

Every row is one VM boot running all four phases. No row is assembled from
separate runs.

## RHEL 9

The RHEL row is a **vendor** kernel, not a mainline 5.14 substituted for one.
`almalinux-9.8-5.14-vendor.json` records `uname`, the `kernel-core` package
version and `lsm=lockdown,capability,bpf` as read inside the guest.

virtme-ng cannot boot RHEL-family kernels at all — they ship no 9p, which is how
virtme-ng shares the host rootfs. That is a fact about virtme-ng, not about
RHEL, so this row was produced differently: an AlmaLinux 9 GenericCloud qcow2
booted under qemu with `-cpu host` (RHEL 9 requires x86-64-v2) on its own
installed kernel, with cloud-init running `grubby` to add the LSM list.

The BPF object was built on the host and carried in. AlmaLinux 9.8 ships clang
21.1.8, which cannot compile `bpf/aegis_file.bpf.h` (BPF stack limit exceeded) —
a failure that reproduces on `main` and is a pre-existing toolchain gap. The
object loaded and enforced on the vendor kernel via CO-RE, which is the property
under test here; building *on* RHEL is a separate, open issue.

## Verifier cost per kernel

| Kernel | total processed insns | peak states |
|---|---|---|
| mainline 5.14 | 170,655 | 2,661 |
| **el9 5.14 (vendor)** | **186,237** | **4,322** |
| 5.15 | 281,386 | 2,931 |
| 6.1 | 225,374 | 5,355 |
| 6.5 | 197,012 | 4,842 |
| 6.8 | 523,038 | 5,374 |

The vendor 5.14 verifier is not mainline 5.14: it accepts the same programs but
explores more states, sitting closer to 6.x than to the mainline kernel it
shares a version number with. Worst single program is `handle_execve` at
111,407 insns — 11% of the 1M per-program limit.

## Why a phase can take minutes: the cost of one commit

Earlier matrix runs looked like they stalled. They did not. `bpf_map_update_elem`
on an `ARRAY_OF_MAPS` waits for an RCU grace period, and a commit stages 16
inner maps and retires 16 more, so it pays that wait ~32 times.

`scripts/mapinmap_cost_matrix.sh` measures it with no Aegis in the picture at
all -- one outer map, one inner map, a timed loop:

| Kernel | idle | every CPU busy | implied cost of one commit (×32) |
|---|---|---|---|
| mainline 5.14 | 15.74 ms | 25.37 ms | 0.50 s → 0.81 s |
| 5.15 | 16.12 ms | 24.37 ms | 0.52 s → 0.78 s |
| 6.1 | 18.62 ms | 24.62 ms | 0.60 s → 0.79 s |
| 6.5 | 16.49 ms | 26.12 ms | 0.53 s → 0.84 s |
| 6.8 | 6.00 ms | 5.63 ms | 0.19 s |
| host 7.0.0-28 (bare metal, for contrast) | 0.021 ms | 1.78 ms | 0.001 s |

6.8 is the outlier that confirms the reading rather than complicating it: its
grace period is ~3× cheaper and barely moves under load, and 6.8 is also the
fastest row in the results table above (150 s against 270–295 s for its
neighbours). The phase duration tracks the grace-period cost, not anything in
Aegis.

On 5.14–6.5 the 150-reload leak phase therefore spends **75–120 seconds inside the kernel
waiting for grace periods** before any Aegis code runs, on a 4-CPU guest whose
CPUs the stress workers are already consuming. That is the whole of the
"stall": an inherent per-commit cost, amplified by contention.

Classification: **resource contention amplifying an inherent kernel cost.** Not
a harness deadlock, not a daemon deadlock, not a kernel bug. The supporting
observation is a `policy apply` that survived `SIGKILL` in state `D`, with
`wchan = __wait_rcu_gp` and a stack of
`__wait_rcu_gp` ← `synchronize_rcu_normal` ← `map_update_elem` ← `__sys_bpf`.

Half of that cost is avoidable: the 16 retire-deletes are not on the
correctness path, since `active_slot` has already moved. Deferring them would
halve the grace periods per commit at the price of holding a retired generation
longer. That trade is **not** made here -- it is a latency change, and this
branch is about proving the transition cannot tear.

## Reproducing

```sh
cmake -S . -B build -G Ninja -DBUILD_TESTING=ON && cmake --build build
scripts/kernel_matrix_vm.sh                      # all kernels, 1 run each
KERNELS="ubuntu-22.04-5.15" RUNS=3 scripts/kernel_matrix_vm.sh
```

RHEL is not in that table (see above). `scripts/rhel_matrix_vm.sh` covers it:
it fetches the AlmaLinux cloud image, seeds cloud-init, boots with `-cpu host`,
builds the agent in the guest with `SKIP_BPF_BUILD=ON`, copies in the host-built
object, and runs the same four phases.

```sh
scripts/rhel_matrix_vm.sh                      # RHEL-family vendor kernel
scripts/mapinmap_cost_matrix.sh                # per-kernel commit cost
```
