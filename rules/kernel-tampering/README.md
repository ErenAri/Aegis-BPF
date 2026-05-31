# Pack: kernel-tampering

Disables three kernel-level abuse vectors that attackers reach for once
they have local code execution:

| Toggle              | Blocks                                        | MITRE ATT&CK         |
| ------------------- | --------------------------------------------- | -------------------- |
| `deny_module_load`  | `init_module(2)`, `finit_module(2)`           | T1547.006, T1014     |
| `deny_bpf`          | unsigned `bpf(2)` `BPF_PROG_LOAD` from non-AegisBPF callers | T1620        |
| `deny_ptrace`       | cross-process `ptrace(2)` attach              | T1055.008, T1003.001 |

## Threat model

After an attacker gains a foothold, they typically pivot through one of:

- Loading a malicious kernel module to hide their process / kthread.
- Loading their own BPF program to redirect packets / shadow files.
- Attaching with ptrace to inject code into a privileged process,
  scrape credentials from `sshd`, or hop to a different uid.

This pack flips all three off at the LSM layer.

## Coverage and limitations

- **Covers**: cold-boot rootkit installation, BPF-based covert channels,
  in-process credential scrapers via `ptrace`.
- **Out of scope**: rootkits installed via firmware / bootloader (UEFI),
  kernel exploits that bypass the LSM hooks entirely. Use Secure Boot +
  IMA appraisal alongside this pack.

## False-positive vectors

| Workflow                                      | Affected by      |
| --------------------------------------------- | ---------------- |
| `modprobe zfs` / NVIDIA driver autoload       | `deny_module_load` |
| `gdb`, `strace`, `perf` interactive debugging | `deny_ptrace`    |
| Other eBPF security agents on the same host   | `deny_bpf`       |
| Dynamic kernel module loading at runtime      | `deny_module_load` |

If any of those describe your host: enable the toggles selectively, or
load this pack only on production hosts where module/BPF state is
finalized at boot.

## Install

Audit-mode dry run first:

```sh
sudo aegisbpf policy validate rules/kernel-tampering/kernel-tampering.conf
sudo aegisbpf policy apply rules/kernel-tampering/kernel-tampering.conf --reset
sudo aegisbpf run --audit
# Inspect events for ~24h. If clean, switch to enforce.
```

Then in `/etc/default/aegisbpf`:

```sh
AEGIS_POLICY=/etc/aegisbpf/policy.conf  # your composed policy
AEGIS_MODE=--enforce
```

## Tested against

- Ubuntu 24.04 (kernel 6.8) — clean on a typical workload (no
  module loads, no debug sessions).
- Fedora 40 (kernel 6.9) — clean.
