# Hook Capability Probe

`aegisbpf probe` answers a question operators ask before they install or upgrade
AegisBPF on a fleet: **for each LSM hook AegisBPF wants to attach, will the
target kernel let it?**

Knowing that up front beats finding out later that, say, `socket_listen` fell
back to audit-only because the kernel did not expose its BPF-LSM trampoline.

## What the probe does

`aegisbpf probe` opens the kernel's BTF blob (typically
`/sys/kernel/btf/vmlinux`) and asks libbpf, for every hook in AegisBPF's
catalog, whether the corresponding `bpf_lsm_<hook>` trampoline function is
present. The presence of that symbol is what BPF-LSM attach requires — see
`btf_loader.hpp` for how AegisBPF resolves the BTF blob at load time.

The probe needs no privileges beyond reading `/sys/kernel/btf/vmlinux` and
loads no BPF programs. It is safe to run during fleet inventory or pre-flight
checks.

## How it differs from `capabilities`

| Command | Source | Answer to "is hook X usable?" |
| --- | --- | --- |
| `aegisbpf probe` | BTF symbols on the live kernel | "The kernel exposes the symbol; AegisBPF would attempt to attach." |
| `aegisbpf capabilities` | Daemon-written `/var/lib/aegisbpf/capabilities.json` | "AegisBPF actually attached it on the most recent run." |

The two views are complementary: `probe` is the prediction, `capabilities` is
the receipt.

## Output schema

```jsonc
{
  "kernel_release": "6.17.0-20-generic",
  "bpf_lsm_enabled": true,
  "cgroup_v2": true,
  "btf_available": true,
  "bpf_syscall": true,
  "ringbuf": true,
  "tracepoints": true,
  "bpffs_mounted": true,
  "capability": "Full",
  "can_enforce_files": true,
  "can_enforce_network": true,
  "can_use_shadow_maps": true,
  "hook_probe": {
    "btf_available": true,
    "hooks": {
      "lsm_file_open": {
        "kernel_supported": true,
        "required": true,
        "btf_symbol": "bpf_lsm_file_open",
        "description": "File open authorization (required)."
      },
      "lsm_socket_listen": {
        "kernel_supported": true,
        "required": false,
        "btf_symbol": "bpf_lsm_socket_listen",
        "description": "TCP listen authorization (kernel-version-gated)."
      }
      // ... 12 more hooks ...
    }
  }
}
```

### `hook_probe` block

* `btf_available` — `true` iff vmlinux BTF could be loaded. When `false`, every
  hook reports `kernel_supported: false` (the probe cannot tell which hooks
  exist without BTF).
* `hooks.<name>.kernel_supported` — `true` iff `bpf_lsm_<hook>` is a
  `BTF_KIND_FUNC` in vmlinux BTF.
* `hooks.<name>.required` — `true` for hooks AegisBPF refuses to start without
  (`lsm_file_open`, `lsm_inode_permission`). All other hooks are optional.
* `hooks.<name>.btf_symbol` — the exact symbol the probe queried. Useful for
  reproducing the lookup with `bpftool btf dump file /sys/kernel/btf/vmlinux`.
* `hooks.<name>.description` — one-line human summary.

### Hook catalog (14 entries)

| Name | Required | BTF symbol |
| --- | :---: | --- |
| `lsm_file_open` | yes | `bpf_lsm_file_open` |
| `lsm_inode_permission` | yes | `bpf_lsm_inode_permission` |
| `lsm_bprm_check_security` | no | `bpf_lsm_bprm_check_security` |
| `lsm_bprm_ima_check` | no | `bpf_lsm_bprm_ima_check` |
| `lsm_file_mmap` | no | `bpf_lsm_mmap_file` |
| `lsm_socket_connect` | no | `bpf_lsm_socket_connect` |
| `lsm_socket_bind` | no | `bpf_lsm_socket_bind` |
| `lsm_socket_listen` | no | `bpf_lsm_socket_listen` |
| `lsm_socket_accept` | no | `bpf_lsm_socket_accept` |
| `lsm_socket_sendmsg` | no | `bpf_lsm_socket_sendmsg` |
| `lsm_socket_recvmsg` | no | `bpf_lsm_socket_recvmsg` |
| `lsm_ptrace_access_check` | no | `bpf_lsm_ptrace_access_check` |
| `lsm_locked_down` | no | `bpf_lsm_locked_down` |
| `lsm_inode_copy_up` | no | `bpf_lsm_inode_copy_up` |

The catalog is asserted by `tests/test_hook_capabilities.cpp`. Adding or
removing a hook requires updating that test, this document, and (if shipped to
operators) the runtime capability schema.

## Caveats

* **BTF resolution path.** The probe reads the kernel-built-in BTF only. The
  daemon honours `AEGIS_BTF_PATH` and the BTFhub fallback search order
  (`docs/BTF_FALLBACK.md`); the probe does not. On kernels lacking
  `/sys/kernel/btf/vmlinux` but with a sidecar BTF blob, the probe will
  conservatively report every hook as unsupported even though the daemon may
  attach them successfully. This is a known limitation; if you rely on a
  sidecar BTF blob, treat the daemon's runtime `capabilities.json` as
  authoritative.
* **Symbol presence ≠ attach success.** A `kernel_supported: true` result
  means the BTF symbol exists. An LSM attach can still fail at runtime due to
  verifier limits, missing CAP_BPF, `lockdown=integrity`, kernel
  configuration, etc.
* **Required-hook drift.** Only `lsm_file_open` and `lsm_inode_permission` are
  treated as required — every other hook degrades gracefully to audit-only on
  kernels that lack it.

## Example: predict 24-hour rollout outcome

```bash
ssh node1 'aegisbpf probe' \
  | jq '.hook_probe.hooks
        | to_entries
        | map(select(.value.kernel_supported == false))
        | map(.key)'
```

If the resulting list contains anything other than `lsm_bprm_ima_check` (still
gated on some distro kernels), expect AegisBPF to start in audit-only mode for
those hooks and surface a `DEGRADED` posture.
