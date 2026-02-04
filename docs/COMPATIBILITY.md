# AegisBPF Kernel Compatibility Matrix

This document describes the kernel requirements and compatibility matrix for AegisBPF.
See `docs/SUPPORT_POLICY.md` for versioning and support windows.

## Requirements

### Minimum Requirements

| Component | Requirement | Notes |
|-----------|-------------|-------|
| Kernel | 5.8+ | For ring buffer support |
| cgroup | v2 | Required for cgroup isolation |
| BTF | Required | `/sys/kernel/btf/vmlinux` must exist |
| bpffs | Mounted | `/sys/fs/bpf` must be mounted |

### Optional Requirements

| Component | Requirement | Notes |
|-----------|-------------|-------|
| BPF LSM | Kernel 5.7+ | Required for full enforcement mode |

## Enforcement Capabilities

AegisBPF operates in one of three capability levels based on kernel support:

### Full Enforcement

**Requirements:**
- BPF LSM enabled (`bpf` in `/sys/kernel/security/lsm`)
- Ring buffer support (kernel 5.8+)
- cgroup v2
- BTF

**Capabilities:**
- Block file access (returns `EPERM`)
- Optional enforce signal (`SIGTERM` by default; `SIGKILL` requires build-time
  `-DENABLE_SIGKILL_ENFORCEMENT=ON` and runtime `--allow-sigkill`)
- Inode-based tracking
- Full audit logging

### Audit-Only Mode

**Requirements:**
- Tracepoint support
- cgroup v2
- BTF

**Capabilities:**
- Log file access attempts (cannot block)
- Process tracking
- Statistics collection

**Limitations:**
- Cannot prevent file access
- Cannot kill processes
- Path-based matching only (tracepoint limitation)

### Disabled

AegisBPF cannot run if:
- BPF syscall not available
- cgroup v2 not available
- BTF not available

## Distribution Compatibility

| Distribution | Version | Kernel | LSM Enforce | Audit-Only | Notes |
|-------------|---------|--------|-------------|------------|-------|
| Ubuntu | 22.04 LTS | 5.15+ | Yes* | Yes | Add `lsm=bpf` to boot params |
| Ubuntu | 24.04 LTS | 6.5+ | Yes* | Yes | Add `lsm=bpf` to boot params |
| Debian | 12 (Bookworm) | 6.1+ | Yes* | Yes | Add `lsm=bpf` to boot params |
| RHEL | 9.x | 5.14+ | Yes* | Yes | Add `lsm=bpf` to boot params |
| Fedora | 38+ | 6.2+ | Yes | Yes | BPF LSM often enabled by default |
| Arch Linux | Rolling | Latest | Yes* | Yes | Depends on kernel config |
| Amazon Linux | 2023 | 6.1+ | Yes* | Yes | Add `lsm=bpf` to boot params |

\* Requires adding `lsm=bpf` or `lsm=landlock,lockdown,yama,bpf` to kernel boot parameters.

Compatibility CI evidence and kernel/distro matrix source of truth are tracked
in `docs/PHASE4_PORTABILITY_EVIDENCE.md`.

## Distribution and Runtime Quirks

- **Ubuntu 22.04 (5.15)**: stable baseline for LSM hooks; ensure BTF package is present on custom kernels.
- **Ubuntu 24.04 (6.5+)**: newer libbpf/kernel combos are generally smoother for CO-RE.
- **RHEL 9.x (5.14)**: verify backported BPF features; some behavior differs from upstream 5.14 docs.
- **Container hosts**: run the agent in host PID/cgroup/mount namespaces for deterministic cgroup and path behavior.
- **Kubernetes**: privileged pods (or pods with host-level capabilities) are outside normal workload threat assumptions.

## Filesystem and Namespace Notes

- Path canonicalization is performed in the agent namespace at policy-apply time.
- Bind mounts and overlay filesystems can present alternative path views for the same inode.
- Inode-based rules remain the primary enforcement primitive; path-only expectations can diverge in namespaced setups.

## Enabling BPF LSM

### Method 1: GRUB (Recommended)

Edit `/etc/default/grub`:
```bash
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=landlock,lockdown,yama,bpf"
```

Then run:
```bash
sudo update-grub
sudo reboot
```

### Method 2: systemd-boot

Edit boot entry in `/boot/loader/entries/*.conf`:
```
options root=... lsm=landlock,lockdown,yama,bpf
```

### Verification

Check if BPF LSM is enabled:
```bash
cat /sys/kernel/security/lsm
# Should include "bpf"
```

Or use AegisBPF:
```bash
aegisbpf health
```

## Kernel Configuration Options

These kernel options are required or recommended:

| Option | Status | Purpose |
|--------|--------|---------|
| `CONFIG_BPF` | Required | Basic BPF support |
| `CONFIG_BPF_SYSCALL` | Required | BPF syscall |
| `CONFIG_BPF_JIT` | Recommended | JIT compilation for performance |
| `CONFIG_BPF_LSM` | Required for enforcement | BPF LSM support |
| `CONFIG_CGROUPS` | Required | cgroup support |
| `CONFIG_CGROUP_BPF` | Required | BPF cgroup support |
| `CONFIG_DEBUG_INFO_BTF` | Required | BTF generation |

Check kernel config:
```bash
# From /proc/config.gz (if available)
zcat /proc/config.gz | grep CONFIG_BPF

# From boot config
cat /boot/config-$(uname -r) | grep CONFIG_BPF
```

## Troubleshooting

### "BPF LSM not enabled"

1. Check current LSM list:
   ```bash
   cat /sys/kernel/security/lsm
   ```

2. Add `lsm=bpf` to boot parameters (see above)

3. Reboot and verify

### "BTF not found"

BTF is required for CO-RE (Compile Once, Run Everywhere) support.

1. Check for BTF:
   ```bash
   ls -la /sys/kernel/btf/vmlinux
   ```

2. If missing, you may need a kernel with `CONFIG_DEBUG_INFO_BTF=y`

### "cgroup v2 not available"

1. Check cgroup version:
   ```bash
   mount | grep cgroup
   # Should show cgroup2 on /sys/fs/cgroup
   ```

2. If using cgroup v1, migrate to v2 or use hybrid mode:
   ```bash
   # Add to kernel boot params
   systemd.unified_cgroup_hierarchy=1
   ```

### "bpffs not mounted"

Mount bpffs:
```bash
sudo mount -t bpf bpf /sys/fs/bpf
```

Or add to `/etc/fstab`:
```
bpf /sys/fs/bpf bpf defaults 0 0
```

## Feature Detection

AegisBPF automatically detects available features at startup. Use the health command to see detected capabilities:

```bash
aegisbpf health
```

Example output:
```
euid: 0
kernel_version: 6.5.0-44-generic
cgroup_v2: ok
bpffs: ok
btf: ok
bpf_obj_path: /home/user/aegisbpf/build/aegis.bpf.o
bpf_lsm_enabled: yes
ringbuf_support: yes
tracepoints: yes
enforcement_capability: Full
capability_explanation: Full enforcement available. BPF LSM is enabled, allowing file access to be blocked and processes to be killed.
break_glass_active: no
lsm_list: landlock,lockdown,yama,bpf,integrity
```

## Graceful Degradation

AegisBPF implements graceful degradation:

1. **Full LSM support**: Uses LSM hooks for enforcement
2. **No LSM but tracepoints**: Falls back to audit-only mode automatically
3. **Missing critical requirements**: Exits with clear error message

This ensures AegisBPF can provide value (at least audit logging) on systems without full BPF LSM support.
