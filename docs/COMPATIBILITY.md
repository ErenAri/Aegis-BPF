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

### Feature Requirements by Kernel Version

| Feature | Min Kernel | Impact if Missing |
|---------|------------|------------------|
| BPF LSM | 5.7+ | **No enforcement** - audit-only mode |
| Ring Buffer | 5.8+ | Perf event array fallback (higher overhead) |
| **Socket Caching** | **5.2+** | **30-40% higher network overhead** |
| Process Tracking | 5.8+ | Tracepoint fallback (path-only, no blocking) |

**Critical:** Kernel 5.2+ required for `BPF_MAP_TYPE_SK_STORAGE` used in network policy socket caching. On older kernels, BPF program load will **fail** with helpful error message.

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
- Optional enforce signal (`SIGTERM` by default, configurable to `SIGKILL`, `SIGINT`, or none)
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

## Kernel Version Feature Matrix

| Kernel | LSM Enforce | Socket Caching | Ring Buffer | Performance | Status |
|--------|-------------|----------------|-------------|-------------|--------|
| 6.8+ (Ubuntu 24.04) | ✅ | ✅ | ✅ | **Optimal** (<30% overhead) | ✅ **Recommended** |
| 6.1-6.7 | ✅ | ✅ | ✅ | **Optimal** (<30% overhead) | ✅ Supported |
| 5.8-6.0 | ✅ | ✅ | ✅ | **Optimal** (<30% overhead) | ✅ Supported |
| 5.7 | ✅ | ✅ | ❌ | Good (~35% overhead, no socket cache) | ⚠️ Degraded |
| 5.2-5.6 | ❌ | ✅ | ❌ | Audit-only | ⚠️ Limited |
| 4.18 (RHEL 8) | ❌ | ❌ | ❌ | **Not Supported** | ❌ **Incompatible** |

**Enterprise Impact:**
- **RHEL 8 (kernel 4.18):** ❌ Not supported - socket storage map will fail to load
- **RHEL 9 (kernel 5.14):** ✅ Supported but LSM may need manual enable
- **Ubuntu 22.04+ / Debian 12+:** ✅ Full support

## Distribution Compatibility

| Distribution | Version | Kernel | Socket Caching | LSM Enforce | Status |
|-------------|---------|--------|----------------|-------------|--------|
| Ubuntu | 24.04 LTS | 6.8+ | ✅ | Yes* | ✅ **Recommended** |
| Ubuntu | 22.04 LTS | 5.15+ | ✅ | Yes* | ✅ Supported |
| Debian | 12 (Bookworm) | 6.1+ | ✅ | Yes* | ✅ Supported |
| RHEL | 9.x | 5.14+ | ✅ | Yes* | ✅ Supported |
| RHEL | 8.x | 4.18 | ❌ | No | ❌ **Not Supported** |
| Fedora | 38+ | 6.2+ | ✅ | Yes | ✅ Supported |
| Arch Linux | Rolling | Latest | ✅ | Yes* | ✅ Supported |
| Amazon Linux | 2023 | 6.1+ | ✅ | Yes* | ✅ Supported |
| Flatcar | Stable | 6.6+ | ✅ | Yes* | ✅ Supported |

\* Requires adding `lsm=bpf` or `lsm=landlock,lockdown,yama,bpf` to kernel boot parameters.

## Distribution and Runtime Quirks

- **Ubuntu 22.04 (6.8 HWE in CI)**: stable baseline for LSM hooks; ensure BTF package is present on custom kernels.
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
