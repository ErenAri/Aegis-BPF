# AegisBPF Troubleshooting Guide

This document helps diagnose and resolve common issues with AegisBPF.

## Quick Diagnostics

Run the doctor command to identify issues:

```bash
sudo aegisbpf doctor
```

Basic health check (if you only need prerequisites):

```bash
sudo aegisbpf health
```

Optional environment verification:
```bash
scripts/verify_env.sh --strict
```

Smoke tests:
```bash
sudo scripts/smoke_enforce.sh
sudo scripts/smoke_audit_fallback.sh
```

Expected output for a healthy system:
```
euid: 0
cgroup_v2: ok
bpffs: ok
btf: ok
bpf_obj_path: /usr/lib/aegisbpf/aegis.bpf.o
bpf_lsm_enabled: yes
lsm_list: lockdown,capability,landlock,yama,bpf
kernel_config_bpf: y
kernel_config_bpf_syscall: y
kernel_config_bpf_jit: y
kernel_config_bpf_lsm: y
kernel_config_cgroups: y
kernel_config_cgroup_bpf: y
pins_present: deny_inode,deny_path,allow_cgroup,block_stats,agent_meta
layout_version: ok (1)
```

## Common Issues

### 1. "BPF LSM not enabled"

**Symptom:**
```
BPF LSM not enabled; falling back to tracepoint audit-only mode
```

**Cause:** The kernel was not booted with BPF LSM enabled.

**Solution:**

1. Check current LSM list:
   ```bash
   cat /sys/kernel/security/lsm
   ```

2. Add `bpf` to the kernel command line:
   ```bash
   # Edit GRUB configuration
   sudo vim /etc/default/grub

   # Add bpf to GRUB_CMDLINE_LINUX
   GRUB_CMDLINE_LINUX="lsm=lockdown,capability,landlock,yama,bpf"

   # Update GRUB
   sudo update-grub

   # Reboot
   sudo reboot
   ```

3. Verify after reboot:
   ```bash
   cat /sys/kernel/security/lsm | grep bpf
   ```

### 2. "Failed to load BPF object"

**Symptom:**
```
Failed to load BPF object: error: ...
```

**Possible Causes:**

#### Missing BTF

```bash
# Check BTF availability
ls -la /sys/kernel/btf/vmlinux
```

If missing, your kernel doesn't have BTF. Options:
- Use a kernel with CONFIG_DEBUG_INFO_BTF=y
- Ubuntu 20.04+, Fedora 31+, Debian 11+ have BTF by default

#### Permission Denied

```bash
# Check capabilities
capsh --print | grep -i bpf
```

Run as root or with required capabilities:
```bash
sudo setcap cap_sys_admin,cap_bpf,cap_perfmon+eip /usr/bin/aegisbpf
```

#### Missing BPF Object File

```bash
# Check if BPF object exists
ls -la /usr/lib/aegisbpf/aegis.bpf.o

# Set custom path if needed
export AEGIS_BPF_OBJ=/path/to/aegis.bpf.o
```

### 3. "Ring buffer poll failed"

**Symptom:**
```
Ring buffer poll failed: error_code=-12
```

**Cause:** Usually memory-related (ENOMEM = 12).

**Solution:**

1. Increase memlock limit:
   ```bash
   ulimit -l unlimited
   ```

2. Or set in systemd:
   ```ini
   [Service]
   LimitMEMLOCK=infinity
   ```

3. Or set system-wide:
   ```bash
   echo "* - memlock unlimited" | sudo tee -a /etc/security/limits.conf
   ```

### 4. "deny_inode_map not found"

**Symptom:**
```
deny_inode_map not found
```

**Cause:** BPF maps not pinned or pins corrupted.

**Solution:**

1. Clear pins and restart:
   ```bash
   sudo aegisbpf block clear
   sudo rm -rf /sys/fs/bpf/aegisbpf/
   sudo aegisbpf run
   ```

2. Check BPF filesystem is mounted:
   ```bash
   mount | grep bpf
   # Should show: bpf on /sys/fs/bpf type bpf
   ```

   If not mounted:
   ```bash
   sudo mount -t bpf bpf /sys/fs/bpf
   ```

### 5. "Layout version mismatch"

**Symptom:**
```
layout_version: mismatch (found 0, expected 1)
```

**Cause:** Map structure changed between versions.

**Solution:**

Clear all pins and restart:
```bash
sudo aegisbpf block clear
sudo aegisbpf run
```

### 6. Events Not Appearing

**Symptom:** Agent running but no events in logs.

**Possible Causes:**

#### Wrong Log Sink

```bash
# Check log configuration
sudo aegisbpf run --log=stdout  # See events immediately
```

#### Process in Allowed Cgroup

```bash
# List allowed cgroups
sudo aegisbpf allow list
```

#### No Matching Deny Rules

```bash
# List deny rules
sudo aegisbpf block list
```

### 7. High Ring Buffer Drops

**Symptom:**
```
ringbuf_drops: 12345
```

**Cause:** Events generated faster than userspace can process.

**Solutions:**

1. Reduce logging verbosity:
   ```bash
   sudo aegisbpf run --log-level=warn
   ```

2. Use journald instead of stdout (more efficient):
   ```bash
   sudo aegisbpf run --log=journald
   ```

3. Check for exec storm (legitimate or attack):
   ```bash
   sudo aegisbpf stats
   ```

### 8. Seccomp Failures

**Symptom:**
```
Failed to apply seccomp filter: ...
```

**Cause:** Seccomp-BPF not available or already applied.

**Solution:**

1. Check seccomp support:
   ```bash
   grep SECCOMP /boot/config-$(uname -r)
   ```

2. Run without seccomp if not needed:
   ```bash
   sudo aegisbpf run  # without --seccomp
   ```

### 9. Policy Apply Failures

**Symptom:**
```
Failed to apply policy: SHA256 mismatch
```

**Cause:** Policy file was modified after hash was computed.

**Solution:**

1. Recompute hash:
   ```bash
   sha256sum /etc/aegisbpf/policy.conf
   ```

2. Apply with new hash:
   ```bash
   sudo aegisbpf policy apply /etc/aegisbpf/policy.conf \
       --sha256 <new-hash>
   ```

### 10. Blocking Not Working

**Symptom:** Deny rules configured but executions not blocked.

**Checklist:**

1. **Verify BPF LSM is enabled:**
   ```bash
   cat /sys/kernel/security/lsm | grep bpf
   ```

2. **Verify enforce mode:**
   ```bash
   sudo aegisbpf run --enforce  # not --audit
   ```

3. **Check process cgroup isn't allowed:**
   ```bash
   cat /proc/$(pgrep -f some_process)/cgroup
   sudo aegisbpf allow list
   ```

4. **Verify deny rule exists:**
   ```bash
   sudo aegisbpf block list | grep /path/to/blocked
   ```

5. **Check inode matches:**
   ```bash
   stat /path/to/blocked
   sudo aegisbpf block list
   ```

## Debug Logging

Enable debug logging for detailed information:

```bash
sudo aegisbpf run --log-level=debug --log-format=json
```

## Kernel Debug

Use bpftool for low-level debugging:

```bash
# List loaded BPF programs
sudo bpftool prog list

# Show BPF maps
sudo bpftool map list

# Dump map contents
sudo bpftool map dump pinned /sys/fs/bpf/aegisbpf/deny_inode

# Trace BPF program execution
sudo bpftool prog tracelog
```

## Getting Help

If issues persist:

1. Collect diagnostic info:
   ```bash
   sudo aegisbpf health > aegisbpf-health.txt 2>&1
   uname -a >> aegisbpf-health.txt
   cat /sys/kernel/security/lsm >> aegisbpf-health.txt
   sudo dmesg | tail -100 >> aegisbpf-health.txt
   ```

2. Open an issue at: https://github.com/aegisbpf/aegisbpf/issues

Include:
- Health check output
- Kernel version
- Distribution and version
- Steps to reproduce
- Expected vs actual behavior
