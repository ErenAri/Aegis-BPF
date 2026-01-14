# AegisBPF

eBPF LSM agent that enforces inode-based deny rules in `lsm/file_open`, kills offenders synchronously (SIGKILL + `-EPERM`), and exempts trusted workloads via cgroup-based allowlisting. Events are emitted over a ring buffer and per-CPU counters track blocks and ringbuf drops.

## Requirements

- Kernel with BPF LSM, cgroup v2 (unified hierarchy mounted at `/sys/fs/cgroup`), bpffs at `/sys/fs/bpf`, and BTF at `/sys/kernel/btf/vmlinux`.
- Verify `/sys/kernel/security/lsm` contains `bpf`; otherwise BPF LSM hooks will not fire.
- If `bpf` is missing from `/sys/kernel/security/lsm`, enable it by adding `bpf` to the kernel `lsm=` boot parameter (e.g., `lsm=landlock,lockdown,yama,bpf,integrity,apparmor`) or rebuilding with `CONFIG_BPF_LSM=y`.
- Root privileges (CAP_SYS_ADMIN) to load LSM programs and manage cgroups.
- Ubuntu build deps:
  ```
  sudo apt-get update
  sudo apt-get install -y clang llvm libbpf-dev bpftool libelf-dev zlib1g-dev libzstd-dev pkg-config cmake make g++ linux-headers-$(uname -r)
  ```

## Build

```
cmake -S . -B build -G Ninja
cmake --build build
```

## Run the agent

```
sudo ./build/aegisbpf run
# Audit-only (log without kill/EPERM)
sudo ./build/aegisbpf run --audit
```

If BPF LSM is not enabled, the agent automatically falls back to tracepoint audit-only mode
(no enforcement). In that mode, file access auditing matches raw `openat` path strings and
may not resolve relative paths.

Startup does the following:
- Verifies cgroup v2 and bpffs mounts.
- Loads BPF and pins maps under `/sys/fs/bpf/aegisbpf`.
- Creates `/sys/fs/cgroup/aegis_agent`, moves the agent PID into it, and allows that cgroup via `allow_cgroup_map`.
- Attaches `lsm/path_open` (enforcement) plus fork/exit/exec lineage tracking.

## Manage deny rules (inode/device based)

```
sudo ./build/aegisbpf block add /etc/shadow
sudo ./build/aegisbpf block list
sudo ./build/aegisbpf block del /etc/shadow
sudo ./build/aegisbpf block clear   # clears pins and DB, resets counters
```

In tracepoint audit fallback, path matching uses raw `openat` strings. Use absolute paths to
avoid mismatches; the agent stores both the canonical path and the raw input string.

State is persisted in:
- `/sys/fs/bpf/aegisbpf/deny_inode`
- `/sys/fs/bpf/aegisbpf/deny_path`
- `/sys/fs/bpf/aegisbpf/allow_cgroup`
- `/sys/fs/bpf/aegisbpf/block_stats`
- `/sys/fs/bpf/aegisbpf/deny_cgroup_stats`
- `/sys/fs/bpf/aegisbpf/deny_inode_stats`
- `/sys/fs/bpf/aegisbpf/deny_path_stats`
- `/sys/fs/bpf/aegisbpf/agent_meta`
- `/var/lib/aegisbpf/deny.db` (dev/ino + optional path notes)

## Manage allowlist (cgroup based)

```
sudo ./build/aegisbpf allow add /sys/fs/cgroup/my_service
sudo ./build/aegisbpf allow list
sudo ./build/aegisbpf allow del /sys/fs/cgroup/my_service
```

## Stats

```
sudo ./build/aegisbpf stats
```

Outputs counts of deny inode/path/allow entries plus per-CPU aggregated `blocks` and `ringbuf_drops`, and per-cgroup/per-inode/per-path block counters (with best-effort cgroup path resolution).

## Event format

Ring buffer events are newline-delimited JSON:
- EXEC: `{"type":"exec","pid":123,"ppid":1,"start_time":1234567890,"cgid":987,"cgroup_path":"/sys/fs/cgroup/...", "comm":"bash"}`
- BLOCK: `{"type":"block","pid":123,"ppid":1,"start_time":1234,"parent_start_time":5678,"cgid":987,"cgroup_path":"/sys/fs/cgroup/...", "path":"/tmp/foo","resolved_path":"/tmp/foo","ino":42,"dev":2049,"action":"KILL","comm":"cat"}` (action is `AUDIT` when running with `--audit` or in tracepoint fallback)

## Smoke test

A runnable smoke test (needs root, will start the agent):

```
sudo scripts/smoke_block.sh
```

It starts the agent, blocks a temp file, attempts to read it (expects KILL/EPERM), prints stats, and cleans up.

If BPF LSM is not enabled, use the audit fallback smoke test instead:

```
sudo scripts/smoke_audit_fallback.sh
```
