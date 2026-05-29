// SPDX-License-Identifier: GPL-2.0
//
// aegis-next: agent self-protection via LSM hooks on BPF subsystem.
//
// P2.6 of the prototype roadmap. Prevents a privileged attacker from
// blinding the agent by detaching its programs or deleting its maps.
//
// Hooks:
//   lsm/bpf      — gates BPF syscall commands (PROG_DETACH, LINK_DETACH)
//   lsm/bpf_map  — gates map operations on protected maps
//
// Caller identity:
//   At startup, userspace stores the agent binary's inode number in
//   the trusted_inode map. Each hook reads the current task's binary
//   inode via bpf_get_current_task_btf() and compares. If the caller
//   is not the trusted binary, the sensitive operation is denied.
//
// This is a proof-of-concept: production would also check mount
// namespace, file hash (ima_inode_hash), and securityfs attributes.

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// BPF syscall command constants (from uapi/linux/bpf.h).
#define BPF_MAP_DELETE_ELEM   3
#define BPF_PROG_DETACH       8
#define BPF_LINK_DETACH      34

// Map holding the trusted binary's inode number.
// Element 0 = trusted inode. Set by userspace at load time.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);  // inode number
    __uint(max_entries, 1);
} aegis_selfprotect_trusted SEC(".maps");

// Enabled flag — allows userspace to disable protection for
// graceful shutdown. Element 0: 1 = active, 0 = disabled.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} aegis_selfprotect_enabled SEC(".maps");

// Read the current task's binary inode number.
static __always_inline __u64 current_exe_ino(void)
{
    struct task_struct *task = bpf_get_current_task_btf();
    if (!task)
        return 0;

    // task->mm->exe_file->f_inode->i_ino
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return 0;

    struct file *exe = BPF_CORE_READ(mm, exe_file);
    if (!exe)
        return 0;

    struct inode *ino = BPF_CORE_READ(exe, f_inode);
    if (!ino)
        return 0;

    return BPF_CORE_READ(ino, i_ino);
}

// Check if the current caller is the trusted agent binary.
static __always_inline bool is_trusted_caller(void)
{
    __u32 zero = 0;

    // Check if protection is enabled.
    __u32 *enabled = bpf_map_lookup_elem(&aegis_selfprotect_enabled, &zero);
    if (!enabled || *enabled == 0)
        return true;  // protection disabled — allow everything

    __u64 *trusted = bpf_map_lookup_elem(&aegis_selfprotect_trusted, &zero);
    if (!trusted || *trusted == 0)
        return true;  // no trusted inode set — allow everything

    __u64 caller_ino = current_exe_ino();
    return caller_ino == *trusted;
}

// lsm/bpf — called on BPF syscall operations.
// Deny sensitive commands (PROG_DETACH, LINK_DETACH) from non-trusted
// callers. This prevents an attacker from detaching our LSM programs.
SEC("lsm/bpf")
int BPF_PROG(aegis_selfprotect_bpf, int cmd, union bpf_attr *attr,
             unsigned int size)
{
    // Only gate sensitive commands.
    if (cmd != BPF_PROG_DETACH && cmd != BPF_LINK_DETACH)
        return 0;

    if (is_trusted_caller())
        return 0;

    return -1;  // EPERM
}

// lsm/bpf_map — called when a process accesses a BPF map.
// We deny write access (fmode & FMODE_WRITE) from non-trusted callers
// to any map. In production, we'd check the map name/id specifically;
// for the prototype, we only block when protection is enabled.
//
// Note: fmode_t is defined as unsigned int in the kernel.
SEC("lsm/bpf_map")
int BPF_PROG(aegis_selfprotect_bpf_map, struct bpf_map *map,
             fmode_t fmode)
{
    // Only protect write operations (delete, update from adversary).
    // FMODE_WRITE = 0x2
    if (!(fmode & 0x2))
        return 0;

    if (is_trusted_caller())
        return 0;

    return -1;  // EPERM
}

char LICENSE[] SEC("license") = "GPL";
