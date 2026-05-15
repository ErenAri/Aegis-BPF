// SPDX-License-Identifier: GPL-2.0
//
// Shared constants between BPF and userspace for the aegis-next
// provenance graph. This header is valid C (not C++), uses no
// kernel types, and is included by both provenance.bpf.c and
// aegis_next_prov.hpp.

#ifndef AEGIS_NEXT_PROV_TYPES_H
#define AEGIS_NEXT_PROV_TYPES_H

// Event kind stored in prov_node.kind.
#define PROV_KIND_EXEC            0
#define PROV_KIND_FILE_OPEN       1
#define PROV_KIND_SOCKET_CONNECT  2
#define PROV_KIND_SOCKET_BIND     3
#define PROV_KIND_SOCKET_LISTEN   4
#define PROV_KIND_FILE_PERM       5  // file_permission (FIM)
#define PROV_KIND_MMAP_FILE       6  // mmap_file (W+X prevention)
#define PROV_KIND_TASK_ALLOC      7  // task_alloc (fork bomb)
#define PROV_KIND_KMOD_REQ        8  // kernel_module_request

// prov_node.extra interpretation per kind:
//   EXEC:           0 (unused)
//   FILE_OPEN:      open flags (O_RDONLY, O_WRONLY, ...)
//   SOCKET_*:       address family (AF_INET, AF_INET6, ...)

// prov_node.path_slab_idx:
//   0    = no path resolved
//   1..N = 1-based index into path_slab[]

// prov_node.net_slab_idx:
//   0    = no network flow
//   1..N = 1-based index into net_slab[]

// Path slab geometry.
#define PATH_SLAB_SLOTS   (1u << 12)  // 4096
#define PATH_SLAB_SLOT_SZ 256

// Network flow slab geometry.
#define NET_SLAB_SLOTS    (1u << 12)  // 4096
#define NET_SLAB_SLOT_SZ  48

// Ringbuf geometry.
#define AEGIS_RINGBUF_PAGES  512  // 2MB (512 × 4K)

// Policy match types (policy_key.match_type).
#define POLICY_MATCH_COMM     0  // match by comm name hash
#define POLICY_MATCH_PATH     1  // match by path prefix hash
#define POLICY_MATCH_PORT     2  // match by destination port
#define POLICY_MATCH_CGROUP   3  // match by cgroup ID (low 32 bits)

// Policy actions (policy_val.action).
#define POLICY_ACTION_ALLOW      0
#define POLICY_ACTION_DENY       1
#define POLICY_ACTION_LOG        2
#define POLICY_ACTION_QUARANTINE 3

// Policy flags (policy_val.flags).
#define POLICY_FLAG_KILL  (1u << 0)  // send SIGKILL after deny

#endif // AEGIS_NEXT_PROV_TYPES_H
