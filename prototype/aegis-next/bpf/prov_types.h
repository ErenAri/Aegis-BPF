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

// Phase 3+ expanded hook coverage.
#define PROV_KIND_PTRACE          12 // ptrace_access_check
#define PROV_KIND_SETUID          13 // task_fix_setuid
#define PROV_KIND_RENAME          14 // inode_rename
#define PROV_KIND_UNLINK          15 // inode_unlink
#define PROV_KIND_SENDMSG         16 // socket_sendmsg

// ---- Phase 4: Advanced Features ----

// Event kinds for Phase 4 hooks.
#define PROV_KIND_FSVERITY_OK   9   // binary passed fsverity check
#define PROV_KIND_FSVERITY_FAIL 10  // binary failed fsverity check
#define PROV_KIND_RATE_LIMIT    11  // rate limit triggered

// Binary authorization verdict (stored in binary_auth_val.verdict).
#define AUTH_VERDICT_UNKNOWN     0  // not yet verified
#define AUTH_VERDICT_ALLOW       1  // trusted digest, allow exec
#define AUTH_VERDICT_DENY        2  // untrusted / no digest, deny
#define AUTH_VERDICT_LOG         3  // log but allow (audit mode)

// Binary authorization flags.
#define AUTH_FLAG_FSVERITY       (1u << 0)  // checked via fsverity digest
#define AUTH_FLAG_XATTR_CACHED   (1u << 1)  // result cached in xattr
#define AUTH_FLAG_PKCS7          (1u << 2)  // verified via PKCS7 signature

// Rate limiter defaults.
#define RATE_LIMIT_WINDOW_NS    (1000000000ULL)  // 1 second window
#define RATE_LIMIT_FORK_MAX     50   // max forks per window per cgroup
#define RATE_LIMIT_CONN_MAX     100  // max connects per window per cgroup

// Policy match type for binary auth (extends POLICY_MATCH_*).
#define POLICY_MATCH_DIGEST     4  // match by fsverity digest prefix

// Security xattr names (for bpf_get_file_xattr / bpf_set_dentry_xattr).
#define AEGIS_XATTR_VERIFIED    "security.aegis.verified"
#define AEGIS_XATTR_DIGEST      "security.aegis.digest"

// Digest sizes.
#define FSVERITY_DIGEST_MAX     64  // SHA-512 = 64 bytes
#define DIGEST_PREFIX_LEN       8   // first 8 bytes for map key

// user_ringbuf policy update message types.
#define POLICY_MSG_ADD          0  // add/update a rule
#define POLICY_MSG_DELETE       1  // delete a rule
#define POLICY_MSG_FLUSH        2  // flush all rules

#endif // AEGIS_NEXT_PROV_TYPES_H
