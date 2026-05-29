// SPDX-License-Identifier: GPL-2.0
//
// aegis-next: in-kernel binary authorization via fsverity + xattr cache.
//
// Phase 4 of the prototype roadmap. This is the single most
// differentiated feature in aegis-next — no competitor (Falco,
// Tetragon, Tracee, KubeArmor) performs binary integrity verification
// entirely in-kernel.
//
// Pipeline (per exec):
//   1. bpf_get_file_xattr("security.aegis.verified") → cache hit?
//      → YES: read cached verdict, skip to step 5.
//      → NO:  continue to step 2.
//
//   2. bpf_get_fsverity_digest(file) → extract digest.
//      → FAIL: file has no fsverity enabled → deny or log (policy).
//
//   3. Look up digest prefix in trusted_digests BPF_MAP_TYPE_HASH.
//      → MISS: untrusted binary → deny.
//      → HIT:  continue to step 4.
//
//   4. (Optional) bpf_verify_pkcs7_signature() against system keyring.
//      → FAIL: signature invalid → deny.
//
//   5. bpf_set_dentry_xattr("security.aegis.verified", verdict)
//      → Cache the result for subsequent opens (avoids re-verification).
//
//   6. Return verdict (allow / deny / log).
//
// Kernel requirements:
//   - bpf_get_fsverity_digest:    6.7+  (CONFIG_FS_VERITY)
//   - bpf_get_file_xattr:        6.8+
//   - bpf_set_dentry_xattr:      6.13+ (optional, for caching)
//   - bpf_verify_pkcs7_signature: 6.1+  (CONFIG_SYSTEM_DATA_VERIFICATION)
//
// All kfuncs declared __weak so the program loads even when the kernel
// lacks the config. Userspace probes availability at startup.

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "prov_types.h"

// ---- kfunc declarations (weak — absent at runtime is OK) --------

// fsverity: get the Merkle tree root digest for a file.
// Returns 0 on success, negative on error.
// digest_p points to a caller-provided buffer.
// digest_p->digest_size is set by the kernel on return.
extern int bpf_get_fsverity_digest(struct file *file,
                                    struct bpf_dynptr *digest_p) __ksym __weak;

// xattr: read an extended attribute from a file.
// Returns the number of bytes read, or negative on error.
extern int bpf_get_file_xattr(struct file *file, const char *name__str,
                               struct bpf_dynptr *value_p) __ksym __weak;

// xattr: write an extended attribute on a dentry.
// Returns 0 on success, negative on error.
extern int bpf_set_dentry_xattr(struct dentry *dentry, const char *name__str,
                                 const struct bpf_dynptr *value_p,
                                 int flags) __ksym __weak;

// PKCS7: verify a signature against a trusted keyring.
// Returns 0 if valid, negative on error.
extern int bpf_verify_pkcs7_signature(struct bpf_dynptr *data_p,
                                       struct bpf_dynptr *sig_p,
                                       struct bpf_key *trusted_keyring) __ksym __weak;

// Keyring: acquire a reference to a trusted keyring.
extern struct bpf_key *bpf_lookup_system_key(__u64 id) __ksym __weak;
extern void bpf_key_put(struct bpf_key *bkey) __ksym __weak;

// ---- maps -------------------------------------------------------

// Trusted digest map: digest prefix (8 bytes) → auth verdict + flags.
// Populated by userspace from a signed manifest of trusted binaries.
struct digest_key {
    __u8 prefix[DIGEST_PREFIX_LEN];  // first 8 bytes of fsverity digest
};

struct digest_val {
    __u8  verdict;   // AUTH_VERDICT_*
    __u8  flags;     // AUTH_FLAG_*
    __u16 _pad;
    __u32 _reserved;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct digest_key);
    __type(value, struct digest_val);
    __uint(max_entries, 16384);  // up to 16K trusted binaries
} aegis_trusted_digests SEC(".maps");

// Auth stats: per-CPU counters for observability.
// [0]=allowed, [1]=denied, [2]=cache_hit, [3]=no_verity, [4]=sig_fail
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 8);
} aegis_auth_stats SEC(".maps");

// Auth mode: [0] = 0 (enforce), 1 (audit/log-only), 2 (disabled).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} aegis_auth_mode SEC(".maps");

// Ringbuf for auth events (shares with provenance or separate).
struct auth_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 uid;
    __u8  verdict;     // AUTH_VERDICT_*
    __u8  flags;       // AUTH_FLAG_*
    __u8  digest[FSVERITY_DIGEST_MAX];
    __u16 digest_size;
    char  comm[16];
    char  path[128];   // truncated path for the alert
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1048576);  // 1MB
} aegis_auth_ringbuf SEC(".maps");

// ---- helpers ----------------------------------------------------

static __always_inline void bump_auth_stat(__u32 idx)
{
    __u64 *cnt = bpf_map_lookup_elem(&aegis_auth_stats, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

static __always_inline __u32 get_auth_mode(void)
{
    __u32 zero = 0;
    __u32 *mode = bpf_map_lookup_elem(&aegis_auth_mode, &zero);
    return mode ? *mode : 0;
}

// Emit an auth event to the ringbuf for userspace logging.
static __always_inline void
emit_auth_event(__u8 verdict, __u8 flags, const __u8 *digest,
                __u16 digest_size, struct task_struct *task)
{
    struct auth_event *evt;
    evt = bpf_ringbuf_reserve(&aegis_auth_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return;

    evt->ts_ns = bpf_ktime_get_ns();
    evt->pid = BPF_CORE_READ(task, tgid);
    evt->uid = BPF_CORE_READ(task, cred, uid.val);
    evt->verdict = verdict;
    evt->flags = flags;
    evt->digest_size = digest_size;

    bpf_probe_read_kernel(evt->comm, sizeof(evt->comm), &task->comm);

    if (digest && digest_size > 0) {
        __u16 copy_len = digest_size;
        if (copy_len > FSVERITY_DIGEST_MAX)
            copy_len = FSVERITY_DIGEST_MAX;
        // Variable-length memcpy not supported in BPF; use probe_read_kernel.
        bpf_probe_read_kernel(evt->digest, copy_len, digest);
    } else {
        __builtin_memset(evt->digest, 0, sizeof(evt->digest));
    }

    // Path is filled by the caller if available.
    __builtin_memset(evt->path, 0, sizeof(evt->path));

    bpf_ringbuf_submit(evt, 0);
}

// ---- LSM hook: binary authorization on exec ---------------------

SEC("lsm.s/bprm_check_security")
int BPF_PROG(aegis_binary_auth, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)
        return ret;

    __u32 mode = get_auth_mode();
    if (mode >= 2)  // disabled
        return 0;

    struct file *file = bprm->file;
    if (!file)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    __u8 verdict = AUTH_VERDICT_UNKNOWN;
    __u8 flags = 0;

    // ---- Step 1: Check xattr cache ----
    // If bpf_get_file_xattr is available, check for a cached verdict.
    if (bpf_get_file_xattr) {
        __u8 cached_verdict = 0;
        struct bpf_dynptr xattr_val;
        bpf_dynptr_from_mem(&cached_verdict, sizeof(cached_verdict),
                            0, &xattr_val);
        int xret = bpf_get_file_xattr(file, AEGIS_XATTR_VERIFIED,
                                        &xattr_val);
        if (xret == sizeof(cached_verdict) && cached_verdict != AUTH_VERDICT_UNKNOWN) {
            // Cache hit — use cached verdict.
            verdict = cached_verdict;
            flags |= AUTH_FLAG_XATTR_CACHED;
            bump_auth_stat(2); // cache_hit
            goto decision;
        }
    }

    // ---- Step 2: Get fsverity digest ----
    if (!bpf_get_fsverity_digest) {
        // Kernel lacks fsverity support — allow (can't verify).
        bump_auth_stat(3); // no_verity
        return 0;
    }

    {
        // Buffer for the digest. fsverity_digest struct:
        //   __u16 digest_algorithm;
        //   __u16 digest_size;
        //   __u8  digest[];
        // We use a flat buffer and parse manually.
        __u8 digest_buf[4 + FSVERITY_DIGEST_MAX];
        struct bpf_dynptr digest_dynptr;

        __builtin_memset(digest_buf, 0, sizeof(digest_buf));
        bpf_dynptr_from_mem(digest_buf, sizeof(digest_buf), 0, &digest_dynptr);

        int dret = bpf_get_fsverity_digest(file, &digest_dynptr);
        if (dret < 0) {
            // File has no fsverity enabled.
            bump_auth_stat(3); // no_verity
            // In enforce mode, deny unsigned binaries.
            // In audit mode, log and allow.
            verdict = (mode == 0) ? AUTH_VERDICT_DENY : AUTH_VERDICT_LOG;
            flags |= AUTH_FLAG_FSVERITY;
            emit_auth_event(verdict, flags, NULL, 0, task);
            goto decision;
        }

        // Parse digest: first 2 bytes = algorithm, next 2 = size, rest = digest.
        __u16 digest_size = 0;
        __builtin_memcpy(&digest_size, &digest_buf[2], 2);
        if (digest_size > FSVERITY_DIGEST_MAX)
            digest_size = FSVERITY_DIGEST_MAX;
        __u8 *digest = &digest_buf[4];

        flags |= AUTH_FLAG_FSVERITY;

        // ---- Step 3: Look up digest in trusted map ----
        struct digest_key dkey = {};
        // Copy first DIGEST_PREFIX_LEN bytes of digest as map key.
        #pragma unroll
        for (int i = 0; i < DIGEST_PREFIX_LEN; i++) {
            if (i < digest_size)
                dkey.prefix[i] = digest[i];
        }

        struct digest_val *dval = bpf_map_lookup_elem(&aegis_trusted_digests,
                                                       &dkey);
        if (dval) {
            // Trusted digest found.
            verdict = dval->verdict;
            flags |= dval->flags;
        } else {
            // Unknown digest — not in trusted list.
            verdict = (mode == 0) ? AUTH_VERDICT_DENY : AUTH_VERDICT_LOG;
        }

        // ---- Step 4: Cache result in xattr ----
        if (bpf_set_dentry_xattr && verdict != AUTH_VERDICT_UNKNOWN) {
            struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
            if (dentry) {
                struct bpf_dynptr cache_val;
                bpf_dynptr_from_mem(&verdict, sizeof(verdict), 0, &cache_val);
                bpf_set_dentry_xattr(dentry, AEGIS_XATTR_VERIFIED,
                                      &cache_val, 0);
            }
        }

        emit_auth_event(verdict, flags, digest, digest_size, task);
    }

decision:
    if (verdict == AUTH_VERDICT_DENY) {
        bump_auth_stat(1); // denied
        if (mode == 0)  // enforce
            return -1;  // -EPERM
    } else if (verdict == AUTH_VERDICT_ALLOW || verdict == AUTH_VERDICT_LOG) {
        bump_auth_stat(0); // allowed
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
