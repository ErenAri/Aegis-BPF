/* C ABI for the memory-safe Rust policy parser (rust/aegis-parser, module `ffi`).
 *
 * This header is the hand-written counterpart to `rust/aegis-parser/src/ffi.rs`
 * and MUST stay in lockstep with it (the struct field order and the function
 * signature are the ABI contract). It is the staged integration seam for the C++
 * agent: the eventual production swap calls `aegis_policy_parse` here instead of
 * the C++ parser. Until then it is exercised only by the in-process FFI parity
 * test (built when -DENABLE_RUST_PARSER_LINK=ON), which links the Rust staticlib
 * and checks the seam agrees with the C++ parser.
 */
#ifndef AEGIS_PARSER_FFI_H
#define AEGIS_PARSER_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Callback sink. Every (msg, len) pair is valid only for the duration of the
 * call and carries an explicit length — the text may contain interior NUL bytes
 * from adversarial input, so consumers MUST honor `len` rather than treat `msg`
 * as a C string. `add_error` / `add_warning` may be NULL. */
typedef struct AegisPolicySink {
    void* ctx;
    void (*add_error)(void* ctx, const char* msg, size_t len);
    void (*add_warning)(void* ctx, const char* msg, size_t len);
} AegisPolicySink;

/* Parse `len` bytes of policy text, reporting each error and warning through
 * `sink`. Returns the number of errors (0 == clean), or a negative code on a bad
 * call / caught panic (-1 bad arguments, -2 panic). Never unwinds across FFI. */
int aegis_policy_parse(const char* text, size_t len, const AegisPolicySink* sink);

/* Emit callback for a canonical decode dump. The `len` bytes at `dump` are valid
 * ONLY for the duration of the call (copy if needed afterwards); they are ASCII
 * but consumers should honor `len` rather than assume NUL-termination. */
typedef void (*AegisEmitFn)(void* ctx, const char* dump, size_t len);

/* Decode a signed-policy-bundle header (`aegis_bundle_canonical`) or a BPF
 * ring-buffer event record (`aegis_event_canonical`) from `len` bytes and emit
 * the canonical decode dump through `emit`. The dump encodes both success and
 * failure (e.g. `err <message>` / `err short_buffer` / `unknown_type`), so parse
 * failures are NOT reported as a negative return. Returns 0 on success, -1 on a
 * bad call, -2 on a caught panic. Never unwinds across FFI. */
int aegis_bundle_canonical(const char* data, size_t len, AegisEmitFn emit, void* ctx);
int aegis_event_canonical(const char* data, size_t len, AegisEmitFn emit, void* ctx);

/* Parse `len` bytes of policy text and emit its FULL canonical dump (version,
 * flags, every stored entry in every category, sorted errors/warnings) through
 * `emit` — the structural-equivalence surface the consensus/enforce mode compares
 * against the C++ canonical. Returns 0 on success, -1 bad call, -2 panic. */
int aegis_policy_canonical(const char* data, size_t len, AegisEmitFn emit, void* ctx);

/* ---- whole-policy transport (the content surface for the eventual swap) ----
 * `aegis_policy_build` parses policy text and, on a clean parse, transports every
 * field of the resulting policy through the callbacks below. The CATEGORY ids
 * (add_string) and FLAG ids (set_flag) are the ABI contract — they MUST match
 * ffi.rs. Compound categories carry their canonical string form (the C side
 * reconstructs the struct from it); the formats are:
 *   AEGIS_PCAT_DENY_INODE        "dev:ino"
 *   AEGIS_PCAT_DENY_IP_PORT      "ip|port|proto"
 *   AEGIS_PCAT_CGROUP_DENY_INODE "cgroup|dev:ino"
 *   AEGIS_PCAT_CGROUP_DENY_IP    "cgroup|ip"
 */
enum {
    AEGIS_PCAT_DENY_PATH = 0,
    AEGIS_PCAT_PROTECT_PATH = 1,
    AEGIS_PCAT_DENY_INODE = 2,
    AEGIS_PCAT_ALLOW_CGROUP_PATH = 3,
    AEGIS_PCAT_DENY_IP = 4,
    AEGIS_PCAT_DENY_CIDR = 5,
    AEGIS_PCAT_DENY_IP_PORT = 6,
    AEGIS_PCAT_DENY_BINARY_HASH = 7,
    AEGIS_PCAT_ALLOW_BINARY_HASH = 8,
    AEGIS_PCAT_TRUSTED_EXEC_HASH = 9,
    AEGIS_PCAT_DENY_COMM = 10,
    AEGIS_PCAT_SCAN_PATH = 11,
    AEGIS_PCAT_CGROUP_DENY_INODE = 12,
    AEGIS_PCAT_CGROUP_DENY_IP = 13
};
enum {
    AEGIS_PFLAG_PROTECT_CONNECT = 0,
    AEGIS_PFLAG_PROTECT_RUNTIME_DEPS = 1,
    AEGIS_PFLAG_REQUIRE_IMA_APPRAISAL = 2,
    AEGIS_PFLAG_IMA_FAIL_CLOSED = 3,
    AEGIS_PFLAG_DENY_PTRACE = 4,
    AEGIS_PFLAG_DENY_MODULE_LOAD = 5,
    AEGIS_PFLAG_DENY_BPF = 6,
    AEGIS_PFLAG_NETWORK_ENABLED = 7,
    AEGIS_PFLAG_CGROUP_ENABLED = 8
};

typedef struct AegisPolicyBuilder {
    void* ctx;
    void (*set_version)(void* ctx, uint64_t version);
    void (*set_flag)(void* ctx, uint32_t flag_id);
    void (*add_string)(void* ctx, uint32_t category, const char* s, size_t len);
    void (*add_cgroup_id)(void* ctx, uint64_t id);
    void (*add_deny_port)(void* ctx, uint16_t port, uint8_t proto, uint8_t dir);
    void (*add_cgroup_deny_port)(void* ctx, const char* cgroup, size_t cgroup_len, uint16_t port, uint8_t proto,
                                 uint8_t dir);
} AegisPolicyBuilder;

/* Returns the number of errors (0 == a clean policy was built via `builder`;
 * >0 == parse failed and nothing was built), or -1 bad call / -2 panic. */
int aegis_policy_build(const char* text, size_t len, const AegisPolicyBuilder* builder);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AEGIS_PARSER_FFI_H */
