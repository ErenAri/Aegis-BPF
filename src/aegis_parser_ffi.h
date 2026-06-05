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

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AEGIS_PARSER_FFI_H */
