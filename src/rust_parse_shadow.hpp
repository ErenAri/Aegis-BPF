// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

#include "types.hpp" // PolicyIssues

namespace aegis {

// Outcome of a Rust-parser shadow comparison. `ran` is false when the shadow is
// compiled out (no AEGIS_RUST_SHADOW) or the runtime gate is off; `diverged` is
// only meaningful when `ran` is true.
struct RustShadowOutcome {
    bool ran = false;
    bool diverged = false;
};

// Re-parse `policy_path` with the memory-safe Rust parser through its C ABI seam
// (`aegis_policy_parse`) and compare its errors/warnings against the authoritative
// C++ result `issues`, logging a structured WARN on any divergence. This is a
// DIAGNOSTIC shadow only: the C++ parser is always authoritative and this never
// affects control flow or the applied policy.
//
// It is a no-op (returns `{false, false}`) unless BOTH:
//   * the binary was built with -DENABLE_RUST_PARSER_LINK=ON (defines
//     AEGIS_RUST_SHADOW and links the Rust staticlib), and
//   * the `AEGIS_RUST_SHADOW=1` environment variable is set at runtime.
// So a default build has no Rust toolchain dependency and this call vanishes.
RustShadowOutcome rust_parse_shadow_compare(const std::string& policy_path, const PolicyIssues& issues);

} // namespace aegis
