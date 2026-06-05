// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

namespace aegis {

// Runtime mode for the Rust-parser cross-check, read from the AEGIS_RUST_SHADOW
// environment variable:
//   unset / anything else -> Off     (no-op; production default)
//   "1" or "shadow"       -> Shadow  (re-parse + log divergence; A2)
//   "enforce"             -> Enforce (consensus: a divergence fails the apply
//                                     CLOSED — the policy is rejected; A3)
enum class RustShadowMode { Off, Shadow, Enforce };

// Outcome of a Rust-parser cross-check. `ran` is false when the shadow is
// compiled out (no AEGIS_RUST_SHADOW) or the mode is Off; `diverged`/`enforce`
// are only meaningful when `ran` is true. When `ran && diverged && enforce`, the
// caller MUST fail the apply closed.
struct RustShadowOutcome {
    bool ran = false;
    bool diverged = false;
    bool enforce = false;
};

// Re-parse `policy_path` with the memory-safe Rust parser through its C ABI seam
// and compare its FULL canonical dump (version, flags, every stored entry, sorted
// errors/warnings) against the authoritative C++ canonical for the same file,
// logging a structured WARN on any divergence. In Enforce mode it additionally
// signals the caller to reject the policy (fail-closed); in Shadow mode it only
// logs. The C++ parse is always authoritative and this never alters the parsed
// policy content.
//
// No-op (returns `{false, false, false}`) unless BOTH:
//   * built with -DENABLE_RUST_PARSER_LINK=ON (defines AEGIS_RUST_SHADOW and links
//     the Rust staticlib), and
//   * AEGIS_RUST_SHADOW is set to a recognized value at runtime.
RustShadowOutcome rust_parse_shadow_compare(const std::string& policy_path);

// Decide the outcome from two already-computed canonical dumps under `mode`,
// logging like the real path. Exposed so the fail-closed logic is testable
// directly (the two parsers are proven equivalent, so a real divergence cannot be
// staged from a policy file). A no-op when built without AEGIS_RUST_SHADOW.
RustShadowOutcome rust_parse_shadow_decide(RustShadowMode mode, const std::string& cpp_canonical,
                                           const std::string& rust_canonical);

} // namespace aegis
