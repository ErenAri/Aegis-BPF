// cppcheck-suppress-file missingIncludeSystem
/*
 * Rust-parser cross-check: the shadow (A2) and consensus/enforce (A3) modes.
 *
 * When built with -DENABLE_RUST_PARSER_LINK=ON (which defines AEGIS_RUST_SHADOW
 * and links the memory-safe Rust parser staticlib) AND gated at runtime by
 * AEGIS_RUST_SHADOW, this re-parses an applied policy through the Rust C ABI seam
 * and compares its FULL canonical dump against the authoritative C++ canonical:
 *
 *   AEGIS_RUST_SHADOW=shadow|1  -> log any divergence (diagnostic only).
 *   AEGIS_RUST_SHADOW=enforce   -> a divergence makes the caller reject the apply
 *                                  (fail-closed) — the memory-safe parser gains
 *                                  authoritative VETO power over what is applied.
 *
 * The C++ parse stays authoritative for the policy CONTENT; this never changes
 * the parsed policy. When the option is OFF (the default), the whole translation
 * unit compiles to a no-op and the binary needs no Rust toolchain.
 */
#include "rust_parse_shadow.hpp"

#ifdef AEGIS_RUST_SHADOW
#    include "aegis_parser_ffi.h"

#    include <cstdlib>
#    include <fstream>
#    include <sstream>
#    include <string>

#    include "commands_policy.hpp" // policy_canonical_dump_from_path
#    include "logging.hpp"
#endif

namespace aegis {

#ifdef AEGIS_RUST_SHADOW

namespace {

RustShadowMode parse_mode()
{
    const char* v = std::getenv("AEGIS_RUST_SHADOW");
    if (v == nullptr) {
        return RustShadowMode::Off;
    }
    const std::string s(v);
    if (s == "authoritative") {
        return RustShadowMode::Authoritative;
    }
    if (s == "enforce") {
        return RustShadowMode::Enforce;
    }
    if (s == "1" || s == "shadow") {
        return RustShadowMode::Shadow;
    }
    return RustShadowMode::Off;
}

std::string slurp(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

void emit_to_string(void* ctx, const char* dump, size_t len)
{
    static_cast<std::string*>(ctx)->assign(dump, len);
}

} // namespace

RustShadowOutcome rust_parse_shadow_decide(RustShadowMode mode, const std::string& cpp_canonical,
                                           const std::string& rust_canonical)
{
    if (mode == RustShadowMode::Off) {
        return {};
    }
    // Both Enforce and Authoritative fail the apply closed on divergence;
    // Authoritative additionally sources the applied content from Rust on agreement.
    const bool enforce = (mode == RustShadowMode::Enforce || mode == RustShadowMode::Authoritative);
    const bool authoritative = (mode == RustShadowMode::Authoritative);
    const bool diverged = (cpp_canonical != rust_canonical);
    if (diverged) {
        logger().log(SLOG_WARN("rust parse shadow: canonical divergence vs authoritative C++ parser")
                         .field("enforce", enforce)
                         .field("authoritative", authoritative)
                         .field("cpp_canonical_len", static_cast<uint64_t>(cpp_canonical.size()))
                         .field("rust_canonical_len", static_cast<uint64_t>(rust_canonical.size())));
    } else {
        logger().log(SLOG_DEBUG("rust parse shadow: canonical agrees with C++ parser"));
    }
    return {true, diverged, enforce, authoritative};
}

RustShadowOutcome rust_parse_shadow_compare(const std::string& policy_path)
{
    const RustShadowMode mode = parse_mode();
    if (mode == RustShadowMode::Off) {
        return {};
    }

    // Authoritative C++ canonical for this file, and the Rust seam's canonical for
    // the same bytes. These match iff the two parsers agree on the full structure
    // (proven equivalent by scripts/rust_policy_parity.sh over the corpus + fuzz).
    const std::string cpp_canonical = policy_canonical_dump_from_path(policy_path);

    const std::string bytes = slurp(policy_path);
    std::string rust_canonical;
    const int rc = aegis_policy_canonical(bytes.data(), bytes.size(), emit_to_string, &rust_canonical);
    if (rc < 0) {
        // A bad-call / caught panic must never happen on a real apply; treat it as
        // a divergence so Enforce mode fails closed.
        logger().log(SLOG_WARN("rust parse shadow: FFI returned a negative code")
                         .field("path", policy_path)
                         .field("rc", static_cast<int64_t>(rc)));
        const bool enforce = (mode == RustShadowMode::Enforce || mode == RustShadowMode::Authoritative);
        // An FFI failure is a divergence; never source content from it.
        return {true, true, enforce, false};
    }
    return rust_parse_shadow_decide(mode, cpp_canonical, rust_canonical);
}

#else // !AEGIS_RUST_SHADOW

RustShadowOutcome rust_parse_shadow_compare(const std::string& /*policy_path*/)
{
    return {};
}

RustShadowOutcome rust_parse_shadow_decide(RustShadowMode /*mode*/, const std::string& /*cpp_canonical*/,
                                           const std::string& /*rust_canonical*/)
{
    return {};
}

#endif

} // namespace aegis
