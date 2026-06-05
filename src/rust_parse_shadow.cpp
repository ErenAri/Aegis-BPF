// cppcheck-suppress-file missingIncludeSystem
/*
 * Rust-parser shadow comparison (A2 of the oxidation swap plan).
 *
 * When built with -DENABLE_RUST_PARSER_LINK=ON (which defines AEGIS_RUST_SHADOW
 * and links the memory-safe Rust parser staticlib) AND gated on at runtime by
 * AEGIS_RUST_SHADOW=1, this re-parses an applied policy through the Rust C ABI
 * seam and logs any divergence from the authoritative C++ parser. It is a pure
 * diagnostic: the C++ result stays authoritative and the applied policy is
 * unaffected. When the option is OFF (the default), this whole translation unit
 * compiles to a trivial no-op and the binary needs no Rust toolchain.
 */
#include "rust_parse_shadow.hpp"

#ifdef AEGIS_RUST_SHADOW
#    include "aegis_parser_ffi.h"

#    include <algorithm>
#    include <cstdint>
#    include <cstdlib>
#    include <fstream>
#    include <sstream>
#    include <vector>

#    include "logging.hpp"
#endif

namespace aegis {

#ifdef AEGIS_RUST_SHADOW

namespace {

struct ShadowSink {
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
};

extern "C" void shadow_add_error(void* ctx, const char* msg, size_t len)
{
    static_cast<ShadowSink*>(ctx)->errors.emplace_back(msg, len);
}
extern "C" void shadow_add_warning(void* ctx, const char* msg, size_t len)
{
    static_cast<ShadowSink*>(ctx)->warnings.emplace_back(msg, len);
}

// Runtime gate, re-read each call so tests (and operators) can toggle it.
bool shadow_gate_on()
{
    const char* v = std::getenv("AEGIS_RUST_SHADOW");
    return v != nullptr && std::string(v) == "1";
}

std::string slurp(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::vector<std::string> sorted(std::vector<std::string> v)
{
    std::sort(v.begin(), v.end());
    return v;
}

} // namespace

RustShadowOutcome rust_parse_shadow_compare(const std::string& policy_path, const PolicyIssues& issues)
{
    if (!shadow_gate_on()) {
        return {};
    }

    const std::string bytes = slurp(policy_path);
    ShadowSink rust;
    AegisPolicySink sink{};
    sink.ctx = &rust;
    sink.add_error = shadow_add_error;
    sink.add_warning = shadow_add_warning;

    const int rc = aegis_policy_parse(bytes.data(), bytes.size(), &sink);

    bool diverged = false;
    if (rc < 0) {
        // A bad-call / caught panic from the seam is itself a divergence worth
        // surfacing (it must never happen on a real apply).
        diverged = true;
        logger().log(SLOG_WARN("rust parse shadow: FFI returned a negative code")
                         .field("path", policy_path)
                         .field("rc", static_cast<int64_t>(rc)));
    } else {
        const bool count_ok = static_cast<size_t>(rc) == issues.errors.size();
        const bool errors_ok = sorted(rust.errors) == sorted(issues.errors);
        const bool warnings_ok = sorted(rust.warnings) == sorted(issues.warnings);
        diverged = !(count_ok && errors_ok && warnings_ok);
        if (diverged) {
            logger().log(SLOG_WARN("rust parse shadow: divergence vs authoritative C++ parser")
                             .field("path", policy_path)
                             .field("cpp_errors", static_cast<uint64_t>(issues.errors.size()))
                             .field("rust_errors", static_cast<uint64_t>(rust.errors.size()))
                             .field("cpp_warnings", static_cast<uint64_t>(issues.warnings.size()))
                             .field("rust_warnings", static_cast<uint64_t>(rust.warnings.size())));
        } else {
            logger().log(SLOG_DEBUG("rust parse shadow: agrees with C++ parser")
                             .field("path", policy_path)
                             .field("errors", static_cast<uint64_t>(issues.errors.size()))
                             .field("warnings", static_cast<uint64_t>(issues.warnings.size())));
        }
    }
    return {true, diverged};
}

#else // !AEGIS_RUST_SHADOW

RustShadowOutcome rust_parse_shadow_compare(const std::string& /*policy_path*/, const PolicyIssues& /*issues*/)
{
    return {};
}

#endif

} // namespace aegis
