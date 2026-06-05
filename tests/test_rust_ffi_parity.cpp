// cppcheck-suppress-file missingIncludeSystem
/*
 * In-process FFI parity test for the memory-safe Rust decoders.
 *
 * Built only when -DENABLE_RUST_PARSER_LINK=ON. It links the Rust staticlib
 * (rust/aegis-parser, crate-type = staticlib) into a C++ binary and drives the
 * C ABI seams (src/aegis_parser_ffi.h <-> ffi.rs) IN-PROCESS, checking each agrees
 * with the authoritative C++ side on the same bytes:
 *   - aegis_policy_parse       vs the C++ policy parser (errors/warnings)
 *   - aegis_bundle_canonical   vs the C++ `policy bundle-canonical` emitter
 *   - aegis_event_canonical    vs the C++ `policy event-canonical` emitter
 *
 * This is strictly stronger evidence than the out-of-process differential parity
 * harnesses (scripts/rust_*_parity.sh): it exercises the real cargo->CMake link,
 * the real C ABI (struct layout, calling convention, length-carrying strings,
 * panic-never-crosses-FFI), and the real callback path — the exact seam a future
 * production swap would call. It does NOT touch the production enforcement path;
 * the C++ implementations stay authoritative.
 */
#include "aegis_parser_ffi.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "commands_policy.hpp"
#include "policy_parse.hpp"
#include "rust_parse_shadow.hpp"
#include "types.hpp"

namespace {

// Collects the strings the Rust FFI reports through the sink.
struct SinkCtx {
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
};

extern "C" void on_error(void* ctx, const char* msg, size_t len)
{
    static_cast<SinkCtx*>(ctx)->errors.emplace_back(msg, len);
}
extern "C" void on_warning(void* ctx, const char* msg, size_t len)
{
    static_cast<SinkCtx*>(ctx)->warnings.emplace_back(msg, len);
}

struct FfiResult {
    int rc;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
};

FfiResult run_rust_ffi(const std::string& bytes)
{
    SinkCtx sink_ctx;
    AegisPolicySink sink{};
    sink.ctx = &sink_ctx;
    sink.add_error = on_error;
    sink.add_warning = on_warning;
    int rc = aegis_policy_parse(bytes.data(), bytes.size(), &sink);
    return {rc, std::move(sink_ctx.errors), std::move(sink_ctx.warnings)};
}

// The authoritative C++ flow, identical to cmd_policy_canonical: parse the file,
// and (only on success) detect lint conflicts — matching what the Rust
// parse_policy(bytes, /*with_conflicts=*/true) the FFI calls does.
aegis::PolicyIssues run_cpp(const std::string& path)
{
    aegis::PolicyIssues issues;
    auto result = aegis::parse_policy_file(path, issues);
    if (result) {
        aegis::detect_policy_conflicts(*result, issues);
    }
    return issues;
}

std::vector<std::string> sorted(std::vector<std::string> v)
{
    std::sort(v.begin(), v.end());
    return v;
}

std::string read_file(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// Compare the Rust FFI seam against the C++ parser on the bytes of `path`.
void expect_ffi_matches_cpp(const std::string& path, const std::string& label)
{
    const std::string bytes = read_file(path);
    const FfiResult rust = run_rust_ffi(bytes);
    const aegis::PolicyIssues cpp = run_cpp(path);

    ASSERT_GE(rust.rc, 0) << label << ": FFI returned a negative (bad-call/panic) code";
    EXPECT_EQ(static_cast<size_t>(rust.rc), cpp.errors.size()) << label << ": FFI error count != C++ error count";
    EXPECT_EQ(sorted(rust.errors), sorted(cpp.errors)) << label << ": error sets diverge";
    EXPECT_EQ(sorted(rust.warnings), sorted(cpp.warnings)) << label << ": warning sets diverge";
}

// Write bytes to a unique temp file so the file-based C++ parser sees the same
// input the byte-based FFI does, run the cross-check, then clean up.
void expect_ffi_matches_cpp_inline(const std::string& bytes, const std::string& label)
{
    static int counter = 0;
    std::filesystem::path tmp =
        std::filesystem::temp_directory_path() / ("aegis_ffi_parity_" + std::to_string(counter++) + ".conf");
    {
        std::ofstream out(tmp, std::ios::binary);
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    }
    expect_ffi_matches_cpp(tmp.string(), label);
    std::error_code ec;
    std::filesystem::remove(tmp, ec);
}

} // namespace

// --- Pure-FFI correctness: the linked seam behaves correctly on its own --------

TEST(RustFfiParity, CleanPolicyReportsNoErrors)
{
    const std::string clean = "version = 6\n[deny_path]\n/etc/shadow\n";
    FfiResult r = run_rust_ffi(clean);
    EXPECT_EQ(r.rc, 0) << "clean policy should yield 0 errors";
    EXPECT_TRUE(r.errors.empty());
}

TEST(RustFfiParity, BadPolicyReportsErrorThroughSink)
{
    // An unsupported version is a hard error in both parsers.
    const std::string bad = "version = 999999\n";
    FfiResult r = run_rust_ffi(bad);
    EXPECT_GT(r.rc, 0) << "bad version should yield >=1 error";
    EXPECT_EQ(static_cast<size_t>(r.rc), r.errors.size());
    EXPECT_FALSE(r.errors.empty());
}

TEST(RustFfiParity, NullSinkAndEmptyInputAreHandled)
{
    // Null sink -> defined negative code, never a crash.
    EXPECT_LT(aegis_policy_parse("x", 1, nullptr), 0);
    // Empty input via a valid sink -> no crash, non-negative.
    FfiResult empty = run_rust_ffi("");
    EXPECT_GE(empty.rc, 0);
}

// --- In-process agreement with the C++ parser ---------------------------------

TEST(RustFfiParity, AgreesWithCppOnInlineCases)
{
    expect_ffi_matches_cpp_inline("version = 6\n[deny_path]\n/etc/shadow\n[deny_ip]\n10.0.0.1\n", "clean_v6");
    expect_ffi_matches_cpp_inline("version = 999999\n", "bad_version");
    expect_ffi_matches_cpp_inline("[unknown_section]\nfoo\n", "unknown_section");
    expect_ffi_matches_cpp_inline("", "empty");
    expect_ffi_matches_cpp_inline("# comment only\nversion = 6\n", "comment_only");
    expect_ffi_matches_cpp_inline("version = 6\n[deny_port]\n80/tcp\n443\n22/udp:bind\n", "ports");
}

TEST(RustFfiParity, AgreesWithCppOnCommittedCorpus)
{
#ifdef AEGIS_SOURCE_DIR
    const std::filesystem::path root(AEGIS_SOURCE_DIR);
    const std::filesystem::path dirs[] = {
        root / "tests" / "fixtures" / "parity",
        root / "examples" / "policies",
    };
    size_t checked = 0;
    for (const auto& dir : dirs) {
        std::error_code ec;
        if (!std::filesystem::is_directory(dir, ec)) {
            continue;
        }
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            expect_ffi_matches_cpp(entry.path().string(), entry.path().filename().string());
            ++checked;
        }
    }
    // The committed parity fixtures must exist, so this never silently no-ops.
    EXPECT_GT(checked, 0u) << "no corpus policies found under " << root;
#else
    GTEST_SKIP() << "AEGIS_SOURCE_DIR not defined";
#endif
}

// --- bundle + event canonical seams -------------------------------------------
// aegis_bundle_canonical / aegis_event_canonical emit the same canonical decode
// dump the differential-parity harnesses compare. Here we drive them through the
// real link and check the dump matches the C++ canonical commands IN-PROCESS.

namespace {

extern "C" void on_emit(void* ctx, const char* dump, size_t len)
{
    static_cast<std::string*>(ctx)->assign(dump, len);
}

using CanonicalFfi = int (*)(const char*, size_t, AegisEmitFn, void*);

std::string rust_canonical(CanonicalFfi fn, const std::string& bytes, const std::string& label)
{
    std::string out;
    int rc = fn(bytes.data(), bytes.size(), on_emit, &out);
    EXPECT_GE(rc, 0) << label << ": FFI returned a negative (bad-call/panic) code";
    return out;
}

// Capture stdout of a `policy *-canonical` command run on a temp file of `bytes`
// (the commands are the authoritative C++ canonical emitters; they take a path).
std::string cpp_command_canonical(int (*cmd)(const std::string&), const std::string& bytes)
{
    static int counter = 0;
    std::filesystem::path tmp =
        std::filesystem::temp_directory_path() / ("aegis_ffi_canon_" + std::to_string(counter++) + ".bin");
    {
        std::ofstream out(tmp, std::ios::binary);
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    }
    std::ostringstream sink;
    std::streambuf* old = std::cout.rdbuf(sink.rdbuf());
    cmd(tmp.string());
    std::cout.rdbuf(old);
    std::error_code ec;
    std::filesystem::remove(tmp, ec);
    return sink.str();
}

void expect_seam_matches(CanonicalFfi ffi, int (*cmd)(const std::string&), const std::string& bytes,
                         const std::string& label)
{
    EXPECT_EQ(rust_canonical(ffi, bytes, label), cpp_command_canonical(cmd, bytes))
        << label << ": canonical seam diverges";
}

// Cross-check every file in `<src>/tests/fixtures/<sub>` through the seam.
size_t check_fixture_dir(const char* sub, CanonicalFfi ffi, int (*cmd)(const std::string&))
{
    size_t checked = 0;
#ifdef AEGIS_SOURCE_DIR
    const std::filesystem::path dir = std::filesystem::path(AEGIS_SOURCE_DIR) / "tests" / "fixtures" / sub;
    std::error_code ec;
    if (std::filesystem::is_directory(dir, ec)) {
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            expect_seam_matches(ffi, cmd, read_file(entry.path().string()), entry.path().filename().string());
            ++checked;
        }
    }
#endif
    return checked;
}

} // namespace

TEST(RustFfiParity, BundleSeamAgreesWithCpp)
{
    expect_seam_matches(aegis_bundle_canonical, aegis::cmd_policy_bundle_canonical,
                        "AEGIS-POLICY-BUNDLE-V1\nformat_version: 1\npolicy_version: 7\n---\nversion=1\n", "valid");
    expect_seam_matches(aegis_bundle_canonical, aegis::cmd_policy_bundle_canonical, "no separator here", "missing_sep");
    expect_seam_matches(aegis_bundle_canonical, aegis::cmd_policy_bundle_canonical, "WRONG-HEADER\n---\nx\n",
                        "bad_header");
    expect_seam_matches(aegis_bundle_canonical, aegis::cmd_policy_bundle_canonical, "", "empty");
    check_fixture_dir("bundle_parity", aegis_bundle_canonical, aegis::cmd_policy_bundle_canonical);
}

TEST(RustFfiParity, EventSeamAgreesWithCpp)
{
    expect_seam_matches(aegis_event_canonical, aegis::cmd_policy_event_canonical, "", "empty");
    expect_seam_matches(aegis_event_canonical, aegis::cmd_policy_event_canonical, std::string(3, '\0'), "short");
    expect_seam_matches(aegis_event_canonical, aegis::cmd_policy_event_canonical, std::string(344, '\0'), "all_zero");
    const size_t checked = check_fixture_dir("event_parity", aegis_event_canonical, aegis::cmd_policy_event_canonical);
    EXPECT_GT(checked, 0u) << "no event fixtures found";
}

// --- the runtime Rust-parser shadow (A2) --------------------------------------
// rust_parse_shadow_compare() is the diagnostic shadow inserted at the production
// policy-apply call site. Here we drive it directly: gated on it must agree with
// the C++ parser on a clean policy, flag an injected divergence, and be a no-op
// when the runtime gate is off. (Exercises the same link + seam, off the real
// enforcement path.)

TEST(RustFfiParity, ShadowComparesAndGates)
{
#ifdef AEGIS_RUST_SHADOW
    // A clean policy: write it, get the authoritative C++ issues the apply path
    // would have (parse + conflicts), then run the shadow against them.
    const std::string policy = "version = 6\n[deny_path]\n/etc/shadow\n[deny_ip]\n10.0.0.1\n";
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / "aegis_shadow_test.conf";
    {
        std::ofstream out(tmp, std::ios::binary);
        out.write(policy.data(), static_cast<std::streamsize>(policy.size()));
    }
    const aegis::PolicyIssues authoritative = run_cpp(tmp.string());

    // Gated ON: the Rust seam must AGREE with the authoritative C++ result.
    ::setenv("AEGIS_RUST_SHADOW", "1", 1);
    const aegis::RustShadowOutcome ok = aegis::rust_parse_shadow_compare(tmp.string(), authoritative);
    EXPECT_TRUE(ok.ran);
    EXPECT_FALSE(ok.diverged) << "Rust shadow should agree with C++ on a clean policy";

    // Inject a bogus authoritative error -> the shadow must FLAG the divergence.
    aegis::PolicyIssues wrong = authoritative;
    wrong.errors.emplace_back("injected bogus error that Rust will not produce");
    const aegis::RustShadowOutcome diverged = aegis::rust_parse_shadow_compare(tmp.string(), wrong);
    EXPECT_TRUE(diverged.ran);
    EXPECT_TRUE(diverged.diverged) << "shadow should flag a mismatch vs the authoritative result";

    // Gated OFF: no-op regardless of input.
    ::unsetenv("AEGIS_RUST_SHADOW");
    const aegis::RustShadowOutcome off = aegis::rust_parse_shadow_compare(tmp.string(), authoritative);
    EXPECT_FALSE(off.ran) << "shadow must be inert when AEGIS_RUST_SHADOW is unset";

    std::error_code ec;
    std::filesystem::remove(tmp, ec);
#else
    GTEST_SKIP() << "built without AEGIS_RUST_SHADOW";
#endif
}
