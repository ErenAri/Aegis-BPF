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
#include "rust_policy_build.hpp"
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

// The policy-canonical seam feeds the shadow/consensus; it must match the C++
// `policy canonical` command (the full structural-equivalence surface).
TEST(RustFfiParity, PolicyCanonicalSeamAgreesWithCpp)
{
    expect_seam_matches(aegis_policy_canonical, aegis::cmd_policy_canonical,
                        "version = 6\n[deny_path]\n/etc/shadow\n[deny_ip]\n10.0.0.1\n", "clean_v6");
    expect_seam_matches(aegis_policy_canonical, aegis::cmd_policy_canonical, "version = 999999\n", "bad_version");
    expect_seam_matches(aegis_policy_canonical, aegis::cmd_policy_canonical, "", "empty");
    expect_seam_matches(aegis_policy_canonical, aegis::cmd_policy_canonical,
                        "version = 6\n[deny_port]\n80/tcp\n443\n22/udp:bind\n", "ports");
    check_fixture_dir("parity", aegis_policy_canonical, aegis::cmd_policy_canonical);
}

// --- the runtime Rust-parser shadow + consensus (A2/A3) -----------------------
// rust_parse_shadow_compare() is inserted at the production policy-apply call
// site: `shadow` mode logs canonical divergence; `enforce` mode signals the
// caller to reject the apply (fail-closed). The decision logic is exercised
// directly with crafted canonicals (the two parsers are proven equivalent, so a
// real divergence cannot be staged from a policy file), and the happy path is
// exercised end-to-end on a real policy.

TEST(RustFfiParity, ShadowConsensusDecisionAndGating)
{
#ifdef AEGIS_RUST_SHADOW
    using aegis::rust_parse_shadow_decide;
    using aegis::RustShadowMode;

    // Agreement: never diverged; `enforce` flag tracks the mode.
    EXPECT_FALSE(rust_parse_shadow_decide(RustShadowMode::Shadow, "x", "x").diverged);
    {
        const auto o = rust_parse_shadow_decide(RustShadowMode::Enforce, "x", "x");
        EXPECT_TRUE(o.ran);
        EXPECT_FALSE(o.diverged);
        EXPECT_TRUE(o.enforce);
    }
    // Divergence in shadow mode: flagged, but not an enforce/fail-closed signal.
    {
        const auto o = rust_parse_shadow_decide(RustShadowMode::Shadow, "a", "b");
        EXPECT_TRUE(o.ran);
        EXPECT_TRUE(o.diverged);
        EXPECT_FALSE(o.enforce);
    }
    // Divergence in enforce mode: THIS is the fail-closed signal the apply path
    // acts on (ran && diverged && enforce -> reject the policy).
    {
        const auto o = rust_parse_shadow_decide(RustShadowMode::Enforce, "a", "b");
        EXPECT_TRUE(o.ran);
        EXPECT_TRUE(o.diverged);
        EXPECT_TRUE(o.enforce);
    }
    // Off: no-op.
    EXPECT_FALSE(rust_parse_shadow_decide(RustShadowMode::Off, "a", "b").ran);

    // Integration: a real clean policy must AGREE in both gated modes — crucially,
    // enforce must NOT reject a valid policy — and be a no-op when the gate is off.
    const std::string policy = "version = 6\n[deny_path]\n/etc/shadow\n[deny_ip]\n10.0.0.1\n";
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / "aegis_shadow_a3.conf";
    {
        std::ofstream out(tmp, std::ios::binary);
        out.write(policy.data(), static_cast<std::streamsize>(policy.size()));
    }
    ::setenv("AEGIS_RUST_SHADOW", "shadow", 1);
    {
        const auto o = aegis::rust_parse_shadow_compare(tmp.string());
        EXPECT_TRUE(o.ran);
        EXPECT_FALSE(o.diverged) << "shadow: Rust must agree with C++ on a clean policy";
        EXPECT_FALSE(o.enforce);
    }
    ::setenv("AEGIS_RUST_SHADOW", "enforce", 1);
    {
        const auto o = aegis::rust_parse_shadow_compare(tmp.string());
        EXPECT_TRUE(o.ran);
        EXPECT_FALSE(o.diverged) << "enforce must NOT reject a valid (agreeing) policy";
        EXPECT_TRUE(o.enforce);
    }
    ::unsetenv("AEGIS_RUST_SHADOW");
    EXPECT_FALSE(aegis::rust_parse_shadow_compare(tmp.string()).ran) << "inert when the gate is unset";

    std::error_code ec;
    std::filesystem::remove(tmp, ec);
#else
    GTEST_SKIP() << "built without AEGIS_RUST_SHADOW";
#endif
}

// --- whole-Policy transport / reconstruction (the full-flip mechanism, A-final)
// rust_build_policy() parses with the memory-safe Rust parser via the
// aegis_policy_build seam and reconstructs the structured C++ Policy. This proves
// the reconstructed Policy is byte-identical (by canonical content) to the
// C++-parsed one — the correctness gate for making Rust the authoritative content
// source. NOT wired into the apply path; this is the staged capability + proof.

namespace {

void expect_policy_build_matches(const std::string& bytes, const std::string& label)
{
    // C++ authoritative parse (path-based).
    static int counter = 0;
    std::filesystem::path tmp =
        std::filesystem::temp_directory_path() / ("aegis_build_" + std::to_string(counter++) + ".conf");
    {
        std::ofstream out(tmp, std::ios::binary);
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    }
    aegis::PolicyIssues issues;
    auto cpp = aegis::parse_policy_file(tmp.string(), issues);
    std::error_code ec;
    std::filesystem::remove(tmp, ec);

    // Rust parse + structured reconstruction (bytes-based).
    aegis::Policy rust_policy;
    const bool built = aegis::rust_build_policy(bytes, rust_policy);

    if (!cpp || issues.has_errors()) {
        // C++ rejected it -> Rust must build nothing either.
        EXPECT_FALSE(built) << label << ": Rust built a policy where C++ parse failed";
        return;
    }
    ASSERT_TRUE(built) << label << ": Rust failed to build a policy that C++ parsed cleanly";
    EXPECT_EQ(aegis::policy_entries_canonical(*cpp), aegis::policy_entries_canonical(rust_policy))
        << label << ": reconstructed Rust Policy diverges from the C++ Policy";
}

} // namespace

TEST(RustFfiParity, RustBuiltPolicyMatchesCpp)
{
#ifdef AEGIS_RUST_SHADOW
    // Exercise every category + flag through the transport + reconstruction.
    expect_policy_build_matches("version = 6\n", "minimal");
    expect_policy_build_matches("version = 6\n[deny_path]\n/etc/shadow\n/root\n", "deny_paths");
    expect_policy_build_matches("version = 6\n[deny_ip]\n10.0.0.1\n[deny_cidr]\n10.0.0.0/8\n", "ip_cidr");
    expect_policy_build_matches("version = 6\n[deny_port]\n80:tcp\n443\n22:udp:bind\n", "ports");
    expect_policy_build_matches("version = 6\n[deny_ip_port]\n1.2.3.4:443:tcp\n", "ip_port");
    expect_policy_build_matches("version = 6\n[cgroup_deny_inode]\n/sys/fs/cgroup/x 10:20\n", "cgroup_inode");
    expect_policy_build_matches("version = 6\n[cgroup_deny_port]\n/sys/fs/cgroup/y 22:tcp:bind\n", "cgroup_port");
    expect_policy_build_matches("version = 6\n[deny_ptrace]\n[deny_bpf]\n", "flags");
    expect_policy_build_matches("version = 999999\n", "bad_version_rejected");
    expect_policy_build_matches("", "empty");

    // The committed corpus exercises the full field surface (all_categories_v6, etc.).
    size_t checked = 0;
#    ifdef AEGIS_SOURCE_DIR
    const std::filesystem::path root(AEGIS_SOURCE_DIR);
    for (const auto& sub : {std::string("tests/fixtures/parity"), std::string("examples/policies")}) {
        const std::filesystem::path dir = root / sub;
        std::error_code ec;
        if (!std::filesystem::is_directory(dir, ec)) {
            continue;
        }
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            expect_policy_build_matches(read_file(entry.path().string()), entry.path().filename().string());
            ++checked;
        }
    }
#    endif
    EXPECT_GT(checked, 0u) << "no corpus policies found for the build-equivalence test";
#else
    GTEST_SKIP() << "built without AEGIS_RUST_SHADOW";
#endif
}

// The flip (opt-in, default-off): `authoritative` mode sources the applied policy
// from the Rust parser — but only when the canonical compare AGREES, so it can
// never enforce content differing from C++. The apply-path integration needs
// root/BPF, so here we test its components: the decision logic + that the policy
// the apply path would source (rust_build_policy_from_path) equals the C++ one.
TEST(RustFfiParity, AuthoritativeFlipSourcesEquivalentPolicy)
{
#ifdef AEGIS_RUST_SHADOW
    using aegis::rust_parse_shadow_decide;
    using aegis::RustShadowMode;

    // Agreement: fail-closed armed AND authoritative set (the apply path would
    // then source content from Rust).
    {
        const auto o = rust_parse_shadow_decide(RustShadowMode::Authoritative, "x", "x");
        EXPECT_TRUE(o.ran);
        EXPECT_FALSE(o.diverged);
        EXPECT_TRUE(o.enforce);
        EXPECT_TRUE(o.authoritative);
    }
    // Divergence under authoritative: fail-closed (the apply path rejects; it
    // NEVER sources differing content).
    {
        const auto o = rust_parse_shadow_decide(RustShadowMode::Authoritative, "a", "b");
        EXPECT_TRUE(o.diverged);
        EXPECT_TRUE(o.enforce);
        EXPECT_TRUE(o.authoritative);
    }

    // Integration on a real clean policy: the compare agrees + flags authoritative,
    // and the policy the apply path would source equals the C++-parsed one.
    const std::string policy = "version = 6\n[deny_path]\n/etc/shadow\n[deny_port]\n443:tcp\n[deny_ip]\n10.0.0.1\n";
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / "aegis_authoritative.conf";
    {
        std::ofstream out(tmp, std::ios::binary);
        out.write(policy.data(), static_cast<std::streamsize>(policy.size()));
    }
    ::setenv("AEGIS_RUST_SHADOW", "authoritative", 1);
    const auto outcome = aegis::rust_parse_shadow_compare(tmp.string());
    EXPECT_TRUE(outcome.ran);
    EXPECT_FALSE(outcome.diverged) << "authoritative must agree with C++ on a clean policy";
    EXPECT_TRUE(outcome.authoritative);

    aegis::Policy rust_policy;
    ASSERT_TRUE(aegis::rust_build_policy_from_path(tmp.string(), rust_policy));
    aegis::PolicyIssues issues;
    auto cpp = aegis::parse_policy_file(tmp.string(), issues);
    ASSERT_TRUE(cpp);
    EXPECT_EQ(aegis::policy_entries_canonical(*cpp), aegis::policy_entries_canonical(rust_policy))
        << "the Rust-sourced policy the apply path would enforce must equal the C++ one";

    ::unsetenv("AEGIS_RUST_SHADOW");
    std::error_code ec;
    std::filesystem::remove(tmp, ec);
#else
    GTEST_SKIP() << "built without AEGIS_RUST_SHADOW";
#endif
}
