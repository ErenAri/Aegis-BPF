// cppcheck-suppress-file missingIncludeSystem
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <unordered_set>

#include <sys/stat.h>

#include "binary_scan.hpp"
#include "bpf_config.hpp"
#include "bpf_ops.hpp"
#include "logging.hpp"
#include "network_ops.hpp"
#include "policy.hpp"
#include "policy_slots.hpp"
#include "rust_parse_shadow.hpp"
#include "rust_policy_build.hpp"
#include "sha256.hpp"
#include "tracing.hpp"
#include "utils.hpp"

namespace aegis {

namespace {

thread_local std::string g_policy_trace_id;

class PolicyTraceScope {
  public:
    explicit PolicyTraceScope(std::string trace_id) : previous_(std::move(g_policy_trace_id))
    {
        g_policy_trace_id = std::move(trace_id);
    }

    ~PolicyTraceScope() { g_policy_trace_id = previous_; }

  private:
    std::string previous_;
};

std::string active_policy_trace_id()
{
    if (!g_policy_trace_id.empty()) {
        return g_policy_trace_id;
    }
    return make_span_id("trace-policy");
}

std::string env_or_default_path(const char* env_name, const char* fallback)
{
    const char* env = std::getenv(env_name);
    if (env && *env) {
        return std::string(env);
    }
    return fallback;
}

std::string policy_applied_path()
{
    return env_or_default_path("AEGIS_POLICY_APPLIED_PATH", kPolicyAppliedPath);
}

std::string policy_applied_prev_path()
{
    return env_or_default_path("AEGIS_POLICY_APPLIED_PREV_PATH", kPolicyAppliedPrevPath);
}

std::string policy_applied_hash_path()
{
    return env_or_default_path("AEGIS_POLICY_APPLIED_HASH_PATH", kPolicyAppliedHashPath);
}

} // namespace

Result<void> record_applied_policy(const std::string& path, const std::string& hash)
{
    const std::string applied_path = policy_applied_path();
    const std::string applied_prev_path = policy_applied_prev_path();
    const std::string applied_hash_path = policy_applied_hash_path();

    auto db_result = ensure_db_dir();
    if (!db_result) {
        return db_result.error();
    }

    std::error_code ec;
    if (std::filesystem::exists(applied_path, ec)) {
        std::filesystem::copy_file(applied_path, applied_prev_path, std::filesystem::copy_options::overwrite_existing,
                                   ec);
        if (ec) {
            return Error(ErrorCode::IoError, "Failed to backup applied policy", ec.message());
        }
    }

    std::ifstream in(path);
    if (!in.is_open()) {
        return Error::system(errno, "Failed to open policy file for recording");
    }
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

    auto write_result = atomic_write_file(applied_path, content);
    if (!write_result) {
        return write_result.error();
    }

    if (!hash.empty()) {
        auto hash_result = atomic_write_file(applied_hash_path, hash + "\n");
        if (!hash_result) {
            return hash_result.error();
        }
    } else {
        std::error_code rm_ec;
        std::filesystem::remove(applied_hash_path, rm_ec);
        if (rm_ec) {
            return Error(ErrorCode::IoError, "Failed to remove policy hash file", rm_ec.message());
        }
    }
    return {};
}

// cppcheck-suppress constParameterReference
Result<void> reset_policy_maps(BpfState& state)
{
    // deny_inode is slotted: a reload builds a fresh, empty inner map, so
    // there is nothing to clear here. Clearing the live map would degrade
    // enforcement, which is exactly what the slot design removes.
    TRY(clear_map_entries(state.deny_path));
    TRY(clear_map_entries(state.allow_cgroup));
    TRY(clear_map_entries(state.allow_exec_inode));
    if (state.trusted_exec_hash) {
        TRY(clear_map_entries(state.trusted_exec_hash));
    }
    TRY(clear_map_entries(state.deny_cgroup_stats));
    TRY(clear_map_entries(state.deny_inode_stats));
    TRY(clear_map_entries(state.deny_path_stats));
    TRY(set_exec_identity_mode(state, false));
    TRY(set_exec_identity_flags(state, 0));

    if (state.block_stats) {
        TRY(reset_block_stats_map(state.block_stats));
    }

    if (state.deny_ipv4) {
        TRY(clear_map_entries(state.deny_ipv4));
    }
    if (state.deny_ipv6) {
        TRY(clear_map_entries(state.deny_ipv6));
    }
    if (state.deny_port) {
        TRY(clear_map_entries(state.deny_port));
    }
    if (state.deny_ip_port_v4) {
        TRY(clear_map_entries(state.deny_ip_port_v4));
    }
    if (state.deny_ip_port_v6) {
        TRY(clear_map_entries(state.deny_ip_port_v6));
    }
    if (state.deny_cidr_v4) {
        TRY(clear_map_entries(state.deny_cidr_v4));
    }
    if (state.deny_cidr_v6) {
        TRY(clear_map_entries(state.deny_cidr_v6));
    }

    // Cgroup-scoped deny maps
    if (state.deny_cgroup_inode) {
        TRY(clear_map_entries(state.deny_cgroup_inode));
    }
    if (state.deny_cgroup_ipv4) {
        TRY(clear_map_entries(state.deny_cgroup_ipv4));
    }
    if (state.deny_cgroup_port) {
        TRY(clear_map_entries(state.deny_cgroup_port));
    }

    std::error_code ec;
    std::filesystem::remove(kDenyDbPath, ec);
    return {};
}

Result<void> apply_policy_internal_impl_fn(const std::string& path, const std::string& computed_hash, bool reset,
                                           bool record)
{
    ScopedSpan root_span("policy.apply_internal", active_policy_trace_id());
    auto fail = [&](const Error& err) -> Result<void> {
        root_span.fail(err.to_string());
        return err;
    };

    uint64_t pending_generation = 0; // set before sync, committed after verify

    Policy policy{};
    {
        ScopedSpan span("policy.parse", root_span.trace_id(), root_span.span_id());
        PolicyIssues issues;
        auto policy_result = parse_policy_file(path, issues);
        report_policy_issues(issues);
#ifdef AEGIS_RUST_SHADOW
        // Cross-check the parse with the memory-safe Rust parser (gated by the
        // AEGIS_RUST_SHADOW env var): `shadow` logs divergence; `enforce` rejects
        // the apply (fail-closed) on divergence; `authoritative` additionally
        // sources the applied policy CONTENT from Rust on agreement (the flip).
        // The C++ parse remains authoritative by default. Compiled out (and the
        // binary needs no Rust toolchain) unless built with
        // -DENABLE_RUST_PARSER_LINK=ON.
        const RustShadowOutcome rust_shadow = rust_parse_shadow_compare(path);
        if (rust_shadow.ran && rust_shadow.diverged && rust_shadow.enforce) {
            Error err(ErrorCode::PolicyParseFailed,
                      "Rust/C++ parser canonical divergence; rejecting policy (fail-closed)");
            span.fail(err.to_string());
            return fail(err);
        }
#endif
        if (!policy_result) {
            span.fail(policy_result.error().to_string());
            return fail(policy_result.error());
        }
        policy = *policy_result;
#ifdef AEGIS_RUST_SHADOW
        // The flip (opt-in, default-off): in `authoritative` mode, and ONLY when
        // the canonical comparison above AGREED (so the Rust policy is proven equal
        // to the C++ one for this file), source the applied content from the
        // memory-safe parser. By construction it can never enforce a policy that
        // differs from what the C++ parser produced.
        if (rust_shadow.ran && rust_shadow.authoritative && !rust_shadow.diverged) {
            Policy rust_policy;
            if (rust_build_policy_from_path(path, rust_policy)) {
                policy = std::move(rust_policy);
                logger().log(SLOG_INFO("policy content sourced from the memory-safe Rust parser (authoritative mode)")
                                 .field("path", path));
            }
        }
#endif
    }

    {
        ScopedSpan span("policy.bump_memlock", root_span.trace_id(), root_span.span_id());
        auto rlimit_result = bump_memlock_rlimit();
        if (!rlimit_result) {
            span.fail(rlimit_result.error().to_string());
            return fail(rlimit_result.error());
        }
    }

    BpfState state;
    {
        ScopedSpan span("policy.load_bpf", root_span.trace_id(), root_span.span_id());
        auto load_result = load_bpf(true, false, state);
        if (!load_result) {
            span.fail(load_result.error().to_string());
            return fail(load_result.error());
        }
    }

    {
        ScopedSpan span("policy.ensure_layout_version", root_span.trace_id(), root_span.span_id());
        auto version_result = ensure_layout_version(state);
        if (!version_result) {
            span.fail(version_result.error().to_string());
            return fail(version_result.error());
        }
    }

    DenyEntries entries;
    // Runtime deny rules that survived from the previous generation and must be
    // re-installed into the new one. Populated below; written into the shadow
    // maps once they exist.
    DenyEntries carried_runtime_rules;
    size_t dropped_stale_runtime_rules = 0;
    {
        ScopedSpan span("policy.prepare_entries", root_span.trace_id(), root_span.span_id());
        entries = reset ? DenyEntries{} : read_deny_db();

        // Runtime-rule carry-forward.
        //
        // `aegis block add` writes straight into the live generation and
        // persists the rule in the deny database. A reload builds a BRAND NEW
        // inner map, so unlike the old copy-into-live path there is nothing for
        // those rules to survive in: every one has to be re-installed, or the
        // reload silently un-blocks whatever an operator blocked by hand.
        //
        // Each carried rule is re-validated against the filesystem rather than
        // trusted. A recorded (device, inode) that no longer resolves to the
        // recorded path names something that no longer exists, or a different
        // file that has since taken the inode number -- re-installing it would
        // block the wrong object. Those are DROPPED, counted and logged, and
        // the pruned set is what gets persisted.
        //
        // Dropping rather than failing is deliberate. A vanished temp file is
        // not a policy error, and failing the commit would wedge every future
        // reload behind a file that will never come back -- a state this
        // codebase has already been observed to reach in practice.
        if (!reset) {
            carried_runtime_rules = prune_stale_runtime_rules(
                read_runtime_rules(), dropped_stale_runtime_rules,
                [](const std::string& path, const std::string& reason) {
                    logger().log(
                        SLOG_WARN("Dropping stale runtime deny rule").field("path", path).field("reason", reason));
                });
            // The accounting set must match what will actually be installed.
            // Previous-generation POLICY rules are deliberately not carried:
            // replacing them is what a reload is for. Only hand-added runtime
            // rules survive.
            entries = carried_runtime_rules;
            if (dropped_stale_runtime_rules > 0) {
                (void)write_runtime_rules(carried_runtime_rules);
            }
            if (dropped_stale_runtime_rules > 0) {
                logger().log(SLOG_WARN("Pruned stale runtime deny rules during policy reload")
                                 .field("dropped", static_cast<int64_t>(dropped_stale_runtime_rules))
                                 .field("carried", static_cast<int64_t>(carried_runtime_rules.size())));
            }
        }
    }

    std::vector<BinaryScanResult> allow_binary_matches;
    if (!policy.allow_binary_hashes.empty()) {
        ScopedSpan span("policy.scan_allow_binary_hashes", root_span.trace_id(), root_span.span_id());
        auto scan_result = scan_for_binary_hashes(policy.allow_binary_hashes, policy.scan_paths);
        if (!scan_result) {
            span.fail(scan_result.error().to_string());
            return fail(scan_result.error());
        }
        allow_binary_matches = std::move(*scan_result);
        if (allow_binary_matches.empty()) {
            Error err(ErrorCode::PolicyApplyFailed,
                      "allow_binary_hash policy has no matching binaries on this host; refusing fail-closed policy");
            span.fail(err.to_string());
            return fail(err);
        }
    }

    size_t expected_allow_exec_inode_entries = 0;

    // Policy generation guard: each apply path bumps the generation exactly once,
    // immediately before it begins mutating live maps, which forces BPF hooks into
    // audit mode until the matching generation is committed. The shadow path bumps
    // right before the shadow->live sync; the direct-apply path bumps at the top of
    // its branch. Bumping any earlier (e.g. during shadow population, while the live
    // maps are still untouched) would open an unnecessary enforcement-downgrade window.

    // Building the next generation is MANDATORY. There is no fallback.
    //
    // These maps are not a "shadow copy" of anything: in the slotted design
    // each one IS generation B's inner map, and the commit installs them.
    // The only alternative would be to clear and rewrite generation A's inner
    // maps in place, which cannot be atomic -- it destroys the live policy to
    // build the new one, and needs the audit-only window to hide the gap.
    //
    // That fallback used to exist and was reachable by accident: it triggered
    // on any transient failure here (memlock pressure, ENOMEM, map limits),
    // logged a warning, and still reported the apply as successful. An
    // operator had no way to tell that the reload had silently given up
    // atomicity and opened an enforcement hole.
    //
    // There is exactly one correct response to "generation B cannot be
    // built": keep generation A. A failed reload is strictly safer than a
    // non-atomic one, and it is visible.
    ShadowMapSet shadows;
    {
        ScopedSpan span("policy.create_shadows", root_span.trace_id(), root_span.span_id());
        // Size the inode generation to what will actually go into it.
        //
        // Only deny_inode is right-sized per reload (every other slotted map
        // uses its template maximum), so an under-estimate here is not a
        // performance detail: inserts fail with E2BIG partway through building
        // the generation and the whole reload aborts. Left at the default the
        // hint is 0, which floors the map at 64 entries -- so any policy with
        // more than ~64 inode-producing rules could never be applied.
        //
        // Every source that writes into shadows.deny_inode is counted:
        // explicit inode rules, path rules (resolved to inodes), protect
        // paths, binary-hash matches, and the runtime rules carried forward.
        ShadowSizeHints hints;
        hints.deny_inode_rules = static_cast<uint32_t>(
            policy.deny_inodes.size() + policy.deny_paths.size() + policy.protect_paths.size() +
            allow_binary_matches.size() + carried_runtime_rules.size());
        auto shadow_result = create_shadow_map_set(state, hints);
        if (!shadow_result) {
            Error err(ErrorCode::PolicyApplyFailed,
                      "Cannot build the next policy generation; previous generation left active",
                      shadow_result.error().to_string());
            span.fail(err.to_string());
            logger().log(SLOG_ERROR("Policy apply aborted: next generation could not be allocated")
                             .field("error", shadow_result.error().to_string())
                             .field("active_generation", "unchanged"));
            return fail(err);
        }
        shadows = std::move(*shadow_result);
        logger().log(SLOG_INFO("Next policy generation allocated"));
    }

    {
        ScopedSpan span("policy.populate_shadows", root_span.trace_id(), root_span.span_id());

        // Re-install carried runtime rules FIRST, so a policy rule naming
        // the same inode simply overwrites the entry rather than colliding
        // with it, and so the new generation is never briefly missing a
        // rule an operator added by hand.
        for (const auto& [id, path] : carried_runtime_rules) {
            auto result = add_deny_inode_to_fd(shadows.deny_inode.fd(), id, entries);
            if (!result) {
                span.fail(result.error().to_string());
                return fail(result.error());
            }
        }
        if (!carried_runtime_rules.empty()) {
            logger().log(SLOG_INFO("Carried runtime deny rules into the new policy generation")
                             .field("count", static_cast<int64_t>(carried_runtime_rules.size())));
        }

        for (const auto& deny_path : policy.deny_paths) {
            auto result = add_deny_path_to_fds(shadows.deny_inode.fd(), shadows.deny_path.fd(), deny_path, entries);
            if (!result) {
                span.fail(result.error().to_string());
                return fail(result.error());
            }
        }
        for (const auto& protect_path : policy.protect_paths) {
            auto result = add_rule_path_to_fds(shadows.deny_inode.fd(), shadows.deny_path.fd(), protect_path,
                                               kRuleFlagProtectByVerifiedExec, entries);
            if (!result) {
                span.fail(result.error().to_string());
                return fail(result.error());
            }
        }
        for (const auto& id : policy.deny_inodes) {
            auto result = add_deny_inode_to_fd(shadows.deny_inode.fd(), id, entries);
            if (!result) {
                span.fail(result.error().to_string());
                return fail(result.error());
            }
        }
        if (!policy.deny_binary_hashes.empty()) {
            auto scan_result = scan_for_binary_hashes(policy.deny_binary_hashes, policy.scan_paths);
            if (scan_result) {
                for (const auto& match : *scan_result) {
                    auto result = add_deny_inode_to_fd(shadows.deny_inode.fd(), match.inode, entries);
                    if (!result) {
                        logger().log(SLOG_WARN("Failed to add binary hash match to shadow")
                                         .field("path", match.path)
                                         .field("hash", match.hash)
                                         .field("error", result.error().message()));
                    }
                }
            } else {
                logger().log(SLOG_WARN("Binary hash scan failed").field("error", scan_result.error().to_string()));
            }
        }

        for (const auto& comm : policy.deny_comm) {
            auto result = add_deny_comm_to_fd(shadows.deny_comm.fd(), comm);
            if (!result) {
                logger().log(SLOG_WARN("Failed to add deny comm to shadow")
                                 .field("comm", comm)
                                 .field("error", result.error().message()));
            }
        }

        for (const auto& cgid : policy.allow_cgroup_ids) {
            auto result = add_allow_cgroup_to_fd(shadows.allow_cgroup.fd(), cgid);
            if (!result) {
                span.fail(result.error().to_string());
                return fail(result.error());
            }
        }
        for (const auto& cgpath : policy.allow_cgroup_paths) {
            auto result = add_allow_cgroup_path_to_fd(shadows.allow_cgroup.fd(), cgpath);
            if (!result) {
                span.fail(result.error().to_string());
                return fail(result.error());
            }
        }

        std::unordered_set<InodeId, InodeIdHash> allow_exec_seen;
        for (const auto& match : allow_binary_matches) {
            if (!allow_exec_seen.insert(match.inode).second) {
                continue;
            }
            auto result = add_allow_exec_inode_to_fd(shadows.allow_exec_inode.fd(), match.inode);
            if (!result) {
                span.fail(result.error().to_string());
                return fail(result.error());
            }
        }
        expected_allow_exec_inode_entries = allow_exec_seen.size();
    }

    if (policy.network.enabled) {
        ScopedSpan span("policy.populate_shadow_network", root_span.trace_id(), root_span.span_id());
        for (const auto& ip : policy.network.deny_ips) {
            auto result = add_deny_ip_to_fds(shadows.deny_ipv4.fd(), shadows.deny_ipv6.fd(), ip);
            if (!result) {
                logger().log(SLOG_WARN("Failed to add deny IP to shadow")
                                 .field("ip", ip)
                                 .field("error", result.error().message()));
            }
        }
        for (const auto& cidr : policy.network.deny_cidrs) {
            auto result = add_deny_cidr_to_fds(shadows.deny_cidr_v4.fd(), shadows.deny_cidr_v6.fd(), cidr);
            if (!result) {
                logger().log(SLOG_WARN("Failed to add deny CIDR to shadow")
                                 .field("cidr", cidr)
                                 .field("error", result.error().message()));
            }
        }
        for (const auto& port_rule : policy.network.deny_ports) {
            auto result = add_deny_port_to_fd(shadows.deny_port.fd(), port_rule.port, port_rule.protocol,
                                              port_rule.direction);
            if (!result) {
                logger().log(SLOG_WARN("Failed to add deny port to shadow")
                                 .field("port", static_cast<int64_t>(port_rule.port))
                                 .field("error", result.error().message()));
            }
        }
        for (const auto& ip_port_rule : policy.network.deny_ip_ports) {
            auto result =
                add_deny_ip_port_to_fds(shadows.deny_ip_port_v4.fd(), shadows.deny_ip_port_v6.fd(), ip_port_rule);
            if (!result) {
                logger().log(SLOG_WARN("Failed to add deny IP:port to shadow")
                                 .field("rule", format_ip_port_rule(ip_port_rule))
                                 .field("error", result.error().message()));
            }
        }
    }

    if (policy.cgroup.enabled) {
        ScopedSpan span("policy.populate_shadow_cgroup", root_span.trace_id(), root_span.span_id());
        for (const auto& rule : policy.cgroup.deny_inodes) {
            auto cgid_result = resolve_cgroup_identifier(rule.cgroup);
            if (!cgid_result) {
                logger().log(SLOG_WARN("Failed to resolve cgroup for cgroup_deny_inode")
                                 .field("cgroup", rule.cgroup)
                                 .field("error", cgid_result.error().message()));
                continue;
            }
            auto result = add_cgroup_deny_inode_to_fd(shadows.deny_cgroup_inode.fd(), *cgid_result, rule.inode);
            if (!result) {
                logger().log(SLOG_WARN("Failed to add cgroup deny inode to shadow")
                                 .field("cgroup", rule.cgroup)
                                 .field("error", result.error().message()));
            }
        }
        for (const auto& rule : policy.cgroup.deny_ips) {
            auto cgid_result = resolve_cgroup_identifier(rule.cgroup);
            if (!cgid_result) {
                logger().log(SLOG_WARN("Failed to resolve cgroup for cgroup_deny_ip")
                                 .field("cgroup", rule.cgroup)
                                 .field("error", cgid_result.error().message()));
                continue;
            }
            auto result = add_cgroup_deny_ipv4_to_fd(shadows.deny_cgroup_ipv4.fd(), *cgid_result, rule.ip);
            if (!result) {
                logger().log(SLOG_WARN("Failed to add cgroup deny IPv4 to shadow")
                                 .field("cgroup", rule.cgroup)
                                 .field("ip", rule.ip)
                                 .field("error", result.error().message()));
            }
        }
        for (const auto& rule : policy.cgroup.deny_ports) {
            auto cgid_result = resolve_cgroup_identifier(rule.cgroup);
            if (!cgid_result) {
                logger().log(SLOG_WARN("Failed to resolve cgroup for cgroup_deny_port")
                                 .field("cgroup", rule.cgroup)
                                 .field("error", cgid_result.error().message()));
                continue;
            }
            auto result = add_cgroup_deny_port_to_fd(shadows.deny_cgroup_port.fd(), *cgid_result, rule.port);
            if (!result) {
                logger().log(SLOG_WARN("Failed to add cgroup deny port to shadow")
                                 .field("cgroup", rule.cgroup)
                                 .field("error", result.error().message()));
            }
        }
        logger().log(SLOG_INFO("Cgroup-scoped policy populated in shadow")
                         .field("deny_inodes", static_cast<int64_t>(policy.cgroup.deny_inodes.size()))
                         .field("deny_ips", static_cast<int64_t>(policy.cgroup.deny_ips.size()))
                         .field("deny_ports", static_cast<int64_t>(policy.cgroup.deny_ports.size())));
    }

    {
        ScopedSpan span("policy.verify_shadows", root_span.trace_id(), root_span.span_id());
        size_t shadow_inode_count = map_fd_entry_count(shadows.deny_inode.fd(), inner_key_size(state.deny_inode));
        if (shadow_inode_count != entries.size()) {
            Error err(ErrorCode::BpfMapOperationFailed, "Shadow verify failed for deny_inode",
                      "expected=" + std::to_string(entries.size()) +
                          " actual=" + std::to_string(shadow_inode_count));
            span.fail(err.to_string());
            logger().log(SLOG_ERROR("Shadow verify failed for deny_inode")
                             .field("expected", static_cast<int64_t>(entries.size()))
                             .field("actual", static_cast<int64_t>(shadow_inode_count)));
            return fail(err);
        }

        size_t shadow_path_count = map_fd_entry_count(shadows.deny_path.fd(), inner_key_size(state.deny_path));
        const size_t expected_min_path_rules = policy.deny_paths.size() + policy.protect_paths.size();
        if (shadow_path_count < expected_min_path_rules) {
            Error err(ErrorCode::BpfMapOperationFailed, "Shadow verify failed for deny_path",
                      "expected>=" + std::to_string(expected_min_path_rules) +
                          " actual=" + std::to_string(shadow_path_count));
            span.fail(err.to_string());
            return fail(err);
        }

        if (!allow_binary_matches.empty()) {
            size_t shadow_allow_exec_count =
                map_fd_entry_count(shadows.allow_exec_inode.fd(), inner_key_size(state.allow_exec_inode));
            if (shadow_allow_exec_count < expected_allow_exec_inode_entries) {
                Error err(ErrorCode::BpfMapOperationFailed, "Shadow verify failed for allow_exec_inode",
                          "expected>=" + std::to_string(expected_allow_exec_inode_entries) +
                              " actual=" + std::to_string(shadow_allow_exec_count));
                span.fail(err.to_string());
                return fail(err);
            }
        }
    }

    // NO generation bump on this path, and that is the whole point.
    //
    // The generation guard works by making hooks see a mismatch and fall
    // back to AUDIT-ONLY for the duration of a reload. That was the only
    // option while a reload copied entries into live maps one at a time:
    // enforcement had to be suspended because the maps were briefly
    // inconsistent. It is also a real hole -- for the length of every
    // reload, nothing was enforced.
    //
    // This path no longer mutates live maps at all. Each generation is
    // built in inner maps no hook can reach, and becomes authoritative at
    // a single active_slot write. There is no inconsistent interval to
    // protect, so suspending enforcement would only re-open the hole the
    // slot design exists to close.
    //
    // Measured, not assumed: with the bump still in place a 254-reload
    // concurrency stress run recorded 100 accesses that BOTH policies
    // deny; with it removed, zero. See scripts/policy_swap_stress.sh.
    //
    // The direct-apply fallback below DOES still write live maps in place,
    // and keeps the guard for exactly that reason.

    {
        ScopedSpan span("policy.sync_shadows_to_live", root_span.trace_id(), root_span.span_id());

        if (reset) {
            TRY(reset_policy_maps(state));
        }

        // Every policy map is slotted, so nothing is copied into a live
        // map here. The freshly built inner maps are staged into the
        // inactive slot and become authoritative together, at the single
        // active_slot write inside commit_policy_slot().
        //
        // Each domain is staged unconditionally, including the ones whose
        // policy section is empty: a map omitted from the commit would
        // resolve to an empty inner map after the flip, silently dropping
        // its rules. An empty shadow is the correct representation of an
        // empty section; an absent one is not.
        //
        // On any failure before the flip nothing is installed and the
        // previous generation stays live and enforcing.
        TRY(commit_policy_slot(state, {
                                          {&state.deny_inode, shadows.deny_inode.fd()},
                                          {&state.deny_path, shadows.deny_path.fd()},
                                          {&state.deny_comm, shadows.deny_comm.fd()},
                                          {&state.allow_cgroup, shadows.allow_cgroup.fd()},
                                          {&state.allow_exec_inode, shadows.allow_exec_inode.fd()},
                                          {&state.trusted_exec_hash, shadows.trusted_exec_hash.fd()},
                                          {&state.deny_ipv4, shadows.deny_ipv4.fd()},
                                          {&state.deny_ipv6, shadows.deny_ipv6.fd()},
                                          {&state.deny_port, shadows.deny_port.fd()},
                                          {&state.deny_ip_port_v4, shadows.deny_ip_port_v4.fd()},
                                          {&state.deny_ip_port_v6, shadows.deny_ip_port_v6.fd()},
                                          {&state.deny_cidr_v4, shadows.deny_cidr_v4.fd()},
                                          {&state.deny_cidr_v6, shadows.deny_cidr_v6.fd()},
                                          {&state.deny_cgroup_inode, shadows.deny_cgroup_inode.fd()},
                                          {&state.deny_cgroup_ipv4, shadows.deny_cgroup_ipv4.fd()},
                                          {&state.deny_cgroup_port, shadows.deny_cgroup_port.fd()},
                                      }));

        logger().log(SLOG_INFO("Policy generation committed atomically"));
    }

    {
        ScopedSpan span("policy.verify_maps", root_span.trace_id(), root_span.span_id());

        auto live_inode_for_verify = live_policy_map(state, state.deny_inode.outer);
        auto verify_deny_inode = live_inode_for_verify
                                     ? verify_map_fd_entry_count(live_inode_for_verify->fd(),
                                                                 inner_key_size(state.deny_inode), entries.size())
                                     : Result<void>(live_inode_for_verify.error());
        if (!verify_deny_inode) {
            span.fail(verify_deny_inode.error().to_string());
            logger().log(SLOG_ERROR("Post-apply verification failed for deny_inode map")
                             .field("error", verify_deny_inode.error().to_string()));
            return fail(verify_deny_inode.error());
        }

        size_t deny_path_actual = map_entry_count(state.deny_path);
        const size_t expected_min_path_rules = policy.deny_paths.size() + policy.protect_paths.size();
        if (deny_path_actual < expected_min_path_rules) {
            Error err(ErrorCode::BpfMapOperationFailed, "Post-apply verification failed for deny_path map",
                      "expected>=" + std::to_string(expected_min_path_rules) +
                          " actual=" + std::to_string(deny_path_actual));
            span.fail(err.to_string());
            logger().log(SLOG_ERROR("Post-apply verification failed for deny_path map")
                             .field("expected_min", static_cast<int64_t>(expected_min_path_rules))
                             .field("actual", static_cast<int64_t>(deny_path_actual)));
            return fail(err);
        }

        size_t expected_cgroup = policy.allow_cgroup_ids.size() + policy.allow_cgroup_paths.size();
        if (expected_cgroup > 0) {
            size_t cgroup_actual = map_entry_count(state.allow_cgroup);
            if (cgroup_actual < expected_cgroup) {
                Error err(ErrorCode::BpfMapOperationFailed, "Post-apply verification failed for allow_cgroup map",
                          "expected>=" + std::to_string(expected_cgroup) + " actual=" + std::to_string(cgroup_actual));
                span.fail(err.to_string());
                return fail(err);
            }
        }

        if (!allow_binary_matches.empty()) {
            size_t allow_exec_actual = map_entry_count(state.allow_exec_inode);
            if (allow_exec_actual < expected_allow_exec_inode_entries) {
                Error err(ErrorCode::BpfMapOperationFailed, "Post-apply verification failed for allow_exec_inode map",
                          "expected>=" + std::to_string(expected_allow_exec_inode_entries) +
                              " actual=" + std::to_string(allow_exec_actual));
                span.fail(err.to_string());
                logger().log(SLOG_ERROR("Post-apply verification failed for allow_exec_inode map")
                                 .field("expected_min", static_cast<int64_t>(expected_allow_exec_inode_entries))
                                 .field("actual", static_cast<int64_t>(allow_exec_actual)));
                return fail(err);
            }
        }

        if (policy.network.enabled) {
            size_t expected_ipv4 = 0;
            size_t expected_ipv6 = 0;
            for (const auto& ip : policy.network.deny_ips) {
                uint32_t ip_be;
                Ipv6Key ipv6{};
                if (parse_ipv4(ip, ip_be)) {
                    ++expected_ipv4;
                } else if (parse_ipv6(ip, ipv6)) {
                    ++expected_ipv6;
                }
            }

            if (expected_ipv4 > 0 && state.deny_ipv4) {
                auto v = verify_map_entry_count(state.deny_ipv4, expected_ipv4);
                if (!v) {
                    span.fail(v.error().to_string());
                    return fail(v.error());
                }
            }
            if (expected_ipv6 > 0 && state.deny_ipv6) {
                auto v = verify_map_entry_count(state.deny_ipv6, expected_ipv6);
                if (!v) {
                    span.fail(v.error().to_string());
                    return fail(v.error());
                }
            }
            if (!policy.network.deny_ports.empty() && state.deny_port) {
                auto v = verify_map_entry_count(state.deny_port, policy.network.deny_ports.size());
                if (!v) {
                    span.fail(v.error().to_string());
                    return fail(v.error());
                }
            }
            size_t expected_ip_port_v4 = 0;
            size_t expected_ip_port_v6 = 0;
            for (const auto& ip_port_rule : policy.network.deny_ip_ports) {
                uint32_t ip_be = 0;
                Ipv6Key ipv6{};
                if (parse_ipv4(ip_port_rule.ip, ip_be)) {
                    ++expected_ip_port_v4;
                } else if (parse_ipv6(ip_port_rule.ip, ipv6)) {
                    ++expected_ip_port_v6;
                }
            }
            if (expected_ip_port_v4 > 0 && state.deny_ip_port_v4) {
                auto v = verify_map_entry_count(state.deny_ip_port_v4, expected_ip_port_v4);
                if (!v) {
                    span.fail(v.error().to_string());
                    return fail(v.error());
                }
            }
            if (expected_ip_port_v6 > 0 && state.deny_ip_port_v6) {
                auto v = verify_map_entry_count(state.deny_ip_port_v6, expected_ip_port_v6);
                if (!v) {
                    span.fail(v.error().to_string());
                    return fail(v.error());
                }
            }

            size_t expected_cidr_v4 = 0;
            size_t expected_cidr_v6 = 0;
            for (const auto& cidr : policy.network.deny_cidrs) {
                uint32_t ip_be;
                uint8_t prefix_len;
                Ipv6Key ipv6{};
                if (parse_cidr_v4(cidr, ip_be, prefix_len)) {
                    ++expected_cidr_v4;
                } else if (parse_cidr_v6(cidr, ipv6, prefix_len)) {
                    ++expected_cidr_v6;
                }
            }
            if (expected_cidr_v4 > 0 && state.deny_cidr_v4) {
                auto v = verify_map_entry_count(state.deny_cidr_v4, expected_cidr_v4);
                if (!v) {
                    span.fail(v.error().to_string());
                    return fail(v.error());
                }
            }
            if (expected_cidr_v6 > 0 && state.deny_cidr_v6) {
                auto v = verify_map_entry_count(state.deny_cidr_v6, expected_cidr_v6);
                if (!v) {
                    span.fail(v.error().to_string());
                    return fail(v.error());
                }
            }
        }
    }

    // Commit the policy generation to the BPF map — hooks will now see
    // committed == expected and resume enforce-mode.
    if (pending_generation > 0) {
        auto commit_result = commit_policy_generation(state, pending_generation);
        if (!commit_result) {
            logger().log(SLOG_WARN("Failed to commit policy generation; hooks remain in audit-mode")
                             .field("error", commit_result.error().to_string()));
        } else {
            logger().log(SLOG_INFO("Policy generation committed; enforcement resumed")
                             .field("generation", static_cast<int64_t>(pending_generation)));
        }
    }

    {
        ScopedSpan span("policy.refresh_policy_empty_hints", root_span.trace_id(), root_span.span_id());
        auto hints_result = refresh_policy_empty_hints(state);
        if (!hints_result) {
            span.fail(hints_result.error().to_string());
            return fail(hints_result.error());
        }
    }

    {
        ScopedSpan span("policy.set_exec_identity_mode", root_span.trace_id(), root_span.span_id());
        size_t allow_exec_count = map_entry_count(state.allow_exec_inode);
        bool exec_identity_enabled = allow_exec_count > 0 || policy.protect_connect || !policy.protect_paths.empty() ||
                                     policy.protect_runtime_deps;
        auto mode_result = set_exec_identity_mode(state, exec_identity_enabled);
        if (!mode_result) {
            span.fail(mode_result.error().to_string());
            return fail(mode_result.error());
        }
        uint8_t exec_flags = 0;
        if (allow_exec_count > 0) {
            exec_flags |= kExecIdentityFlagAllowlistEnforce;
        }
        if (policy.protect_connect) {
            exec_flags |= kExecIdentityFlagProtectConnect;
        }
        if (!policy.protect_paths.empty()) {
            exec_flags |= kExecIdentityFlagProtectFiles;
        }
        if (policy.protect_runtime_deps) {
            exec_flags |= kExecIdentityFlagTrustRuntimeDeps;
        }
        if (!policy.trusted_exec_hashes.empty()) {
            // Activate the in-kernel IMA-hash exec verifier (handle_bprm_ima_check).
            exec_flags |= kExecIdentityFlagUseImaHash;
        }
        if (policy.ima_fail_closed) {
            // Deny binaries IMA cannot appraise instead of failing open.
            exec_flags |= kExecIdentityFlagImaFailClosed;
        }
        auto flags_result = set_exec_identity_flags(state, exec_flags);
        if (!flags_result) {
            span.fail(flags_result.error().to_string());
            return fail(flags_result.error());
        }
        logger().log(SLOG_INFO("Exec identity kernel mode updated")
                         .field("enabled", exec_identity_enabled)
                         .field("allow_exec_inode_entries", static_cast<int64_t>(allow_exec_count))
                         .field("exec_identity_flags", static_cast<int64_t>(exec_flags))
                         .field("protect_connect", policy.protect_connect)
                         .field("protect_runtime_deps", policy.protect_runtime_deps)
                         .field("protect_paths", static_cast<int64_t>(policy.protect_paths.size())));
    }

    // Commit the policy generation: write the expected value to the
    // policy_generation map so BPF hooks see the match and resume
    // enforcement.  The generation was bumped before shadow sync
    // (causing hooks to fall back to audit during the transition).
    if (pending_generation > 0) {
        ScopedSpan span("policy.commit_generation", root_span.trace_id(), root_span.span_id());
        auto commit_result = commit_policy_generation(state, pending_generation);
        if (!commit_result) {
            logger().log(SLOG_WARN("Failed to commit policy generation")
                             .field("generation", static_cast<int64_t>(pending_generation))
                             .field("error", commit_result.error().to_string()));
        } else {
            logger().log(SLOG_INFO("Policy generation committed — enforcement resumed")
                             .field("generation", static_cast<int64_t>(pending_generation)));
        }
    }

    // Set kernel security flags (MITRE ATT&CK hooks)
    if (policy.deny_ptrace || policy.deny_module_load || policy.deny_bpf) {
        ScopedSpan span("policy.set_kernel_security_flags", root_span.trace_id(), root_span.span_id());
        auto ksec_result =
            set_kernel_security_flags(state, policy.deny_ptrace, policy.deny_module_load, policy.deny_bpf);
        if (!ksec_result) {
            span.fail(ksec_result.error().to_string());
            logger().log(
                SLOG_WARN("Failed to set kernel security flags").field("error", ksec_result.error().to_string()));
        } else {
            logger().log(SLOG_INFO("Kernel security flags updated")
                             .field("deny_ptrace", policy.deny_ptrace)
                             .field("deny_module_load", policy.deny_module_load)
                             .field("deny_bpf", policy.deny_bpf));
        }
    }

    {
        ScopedSpan span("policy.write_deny_db", root_span.trace_id(), root_span.span_id());
        auto write_result = write_deny_db(entries);
        if (!write_result) {
            span.fail(write_result.error().to_string());
            return fail(write_result.error());
        }
    }

    if (record) {
        ScopedSpan span("policy.record_applied_policy", root_span.trace_id(), root_span.span_id());
        auto record_result = record_applied_policy(path, computed_hash);
        if (!record_result) {
            span.fail(record_result.error().to_string());
            return fail(record_result.error());
        }
    }
    return {};
}

static ApplyPolicyInternalFn g_apply_policy_internal_fn = apply_policy_internal_impl_fn;

Result<void> apply_policy_internal(const std::string& path, const std::string& computed_hash, bool reset, bool record)
{
    return g_apply_policy_internal_fn(path, computed_hash, reset, record);
}

void set_apply_policy_internal_for_test(ApplyPolicyInternalFn fn)
{
    g_apply_policy_internal_fn = fn ? fn : apply_policy_internal_impl_fn;
}

void reset_apply_policy_internal_for_test()
{
    g_apply_policy_internal_fn = apply_policy_internal_impl_fn;
}

Result<void> policy_apply(const std::string& path, bool reset, const std::string& cli_hash,
                          const std::string& cli_hash_file, bool rollback_on_failure,
                          const std::string& trace_id_override)
{
    std::string trace_id = trace_id_override;
    if (trace_id.empty()) {
        trace_id = make_span_id("trace-policy-apply");
    }
    PolicyTraceScope trace_scope(trace_id);
    ScopedSpan root_span("policy.apply", trace_id);
    auto fail = [&](const Error& err) -> Result<void> {
        root_span.fail(err.to_string());
        return err;
    };

    const std::string applied_path = policy_applied_path();

    std::string expected_hash = cli_hash;
    std::string hash_file = cli_hash_file;

    if (expected_hash.empty()) {
        const char* env = std::getenv("AEGIS_POLICY_SHA256");
        if (env && *env) {
            expected_hash = env;
        }
    }
    if (hash_file.empty()) {
        const char* env = std::getenv("AEGIS_POLICY_SHA256_FILE");
        if (env && *env) {
            hash_file = env;
        }
    }

    if (!expected_hash.empty() && !hash_file.empty()) {
        return fail(Error(ErrorCode::InvalidArgument, "Provide either --sha256 or --sha256-file (not both)"));
    }

    {
        ScopedSpan span("policy.validate_inputs", trace_id, root_span.span_id());
        auto policy_perms = validate_file_permissions(path, false);
        if (!policy_perms) {
            span.fail(policy_perms.error().to_string());
            return fail(policy_perms.error());
        }

        if (!hash_file.empty()) {
            auto hash_perms = validate_file_permissions(hash_file, false);
            if (!hash_perms) {
                span.fail(hash_perms.error().to_string());
                return fail(hash_perms.error());
            }
            if (!read_sha256_file(hash_file, expected_hash)) {
                Error err(ErrorCode::IoError, "Failed to read sha256 file", hash_file);
                span.fail(err.to_string());
                return fail(err);
            }
        }

        if (!expected_hash.empty()) {
            if (!parse_sha256_token(expected_hash, expected_hash)) {
                Error err(ErrorCode::InvalidArgument, "Invalid sha256 value format");
                span.fail(err.to_string());
                return fail(err);
            }
        }
    }

    std::string computed_hash;
    {
        ScopedSpan span("policy.integrity_check", trace_id, root_span.span_id());
        if (!expected_hash.empty()) {
            if (!verify_policy_hash(path, expected_hash, computed_hash)) {
                Error err(ErrorCode::PolicyHashMismatch, "Policy sha256 mismatch");
                span.fail(err.to_string());
                return fail(err);
            }
        } else if (!sha256_file_hex(path, computed_hash)) {
            logger().log(SLOG_WARN("Failed to compute policy sha256; continuing without hash"));
            computed_hash.clear();
        }
    }

    DenyEntries pre_apply_snapshot = read_deny_db();

    Result<void> result;
    {
        ScopedSpan span("policy.apply_internal_call", trace_id, root_span.span_id());
        result = apply_policy_internal(path, computed_hash, reset, true);
        if (!result) {
            span.fail(result.error().to_string());
        }
    }

    if (!result && rollback_on_failure) {
        std::error_code ec;
        bool file_rollback_succeeded = false;

        if (std::filesystem::exists(applied_path, ec)) {
            std::string rollback_hash;
            std::string stored_hash = read_file_first_line(policy_applied_hash_path());
            bool hash_ok = true;
            if (!stored_hash.empty()) {
                std::string actual_hash;
                if (sha256_file_hex(applied_path, actual_hash) && actual_hash == stored_hash) {
                    rollback_hash = stored_hash;
                } else {
                    logger().log(SLOG_WARN("Rollback policy hash mismatch; skipping file-based rollback")
                                     .field("stored_hash", stored_hash)
                                     .field("actual_hash", actual_hash));
                    hash_ok = false;
                }
            }

            if (hash_ok) {
                logger().log(SLOG_WARN("Apply failed; rolling back to last applied policy"));
                ScopedSpan span("policy.rollback_last_applied", trace_id, root_span.span_id());
                auto rollback_result = apply_policy_internal(applied_path, rollback_hash, true, false);
                if (rollback_result) {
                    file_rollback_succeeded = true;
                } else {
                    span.fail(rollback_result.error().to_string());
                    logger().log(SLOG_ERROR("File-based rollback failed; attempting in-memory snapshot restore")
                                     .field("error", rollback_result.error().to_string()));
                }
            }
        }

        if (!file_rollback_succeeded && !pre_apply_snapshot.empty()) {
            ScopedSpan span("policy.rollback_inmemory", trace_id, root_span.span_id());
            logger().log(SLOG_WARN("Restoring maps from in-memory snapshot")
                             .field("snapshot_entries", static_cast<int64_t>(pre_apply_snapshot.size())));
            BpfState rollback_state;
            auto load_result = load_bpf(true, false, rollback_state);
            if (load_result) {
                auto reset_result = reset_policy_maps(rollback_state);
                if (reset_result) {
                    bool snapshot_ok = true;
                    for (const auto& [inode_id, path_str] : pre_apply_snapshot) {
                        uint8_t one = 1;
                        auto rb_live = live_policy_map(rollback_state, rollback_state.deny_inode.outer);
                        if (!rb_live || bpf_map_update_elem(rb_live->fd(), &inode_id, &one, BPF_ANY)) {
                            snapshot_ok = false;
                            break;
                        }
                        if (!path_str.empty() && path_str.size() < kDenyPathMax) {
                            PathKey pk{};
                            fill_path_key(path_str, pk);
                            bpf_map_update_elem(rollback_state.deny_path.live_fd(), &pk, &one, BPF_ANY);
                        }
                    }
                    if (snapshot_ok) {
                        auto db_result = write_deny_db(pre_apply_snapshot);
                        if (db_result) {
                            logger().log(SLOG_INFO("In-memory snapshot restore succeeded")
                                             .field("entries", static_cast<int64_t>(pre_apply_snapshot.size())));
                        } else {
                            logger().log(SLOG_ERROR("In-memory snapshot: deny.db write failed")
                                             .field("error", db_result.error().to_string()));
                        }
                    } else {
                        span.fail("In-memory snapshot restore failed: map update error");
                        logger().log(SLOG_ERROR("In-memory snapshot restore failed: map update error"));
                    }
                } else {
                    span.fail(reset_result.error().to_string());
                    logger().log(SLOG_ERROR("In-memory snapshot: map reset failed")
                                     .field("error", reset_result.error().to_string()));
                }
            } else {
                span.fail(load_result.error().to_string());
                logger().log(
                    SLOG_ERROR("In-memory snapshot: BPF load failed").field("error", load_result.error().to_string()));
            }
        }

        return fail(result.error());
    }

    if (!result) {
        return fail(result.error());
    }

    return result;
}

Result<void> policy_show()
{
    const std::string applied_path = policy_applied_path();
    const std::string applied_hash_path = policy_applied_hash_path();

    std::ifstream in(applied_path);
    if (!in.is_open()) {
        return Error(ErrorCode::ResourceNotFound, "No applied policy found", applied_path);
    }
    std::string hash = read_file_first_line(applied_hash_path);
    if (!hash.empty()) {
        std::cout << "# applied_sha256: " << hash << "\n";
    }
    std::cout << in.rdbuf();
    return {};
}

Result<void> policy_rollback()
{
    const std::string applied_prev_path = policy_applied_prev_path();

    if (!std::filesystem::exists(applied_prev_path)) {
        return Error(ErrorCode::ResourceNotFound, "No rollback policy found", applied_prev_path);
    }
    std::string computed_hash;
    sha256_file_hex(applied_prev_path, computed_hash);
    return apply_policy_internal(applied_prev_path, computed_hash, true, true);
}

} // namespace aegis
