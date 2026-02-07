// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Block and allow command implementations
 */

#include "commands_block_allow.hpp"

#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <iostream>

#include "bpf_ops.hpp"
#include "logging.hpp"
#include "tracing.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace aegis {

namespace {

int fail_span(ScopedSpan& span, const std::string& message)
{
    span.fail(message);
    return 1;
}

int block_file(const std::string& path)
{
    auto validated = validate_existing_path(path);
    if (!validated) {
        logger().log(SLOG_ERROR("Invalid path").field("error", validated.error().to_string()));
        return 1;
    }

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit").field("error", rlimit_result.error().to_string()));
        return 1;
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        return 1;
    }

    auto version_result = ensure_layout_version(state);
    if (!version_result) {
        logger().log(SLOG_ERROR("Layout version check failed").field("error", version_result.error().to_string()));
        return 1;
    }

    auto entries = read_deny_db();
    auto add_result = add_deny_path(state, *validated, entries);
    if (!add_result) {
        logger().log(SLOG_ERROR("Failed to add deny entry").field("error", add_result.error().to_string()));
        return 1;
    }

    auto write_result = write_deny_db(entries);
    if (!write_result) {
        logger().log(SLOG_ERROR("Failed to write deny database").field("error", write_result.error().to_string()));
        return 1;
    }
    return 0;
}

} // namespace

int cmd_block_add(const std::string& path)
{
    const std::string trace_id = make_span_id("trace-block-add");
    ScopedSpan span("cli.block_add", trace_id);
    int rc = block_file(path);
    if (rc != 0) {
        span.fail("block add failed");
    }
    return rc;
}

int cmd_block_del(const std::string& path)
{
    const std::string trace_id = make_span_id("trace-block-del");
    ScopedSpan span("cli.block_del", trace_id);

    auto inode_result = path_to_inode(path);
    if (!inode_result) {
        logger().log(SLOG_ERROR("Failed to get inode").field("error", inode_result.error().to_string()));
        return fail_span(span, inode_result.error().to_string());
    }
    InodeId id = *inode_result;

    int map_fd = bpf_obj_get(kDenyInodePin);
    if (map_fd < 0) {
        logger().log(SLOG_ERROR("deny_inode_map not found"));
        return fail_span(span, "deny_inode_map not found");
    }
    bpf_map_delete_elem(map_fd, &id);
    close(map_fd);

    std::error_code ec;
    std::filesystem::path resolved = std::filesystem::canonical(path, ec);
    std::string resolved_path = ec ? path : resolved.string();
    PathKey path_key{};
    fill_path_key(resolved_path, path_key);
    int path_fd = bpf_obj_get(kDenyPathPin);
    if (path_fd >= 0) {
        bpf_map_delete_elem(path_fd, &path_key);
        if (resolved_path != path) {
            PathKey raw_key{};
            fill_path_key(path, raw_key);
            bpf_map_delete_elem(path_fd, &raw_key);
        }
        close(path_fd);
    } else {
        logger().log(SLOG_WARN("deny_path_map not found"));
    }

    auto entries = read_deny_db();
    entries.erase(id);
    auto write_result = write_deny_db(entries);
    if (!write_result) {
        logger().log(SLOG_ERROR("Failed to write deny database").field("error", write_result.error().to_string()));
        return fail_span(span, write_result.error().to_string());
    }
    return 0;
}

int cmd_block_list()
{
    const std::string trace_id = make_span_id("trace-block-list");
    ScopedSpan span("cli.block_list", trace_id);

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    auto db = read_deny_db();
    InodeId key{};
    InodeId next_key{};
    int rc = bpf_map_get_next_key(bpf_map__fd(state.deny_inode), nullptr, &key);
    while (!rc) {
        auto it = db.find(key);
        if (it != db.end() && !it->second.empty()) {
            std::cout << it->second << " (" << inode_to_string(key) << ")" << '\n';
        } else {
            std::cout << inode_to_string(key) << '\n';
        }
        rc = bpf_map_get_next_key(bpf_map__fd(state.deny_inode), &key, &next_key);
        key = next_key;
    }

    return 0;
}

int cmd_block_clear()
{
    const std::string trace_id = make_span_id("trace-block-clear");
    ScopedSpan span("cli.block_clear", trace_id);

    std::remove(kDenyInodePin);
    std::remove(kDenyPathPin);
    std::remove(kAllowCgroupPin);
    std::remove(kDenyCgroupStatsPin);
    std::remove(kDenyInodeStatsPin);
    std::remove(kDenyPathStatsPin);
    std::remove(kAgentMetaPin);
    std::remove(kSurvivalAllowlistPin);
    std::filesystem::remove(kDenyDbPath);
    std::filesystem::remove(kPolicyAppliedPath);
    std::filesystem::remove(kPolicyAppliedPrevPath);
    std::filesystem::remove(kPolicyAppliedHashPath);

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit").field("error", rlimit_result.error().to_string()));
        return fail_span(span, rlimit_result.error().to_string());
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to reload BPF object").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }
    if (state.block_stats) {
        auto reset_result = reset_block_stats_map(state.block_stats);
        if (!reset_result) {
            logger().log(SLOG_WARN("Failed to reset block stats").field("error", reset_result.error().to_string()));
        }
    }
    return 0;
}

int cmd_allow_add(const std::string& path)
{
    const std::string trace_id = make_span_id("trace-allow-add");
    ScopedSpan span("cli.allow_add", trace_id);

    auto validated = validate_cgroup_path(path);
    if (!validated) {
        logger().log(SLOG_ERROR("Invalid cgroup path").field("error", validated.error().to_string()));
        return fail_span(span, validated.error().to_string());
    }

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit").field("error", rlimit_result.error().to_string()));
        return fail_span(span, rlimit_result.error().to_string());
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    auto add_result = add_allow_cgroup_path(state, *validated);
    if (!add_result) {
        logger().log(SLOG_ERROR("Failed to add allow cgroup").field("error", add_result.error().to_string()));
        return fail_span(span, add_result.error().to_string());
    }

    return 0;
}

int cmd_allow_del(const std::string& path)
{
    const std::string trace_id = make_span_id("trace-allow-del");
    ScopedSpan span("cli.allow_del", trace_id);

    auto cgid_result = path_to_cgid(path);
    if (!cgid_result) {
        logger().log(SLOG_ERROR("Failed to get cgroup ID").field("error", cgid_result.error().to_string()));
        return fail_span(span, cgid_result.error().to_string());
    }
    uint64_t cgid = *cgid_result;

    int fd = bpf_obj_get(kAllowCgroupPin);
    if (fd < 0) {
        logger().log(SLOG_ERROR("allow_cgroup_map not found"));
        return fail_span(span, "allow_cgroup_map not found");
    }
    bpf_map_delete_elem(fd, &cgid);
    close(fd);
    return 0;
}

int cmd_allow_list()
{
    const std::string trace_id = make_span_id("trace-allow-list");
    ScopedSpan span("cli.allow_list", trace_id);

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object").field("error", load_result.error().to_string()));
        return fail_span(span, load_result.error().to_string());
    }

    auto ids_result = read_allow_cgroup_ids(state.allow_cgroup);
    if (!ids_result) {
        logger().log(SLOG_ERROR("Failed to read allow cgroup IDs").field("error", ids_result.error().to_string()));
        return fail_span(span, ids_result.error().to_string());
    }

    for (uint64_t id : *ids_result) {
        std::cout << id << '\n';
    }

    return 0;
}

} // namespace aegis
