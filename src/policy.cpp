// cppcheck-suppress-file missingIncludeSystem
#include "policy.hpp"

#include <algorithm>
#include <ostream>

#include "bpf_ops.hpp"
#include "utils.hpp"

namespace aegis {

Result<void> write_policy_file(const std::string& path, std::vector<std::string> deny_paths,
                               std::vector<std::string> deny_inodes, std::vector<std::string> allow_cgroups)
{
    std::sort(deny_paths.begin(), deny_paths.end());
    deny_paths.erase(std::unique(deny_paths.begin(), deny_paths.end()), deny_paths.end());
    std::sort(deny_inodes.begin(), deny_inodes.end());
    deny_inodes.erase(std::unique(deny_inodes.begin(), deny_inodes.end()), deny_inodes.end());
    std::sort(allow_cgroups.begin(), allow_cgroups.end());
    allow_cgroups.erase(std::unique(allow_cgroups.begin(), allow_cgroups.end()), allow_cgroups.end());

    return atomic_write_stream(path, [&](std::ostream& out) -> bool {
        out << "version=1\n";
        if (!deny_paths.empty()) {
            out << "\n[deny_path]\n";
            for (const auto& p : deny_paths) {
                out << p << "\n";
            }
        }
        if (!deny_inodes.empty()) {
            out << "\n[deny_inode]\n";
            for (const auto& p : deny_inodes) {
                out << p << "\n";
            }
        }
        if (!allow_cgroups.empty()) {
            out << "\n[allow_cgroup]\n";
            for (const auto& p : allow_cgroups) {
                out << p << "\n";
            }
        }
        return out.good();
    });
}

Result<void> policy_export(const std::string& path)
{
    TRY(bump_memlock_rlimit());

    BpfState state;
    TRY(load_bpf(true, false, state));

    auto db = read_deny_db();
    std::vector<std::string> deny_paths;
    std::vector<std::string> deny_inodes;
    for (const auto& kv : db) {
        if (!kv.second.empty()) {
            deny_paths.push_back(kv.second);
        } else {
            deny_inodes.push_back(inode_to_string(kv.first));
        }
    }

    auto allow_ids_result = read_allow_cgroup_ids(state.allow_cgroup);
    if (!allow_ids_result) {
        return allow_ids_result.error();
    }

    std::vector<std::string> allow_entries;
    for (uint64_t id : *allow_ids_result) {
        std::string cgpath = resolve_cgroup_path(id);
        if (!cgpath.empty()) {
            allow_entries.push_back(cgpath);
        } else {
            allow_entries.push_back("cgid:" + std::to_string(id));
        }
    }

    return write_policy_file(path, deny_paths, deny_inodes, allow_entries);
}

} // namespace aegis
