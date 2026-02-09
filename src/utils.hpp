// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <sys/types.h>

#include <functional>
#include <mutex>
#include <string>
#include <system_error>
#include <vector>

#include "result.hpp"
#include "types.hpp"

namespace aegis {

// String utilities
std::string trim(const std::string& s);
bool parse_key_value(const std::string& line, std::string& key, std::string& value);
bool parse_uint64(const std::string& text, uint64_t& out);
bool parse_inode_id(const std::string& text, InodeId& out);
std::string join_list(const std::vector<std::string>& items);
std::string to_string(const char* buf, size_t sz);
std::string json_escape(const std::string& in);
std::string prometheus_escape_label(const std::string& in);

// Device encoding (match kernel's s_dev encoding)
uint32_t encode_dev(dev_t dev);

// Path utilities
Result<InodeId> path_to_inode(const std::string& path);
Result<uint64_t> path_to_cgid(const std::string& path);
void fill_path_key(const std::string& path, PathKey& key);
std::string inode_to_string(const InodeId& id);
std::string resolve_cgroup_path(uint64_t cgid);
std::string read_proc_cwd(uint32_t pid);
std::string resolve_relative_path(uint32_t pid, uint64_t start_time, const std::string& path);
bool path_exists(const char* path, std::error_code& ec);

// Path validation utilities
Result<std::string> validate_path(const std::string& path);
Result<std::string> validate_existing_path(const std::string& path);
Result<std::string> validate_cgroup_path(const std::string& path);

// File utilities
std::string read_file_first_line(const std::string& path);
std::string find_kernel_config_value_in_file(const std::string& path, const std::string& key);
std::string find_kernel_config_value_in_proc(const std::string& key);
std::string kernel_config_value(const std::string& key);

// Atomic file writes (write-to-temp + fsync + rename)
Result<void> atomic_write_file(const std::string& target_path, const std::string& content);
Result<void> atomic_write_stream(const std::string& target_path,
                                 const std::function<bool(std::ostream&)>& writer);

// Database operations
DenyEntries read_deny_db();
Result<void> write_deny_db(const DenyEntries& entries);

// Exec ID generation
std::string build_exec_id(uint32_t pid, uint64_t start_time);

// Break-glass detection
bool detect_break_glass();

// Security validation
Result<void> validate_config_directory_permissions(const std::string& path);
Result<void> validate_file_permissions(const std::string& path, bool require_root_owner = true);

// Path canonicalization for policy identity
Result<std::pair<InodeId, std::string>> canonicalize_path(const std::string& path);
Result<InodeId> resolve_to_inode(const std::string& path, bool follow_symlinks = true);

// Thread-safe cgroup path cache with batch-rebuild on miss
class CgroupPathCache {
  public:
    static CgroupPathCache& instance();
    std::string resolve(uint64_t cgid);

  private:
    CgroupPathCache() = default;
    void rebuild_locked();
    std::string try_open_by_handle(uint64_t cgid);

    std::mutex mutex_;
    std::unordered_map<uint64_t, std::string> cache_;
    bool fully_populated_ = false;
    int mount_fd_ = -1;
};

// Thread-safe CWD cache for relative path resolution
class CwdCache {
  public:
    static CwdCache& instance();
    std::string resolve(uint32_t pid, uint64_t start_time, const std::string& path);

  private:
    CwdCache() = default;
    struct Entry {
        uint64_t start_time;
        std::string cwd;
    };
    std::mutex mutex_;
    std::unordered_map<uint32_t, Entry> cache_;
};

} // namespace aegis
