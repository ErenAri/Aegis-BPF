// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <sys/types.h>

#include <cstddef>
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
Result<void> atomic_write_stream(const std::string& target_path, const std::function<bool(std::ostream&)>& writer);

// Database operations
DenyEntries read_deny_db();
Result<void> write_deny_db(const DenyEntries& entries);

/// Runtime deny rules: the subset added at runtime via `aegis block add`,
/// tracked separately from the deny database.
///
/// deny.db records everything currently installed, policy-derived rules
/// included, so it cannot answer "which rules did an operator add by hand?".
/// A policy reload builds a brand new generation and must re-install exactly
/// the hand-added rules while letting the previous generation's policy rules
/// go. That needs provenance, which this registry supplies.
///
/// Absent file means "no runtime rules", which is also the correct reading for
/// a daemon upgraded from a build that did not maintain it.
/// Re-validate runtime deny rules against the filesystem.
///
/// Returns the subset still naming the same object, and reports how many were
/// dropped. A rule is dropped when its path no longer exists, or now resolves
/// to a different (device, inode) -- re-installing that would block whatever
/// has since taken the inode number.
///
/// Dropping never fails a reload: a blocked temp file that has been deleted is
/// not a policy error, and failing would wedge every future reload behind a
/// file that will not return. Each drop is reported by the caller.
DenyEntries prune_stale_runtime_rules(const DenyEntries& rules, size_t& dropped,
                                      const std::function<void(const std::string&, const std::string&)>& on_drop);

/// Outcome of migrating a pre-slot installation's deny database.
struct RuntimeRuleMigration {
    bool ran = false;          ///< false when already migrated (marker present)
    size_t migrated = 0;       ///< entries adopted as runtime rules
    size_t policy_derived = 0; ///< entries attributed to the applied policy
    size_t quarantined = 0;    ///< entries whose provenance could not be decided
    size_t unaccounted = 0;    ///< post-migration deny.db entries in neither the registry nor the policy
    std::string quarantine_path;
    std::string reason; ///< why entries were quarantined, when any were
};

/// Migrate a legacy deny database into the runtime-rule registry, once.
///
/// Installations from before the registry existed recorded hand-added blocks
/// only in deny.db, alongside policy-derived rules and with no provenance. An
/// upgrade that ignored them would silently drop every manual block on the
/// first reload; one that adopted all of them would resurrect policy rules the
/// operator had already removed.
///
/// Provenance is reconstructed by subtracting the applied policy
/// (/var/lib/aegisbpf/policy.applied, the exact text last applied) from the
/// deny database. What remains was not produced by that policy, so it was
/// added at runtime.
///
/// Where that subtraction cannot be trusted the entries are QUARANTINED rather
/// than guessed at: written to a file, reported, and not enforced. See
/// docs/GUARANTEES.md for the cases.
///
/// Idempotent: a marker file records the completed migration, so a rerun is a
/// no-op. Crash-safe: the registry is written before the marker, so an
/// interrupted run repeats rather than half-applies.
RuntimeRuleMigration migrate_legacy_runtime_rules();

/// Locations the migration reads and writes. Exists so the migration can be
/// tested against a temporary directory instead of /var/lib/aegisbpf.
struct RuntimeRuleMigrationPaths {
    std::string deny_db;
    std::string runtime_rules;
    std::string migrated_marker;
    std::string quarantine;
    std::string applied_policy;
};
RuntimeRuleMigration migrate_legacy_runtime_rules(const RuntimeRuleMigrationPaths& paths);

/// Test helper: read a deny-entry file from an arbitrary path.
DenyEntries read_deny_entries_file_for_test(const std::string& path);

DenyEntries read_runtime_rules();
Result<void> write_runtime_rules(const DenyEntries& entries);

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
