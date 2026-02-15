// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "result.hpp"

namespace aegis {

struct EmergencyControlConfig {
    uint64_t log_max_bytes = 10ULL * 1024ULL * 1024ULL;
    uint32_t log_max_files = 5;
    uint32_t storm_threshold = 10;
    uint32_t storm_window_seconds = 60;
    size_t reason_max_bytes = 512;
    uint32_t lock_timeout_seconds = 5;
};

EmergencyControlConfig emergency_control_config_from_env();

std::string control_state_path_from_env();
std::string control_log_path_from_env();
std::string control_lock_path_from_env();

std::string node_name_from_env_or_hostname();

struct SanitizedReason {
    std::string sanitized;
    bool truncated = false;
    std::string raw_sha256_hex;
};

// NOTE: raw_sha256_hex is computed over the raw UTF-8 bytes exactly as provided,
// before truncation/sanitization.
SanitizedReason sanitize_reason_and_hash(const std::string& raw_reason, size_t max_bytes);

struct EmergencyControlState {
    int schema_version = 1;
    bool enabled = false;
    int64_t changed_at_unix = 0;
    uint32_t uid = 0;
    uint32_t pid = 0;
    std::string node_name;
    std::string reason;
    std::string reason_sha256;
    uint64_t transitions_total = 0;
    std::vector<int64_t> transition_times_unix;
};

Result<EmergencyControlState> read_emergency_control_state(const std::string& path);
Result<void> write_emergency_control_state(const std::string& path, const EmergencyControlState& state);

struct EmergencyStormStatus {
    bool active = false;
    uint32_t threshold = 0;
    uint32_t window_seconds = 0;
    uint32_t transitions_in_window = 0;
};

EmergencyStormStatus evaluate_toggle_storm(const EmergencyControlState& state, const EmergencyControlConfig& cfg,
                                           int64_t now_unix);

class ScopedFileLock {
  public:
    static Result<ScopedFileLock> acquire(const std::string& lock_path, uint32_t timeout_seconds);

    ScopedFileLock() = default;
    ~ScopedFileLock();

    ScopedFileLock(const ScopedFileLock&) = delete;
    ScopedFileLock& operator=(const ScopedFileLock&) = delete;

    ScopedFileLock(ScopedFileLock&& other) noexcept;
    ScopedFileLock& operator=(ScopedFileLock&& other) noexcept;

    [[nodiscard]] bool ok() const { return fd_ >= 0; }

  private:
    explicit ScopedFileLock(int fd) : fd_(fd) {}
    int fd_ = -1;
};

// Rotate jsonl file if current_size + next_entry_size would exceed max_bytes.
Result<void> rotate_jsonl_if_needed_pre_write(const std::string& path, uint64_t max_bytes, uint32_t max_files,
                                              uint64_t next_entry_size);

// Append a single jsonl line (caller provides locking). Flush + fsync to persist.
Result<void> append_jsonl_line(const std::string& path, const std::string& line);

} // namespace aegis
