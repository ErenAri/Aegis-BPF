// cppcheck-suppress-file missingIncludeSystem
#include "control.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>

#include "logging.hpp"
#include "sha256.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace aegis {

namespace {

constexpr uint32_t kDefaultLockRetrySleepMs = 50;
constexpr size_t kMaxStoredTransitionTimes = 128;

bool parse_u64_env(const char* key, uint64_t& out)
{
    const char* env = std::getenv(key);
    if (!env || !*env) {
        return false;
    }
    uint64_t v = 0;
    if (!parse_uint64(env, v)) {
        logger().log(SLOG_WARN("Invalid env value; using default").field("key", key).field("value", env));
        return false;
    }
    out = v;
    return true;
}

bool parse_u32_env(const char* key, uint32_t& out)
{
    uint64_t v = 0;
    if (!parse_u64_env(key, v)) {
        return false;
    }
    if (v > UINT32_MAX) {
        logger().log(SLOG_WARN("Env value out of range; using default").field("key", key).field("value", v));
        return false;
    }
    out = static_cast<uint32_t>(v);
    return true;
}

bool find_json_value_pos(const std::string& json, const std::string& key, size_t& pos_out)
{
    const std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) {
        return false;
    }
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) {
        return false;
    }
    ++pos;
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) {
        ++pos;
    }
    pos_out = pos;
    return true;
}

bool extract_json_string_simple(const std::string& json, const std::string& key, std::string& out)
{
    size_t pos = 0;
    if (!find_json_value_pos(json, key, pos)) {
        return false;
    }
    if (pos >= json.size() || json[pos] != '"') {
        return false;
    }
    ++pos;
    std::string s;
    while (pos < json.size()) {
        char c = json[pos++];
        if (c == '"') {
            out = s;
            return true;
        }
        if (c != '\\') {
            s.push_back(c);
            continue;
        }
        if (pos >= json.size()) {
            return false;
        }
        char esc = json[pos++];
        switch (esc) {
            case '"':
            case '\\':
            case '/':
                s.push_back(esc);
                break;
            case 'n':
                s.push_back('\n');
                break;
            case 'r':
                s.push_back('\r');
                break;
            case 't':
                s.push_back('\t');
                break;
            case 'b':
                s.push_back('\b');
                break;
            case 'f':
                s.push_back('\f');
                break;
            case 'u': {
                // Minimal \u00XX support (we never intentionally write non-ASCII here).
                if (pos + 4 > json.size()) {
                    return false;
                }
                unsigned int code = 0;
                for (int i = 0; i < 4; ++i) {
                    char h = json[pos++];
                    code <<= 4;
                    if (h >= '0' && h <= '9') {
                        code |= static_cast<unsigned int>(h - '0');
                    } else if (h >= 'a' && h <= 'f') {
                        code |= static_cast<unsigned int>(10 + (h - 'a'));
                    } else if (h >= 'A' && h <= 'F') {
                        code |= static_cast<unsigned int>(10 + (h - 'A'));
                    } else {
                        return false;
                    }
                }
                if (code <= 0x7f) {
                    s.push_back(static_cast<char>(code));
                } else {
                    s.push_back('?');
                }
                break;
            }
            default:
                return false;
        }
    }
    return false;
}

bool extract_json_int64_simple(const std::string& json, const std::string& key, int64_t& out)
{
    size_t pos = 0;
    if (!find_json_value_pos(json, key, pos)) {
        return false;
    }
    bool neg = false;
    if (pos < json.size() && json[pos] == '-') {
        neg = true;
        ++pos;
    }
    if (pos >= json.size() || !std::isdigit(static_cast<unsigned char>(json[pos]))) {
        return false;
    }
    int64_t v = 0;
    while (pos < json.size() && std::isdigit(static_cast<unsigned char>(json[pos]))) {
        int digit = json[pos++] - '0';
        if (v > (INT64_MAX - digit) / 10) {
            return false;
        }
        v = v * 10 + digit;
    }
    out = neg ? -v : v;
    return true;
}

bool extract_json_uint64_simple(const std::string& json, const std::string& key, uint64_t& out)
{
    size_t pos = 0;
    if (!find_json_value_pos(json, key, pos)) {
        return false;
    }
    if (pos >= json.size() || !std::isdigit(static_cast<unsigned char>(json[pos]))) {
        return false;
    }
    uint64_t v = 0;
    while (pos < json.size() && std::isdigit(static_cast<unsigned char>(json[pos]))) {
        int digit = json[pos++] - '0';
        if (v > (UINT64_MAX - static_cast<uint64_t>(digit)) / 10) {
            return false;
        }
        v = v * 10 + static_cast<uint64_t>(digit);
    }
    out = v;
    return true;
}

bool extract_json_bool_simple(const std::string& json, const std::string& key, bool& out)
{
    size_t pos = 0;
    if (!find_json_value_pos(json, key, pos)) {
        return false;
    }
    if (json.compare(pos, 4, "true") == 0) {
        out = true;
        return true;
    }
    if (json.compare(pos, 5, "false") == 0) {
        out = false;
        return true;
    }
    return false;
}

bool extract_json_int64_array_simple(const std::string& json, const std::string& key, std::vector<int64_t>& out)
{
    size_t pos = 0;
    if (!find_json_value_pos(json, key, pos)) {
        return false;
    }
    if (pos >= json.size() || json[pos] != '[') {
        return false;
    }
    ++pos;
    std::vector<int64_t> vals;
    while (pos < json.size()) {
        while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) {
            ++pos;
        }
        if (pos < json.size() && json[pos] == ']') {
            ++pos;
            out = vals;
            return true;
        }
        bool neg = false;
        if (pos < json.size() && json[pos] == '-') {
            neg = true;
            ++pos;
        }
        if (pos >= json.size() || !std::isdigit(static_cast<unsigned char>(json[pos]))) {
            return false;
        }
        int64_t n = 0;
        while (pos < json.size() && std::isdigit(static_cast<unsigned char>(json[pos]))) {
            int digit = json[pos++] - '0';
            if (n > (INT64_MAX - digit) / 10) {
                return false;
            }
            n = n * 10 + digit;
        }
        int64_t v = neg ? -n : n;

        vals.push_back(v);

        while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) {
            ++pos;
        }
        if (pos < json.size() && json[pos] == ',') {
            ++pos;
        }
    }
    return false;
}

} // namespace

EmergencyControlConfig emergency_control_config_from_env()
{
    EmergencyControlConfig cfg{};
    parse_u64_env("AEGIS_CONTROL_LOG_MAX_BYTES", cfg.log_max_bytes);
    parse_u32_env("AEGIS_CONTROL_LOG_MAX_FILES", cfg.log_max_files);
    parse_u32_env("AEGIS_CONTROL_STORM_THRESHOLD", cfg.storm_threshold);
    parse_u32_env("AEGIS_CONTROL_STORM_WINDOW_SECONDS", cfg.storm_window_seconds);
    {
        uint64_t v = 0;
        if (parse_u64_env("AEGIS_CONTROL_REASON_MAX_BYTES", v)) {
            cfg.reason_max_bytes = (v > 0 && v <= 4096) ? static_cast<size_t>(v) : cfg.reason_max_bytes;
        }
    }
    parse_u32_env("AEGIS_CONTROL_LOCK_TIMEOUT_SECONDS", cfg.lock_timeout_seconds);

    if (cfg.log_max_files == 0) {
        cfg.log_max_files = 1;
    }
    if (cfg.storm_window_seconds == 0) {
        cfg.storm_window_seconds = 60;
    }
    return cfg;
}

std::string control_state_path_from_env()
{
    const char* env = std::getenv("AEGIS_CONTROL_STATE_PATH");
    if (env && *env) {
        return std::string(env);
    }
    return kControlStatePath;
}

std::string control_log_path_from_env()
{
    const char* env = std::getenv("AEGIS_CONTROL_LOG_PATH");
    if (env && *env) {
        return std::string(env);
    }
    return kControlLogPath;
}

std::string control_lock_path_from_env()
{
    const char* env = std::getenv("AEGIS_CONTROL_LOCK_PATH");
    if (env && *env) {
        return std::string(env);
    }
    return kControlLockPath;
}

std::string node_name_from_env_or_hostname()
{
    const char* env = std::getenv("AEGIS_NODE_NAME");
    if (env && *env) {
        return std::string(env);
    }
    char host[256];
    if (::gethostname(host, sizeof(host)) == 0) {
        host[sizeof(host) - 1] = '\0';
        return std::string(host);
    }
    return "unknown";
}

SanitizedReason sanitize_reason_and_hash(const std::string& raw_reason, size_t max_bytes)
{
    SanitizedReason out{};
    out.raw_sha256_hex = Sha256::hash_hex(raw_reason);

    std::string s;
    s.reserve(raw_reason.size());
    for (unsigned char c : raw_reason) {
        if (c < 0x20) {
            s.push_back(' ');
            continue;
        }
        s.push_back(static_cast<char>(c));
    }

    s = trim(s);

    if (max_bytes == 0) {
        max_bytes = 512;
    }
    static constexpr const char* kSuffix = "...(truncated)";
    if (s.size() > max_bytes) {
        out.truncated = true;
        const size_t suffix_len = std::strlen(kSuffix);
        if (max_bytes > suffix_len + 1) {
            s = s.substr(0, max_bytes - suffix_len) + kSuffix;
        } else {
            s = s.substr(0, max_bytes);
        }
    }

    out.sanitized = s;
    return out;
}

Result<EmergencyControlState> read_emergency_control_state(const std::string& path)
{
    std::ifstream in(path);
    if (!in.is_open()) {
        if (errno == ENOENT) {
            return Error::not_found("control state file");
        }
        return Error::system(errno, "Failed to open control state file");
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    const std::string json = buf.str();

    EmergencyControlState state{};
    {
        int64_t schema_version = 0;
        if (extract_json_int64_simple(json, "schema_version", schema_version)) {
            if (schema_version > 0 && schema_version <= INT32_MAX) {
                state.schema_version = static_cast<int>(schema_version);
            }
        }
    }
    extract_json_bool_simple(json, "enabled", state.enabled);
    extract_json_int64_simple(json, "changed_at_unix", state.changed_at_unix);
    {
        uint64_t v = 0;
        if (extract_json_uint64_simple(json, "uid", v) && v <= UINT32_MAX) {
            state.uid = static_cast<uint32_t>(v);
        }
        if (extract_json_uint64_simple(json, "pid", v) && v <= UINT32_MAX) {
            state.pid = static_cast<uint32_t>(v);
        }
        extract_json_uint64_simple(json, "transitions_total", state.transitions_total);
    }
    extract_json_string_simple(json, "node_name", state.node_name);
    extract_json_string_simple(json, "reason", state.reason);
    extract_json_string_simple(json, "reason_sha256", state.reason_sha256);
    extract_json_int64_array_simple(json, "transition_times_unix", state.transition_times_unix);
    if (state.transition_times_unix.size() > kMaxStoredTransitionTimes) {
        state.transition_times_unix.erase(state.transition_times_unix.begin(),
                                          state.transition_times_unix.end() - kMaxStoredTransitionTimes);
    }
    return state;
}

Result<void> write_emergency_control_state(const std::string& path, const EmergencyControlState& state)
{
    std::error_code ec;
    const std::filesystem::path p(path);
    const std::filesystem::path parent = p.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return Error(ErrorCode::IoError, "Failed to create control state directory", ec.message());
        }
    }

    return atomic_write_stream(path, [&](std::ostream& out) -> bool {
        out << "{\n";
        out << "  \"schema_version\": " << state.schema_version << ",\n";
        out << "  \"enabled\": " << (state.enabled ? "true" : "false") << ",\n";
        out << "  \"changed_at_unix\": " << state.changed_at_unix << ",\n";
        out << "  \"uid\": " << state.uid << ",\n";
        out << "  \"pid\": " << state.pid << ",\n";
        out << "  \"node_name\": \"" << json_escape(state.node_name) << "\",\n";
        out << "  \"reason\": \"" << json_escape(state.reason) << "\",\n";
        out << "  \"reason_sha256\": \"" << json_escape(state.reason_sha256) << "\",\n";
        out << "  \"transitions_total\": " << state.transitions_total << ",\n";
        out << "  \"transition_times_unix\": [";
        for (size_t i = 0; i < state.transition_times_unix.size(); ++i) {
            if (i > 0) {
                out << ", ";
            }
            out << state.transition_times_unix[i];
        }
        out << "]\n";
        out << "}\n";
        return out.good();
    });
}

EmergencyStormStatus evaluate_toggle_storm(const EmergencyControlState& state, const EmergencyControlConfig& cfg,
                                           int64_t now_unix)
{
    EmergencyStormStatus s{};
    s.threshold = cfg.storm_threshold;
    s.window_seconds = cfg.storm_window_seconds;

    if (cfg.storm_window_seconds == 0) {
        s.active = false;
        s.transitions_in_window = 0;
        return s;
    }

    const int64_t cutoff = now_unix - static_cast<int64_t>(cfg.storm_window_seconds);
    uint32_t count = 0;
    for (int64_t t : state.transition_times_unix) {
        if (t >= cutoff && t <= now_unix) {
            ++count;
        }
    }
    s.transitions_in_window = count;
    s.active = (cfg.storm_threshold > 0) && (count > cfg.storm_threshold);
    return s;
}

Result<ScopedFileLock> ScopedFileLock::acquire(const std::string& lock_path, uint32_t timeout_seconds)
{
    std::error_code ec;
    const std::filesystem::path p(lock_path);
    const std::filesystem::path parent = p.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return Error(ErrorCode::IoError, "Failed to create lock directory", ec.message());
        }
    }

    int fd = ::open(lock_path.c_str(), O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
        return Error::system(errno, "Failed to open control lock file");
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_seconds);
    while (true) {
        if (::flock(fd, LOCK_EX | LOCK_NB) == 0) {
            return ScopedFileLock(fd);
        }
        if (errno != EWOULDBLOCK) {
            int saved = errno;
            ::close(fd);
            return Error::system(saved, "Failed to lock control lock file");
        }
        if (timeout_seconds == 0 || std::chrono::steady_clock::now() >= deadline) {
            ::close(fd);
            return Error(ErrorCode::ResourceBusy, "Timed out acquiring control lock");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(kDefaultLockRetrySleepMs));
    }
}

ScopedFileLock::~ScopedFileLock()
{
    if (fd_ >= 0) {
        ::flock(fd_, LOCK_UN);
        ::close(fd_);
        fd_ = -1;
    }
}

ScopedFileLock::ScopedFileLock(ScopedFileLock&& other) noexcept : fd_(other.fd_)
{
    other.fd_ = -1;
}

ScopedFileLock& ScopedFileLock::operator=(ScopedFileLock&& other) noexcept
{
    if (this == &other) {
        return *this;
    }
    if (fd_ >= 0) {
        ::flock(fd_, LOCK_UN);
        ::close(fd_);
    }
    fd_ = other.fd_;
    other.fd_ = -1;
    return *this;
}

Result<void> rotate_jsonl_if_needed_pre_write(const std::string& path, uint64_t max_bytes, uint32_t max_files,
                                              uint64_t next_entry_size)
{
    if (max_bytes == 0) {
        return {};
    }
    if (max_files == 0) {
        max_files = 1;
    }

    std::error_code ec;
    const bool exists = std::filesystem::exists(path, ec);
    if (ec) {
        return Error(ErrorCode::IoError, "Failed to stat control log", ec.message());
    }
    if (!exists) {
        return {};
    }

    const uint64_t current = std::filesystem::file_size(path, ec);
    if (ec) {
        return Error(ErrorCode::IoError, "Failed to read control log size", ec.message());
    }
    if (current + next_entry_size <= max_bytes) {
        return {};
    }

    // Shift existing rotations: .(max_files-1) -> .max_files, ..., .1 -> .2
    for (uint32_t i = max_files; i >= 2; --i) {
        const std::string src = path + "." + std::to_string(i - 1);
        const std::string dst = path + "." + std::to_string(i);
        if (std::filesystem::exists(src, ec) && !ec) {
            (void)std::rename(src.c_str(), dst.c_str());
        }
        if (i == 2) {
            break; // avoid uint underflow
        }
    }

    const std::string first = path + ".1";
    (void)std::rename(path.c_str(), first.c_str());
    return {};
}

Result<void> append_jsonl_line(const std::string& path, const std::string& line)
{
    if (line.find('\n') != std::string::npos || line.find('\r') != std::string::npos) {
        return Error::invalid_argument("jsonl line contains newline characters");
    }

    std::error_code ec;
    const std::filesystem::path p(path);
    const std::filesystem::path parent = p.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return Error(ErrorCode::IoError, "Failed to create control log directory", ec.message());
        }
    }

    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) {
        return Error::system(errno, "Failed to open control log for append");
    }

    const std::string payload = line + "\n";
    size_t off = 0;
    while (off < payload.size()) {
        ssize_t wrote = ::write(fd, payload.data() + off, payload.size() - off);
        if (wrote < 0) {
            int saved = errno;
            ::close(fd);
            return Error::system(saved, "Failed to append control log");
        }
        off += static_cast<size_t>(wrote);
    }

    ::fsync(fd);
    ::close(fd);
    return {};
}

} // namespace aegis
