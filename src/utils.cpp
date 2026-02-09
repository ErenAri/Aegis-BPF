// cppcheck-suppress-file missingIncludeSystem
#include "utils.hpp"

#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <zlib.h>

#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "bpf_ops.hpp"
#include "crypto.hpp"
#include "logging.hpp"

namespace aegis {

std::string trim(const std::string& s)
{
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(start, end - start);
}

bool parse_key_value(const std::string& line, std::string& key, std::string& value)
{
    size_t pos = line.find('=');
    if (pos == std::string::npos) {
        return false;
    }
    key = trim(line.substr(0, pos));
    value = trim(line.substr(pos + 1));
    return !key.empty();
}

bool parse_uint64(const std::string& text, uint64_t& out)
{
    if (text.empty()) {
        return false;
    }
    // Reject negative numbers (strtoull accepts them and wraps around)
    if (text[0] == '-') {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    unsigned long long val = std::strtoull(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str() || *end != '\0') {
        return false;
    }
    out = static_cast<uint64_t>(val);
    return true;
}

bool parse_inode_id(const std::string& text, InodeId& out)
{
    size_t pos = text.find(':');
    if (pos == std::string::npos) {
        return false;
    }
    std::string dev_str = trim(text.substr(0, pos));
    std::string ino_str = trim(text.substr(pos + 1));
    uint64_t dev = 0;
    uint64_t ino = 0;
    if (!parse_uint64(dev_str, dev) || !parse_uint64(ino_str, ino)) {
        return false;
    }
    if (dev > UINT32_MAX) {
        return false;
    }
    out.dev = static_cast<uint32_t>(dev);
    out.ino = ino;
    out.pad = 0;
    return true;
}

std::string join_list(const std::vector<std::string>& items)
{
    std::ostringstream oss;
    for (size_t i = 0; i < items.size(); ++i) {
        if (i) {
            oss << ", ";
        }
        oss << items[i];
    }
    return oss.str();
}

std::string to_string(const char* buf, size_t sz)
{
    return std::string(buf, strnlen(buf, sz));
}

std::string json_escape(const std::string& in)
{
    std::string out;
    out.reserve(in.size() + 4);
    for (unsigned char c : in) {
        switch (c) {
            case '\\':
                out += "\\\\";
                break;
            case '"':
                out += "\\\"";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            default:
                // Escape control characters (0x00-0x1f) as \u00XX
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
                break;
        }
    }
    return out;
}

std::string prometheus_escape_label(const std::string& in)
{
    std::string out;
    out.reserve(in.size() + 4);
    for (char c : in) {
        switch (c) {
            case '\\':
                out += "\\\\";
                break;
            case '"':
                out += "\\\"";
                break;
            case '\n':
                out += "\\n";
                break;
            default:
                out += c;
                break;
        }
    }
    return out;
}

uint32_t encode_dev(dev_t dev)
{
    constexpr uint32_t kMinorBits = 20;
    constexpr uint32_t kMinorMask = (1U << kMinorBits) - 1U;
    constexpr uint32_t kMajorMask = (1U << (32 - kMinorBits)) - 1U;

    uint32_t maj = static_cast<uint32_t>(major(dev));
    uint32_t min = static_cast<uint32_t>(minor(dev));
    return ((maj & kMajorMask) << kMinorBits) | (min & kMinorMask);
}

Result<InodeId> path_to_inode(const std::string& path)
{
    struct stat st {};
    if (stat(path.c_str(), &st) != 0) {
        return Error::system(errno, "stat failed for " + path);
    }
    InodeId id{};
    id.ino = st.st_ino;
    id.dev = encode_dev(st.st_dev);
    id.pad = 0;
    return id;
}

Result<uint64_t> path_to_cgid(const std::string& path)
{
    struct stat st {};
    if (stat(path.c_str(), &st) != 0) {
        return Error::system(errno, "stat failed for " + path);
    }
    return static_cast<uint64_t>(st.st_ino);
}

void fill_path_key(const std::string& path, PathKey& key)
{
    std::memset(&key, 0, sizeof(key));
    size_t len = path.size();
    if (len >= sizeof(key.path)) {
        len = sizeof(key.path) - 1;
    }
    std::memcpy(key.path, path.data(), len);
}

std::string inode_to_string(const InodeId& id)
{
    std::ostringstream oss;
    oss << id.dev << ":" << id.ino;
    return oss.str();
}

// Thread-safe cgroup path cache implementation
CgroupPathCache& CgroupPathCache::instance()
{
    static CgroupPathCache instance;
    return instance;
}

std::string CgroupPathCache::try_open_by_handle(uint64_t cgid)
{
    // Lazy-open mount fd for /sys/fs/cgroup
    if (mount_fd_ < 0) {
        mount_fd_ = ::open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY);
        if (mount_fd_ < 0) {
            return {};
        }
    }

    // Construct a file handle from the cgroup inode number.
    // cgroup2 uses FILEID_INO32_GEN (type 1) with 8-byte handle.
    struct HandleBuf {
        struct file_handle fh;
        // NOLINTNEXTLINE(modernize-avoid-c-arrays)
        unsigned char extra[8];
    } hbuf{};
    hbuf.fh.handle_bytes = 8;
    hbuf.fh.handle_type = 1; // FILEID_INO32_GEN
    auto ino32 = static_cast<uint32_t>(cgid);
    memcpy(hbuf.fh.f_handle, &ino32, sizeof(ino32));
    // generation = 0 for pseudo-filesystems

    int fd = open_by_handle_at(mount_fd_, &hbuf.fh, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        return {};
    }

    // Read path back via /proc/self/fd/<fd>
    std::string fd_link = "/proc/self/fd/" + std::to_string(fd);
    char pathbuf[PATH_MAX];
    ssize_t len = readlink(fd_link.c_str(), pathbuf, sizeof(pathbuf) - 1);
    ::close(fd);
    if (len <= 0) {
        return {};
    }
    pathbuf[len] = '\0';
    return std::string(pathbuf, static_cast<size_t>(len));
}

void CgroupPathCache::rebuild_locked()
{
    // Batch-populate the entire cache in a single walk of /sys/fs/cgroup.
    // This amortizes the cost so subsequent misses are also cache hits.
    cache_.clear();
    fully_populated_ = true;

    try {
        std::error_code ec;
        std::filesystem::recursive_directory_iterator dir(
            "/sys/fs/cgroup", std::filesystem::directory_options::skip_permission_denied, ec);
        if (!ec) {
            auto end = std::filesystem::recursive_directory_iterator();
            for (; dir != end;) {
                std::error_code entry_ec;
                const bool is_directory = dir->is_directory(entry_ec);
                if (!entry_ec && is_directory) {
                    struct stat st {};
                    const auto path = dir->path();
                    if (stat(path.c_str(), &st) == 0) {
                        cache_[static_cast<uint64_t>(st.st_ino)] = path.string();
                    }
                }
                dir.increment(entry_ec);
                if (entry_ec) {
                    entry_ec.clear();
                }
            }
        }
    } catch (const std::exception&) {
        // partial map is better than no map
    }
}

std::string CgroupPathCache::resolve(uint64_t cgid)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_.find(cgid);
        if (it != cache_.end()) {
            return it->second;
        }
    }

    // Fast path: O(1) lookup via open_by_handle_at (no lock needed for the syscall)
    std::string found = try_open_by_handle(cgid);
    if (!found.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        cache_[cgid] = found;
        return found;
    }

    // Slow path: batch-rebuild the entire cache if not yet done
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!fully_populated_) {
            rebuild_locked();
            auto it = cache_.find(cgid);
            if (it != cache_.end()) {
                return it->second;
            }
        }
    }

    return {};
}

std::string resolve_cgroup_path(uint64_t cgid)
{
    return CgroupPathCache::instance().resolve(cgid);
}

std::string read_proc_cwd(uint32_t pid)
{
    std::string link = "/proc/" + std::to_string(pid) + "/cwd";
    char buf[PATH_MAX];
    ssize_t len = readlink(link.c_str(), buf, sizeof(buf) - 1);
    if (len < 0) {
        return {};
    }
    buf[len] = '\0';
    return std::string(buf);
}

// Thread-safe CWD cache implementation
CwdCache& CwdCache::instance()
{
    static CwdCache instance;
    return instance;
}

std::string CwdCache::resolve(uint32_t pid, uint64_t start_time, const std::string& path)
{
    if (path.empty() || path.front() == '/') {
        return path;
    }

    std::string cwd;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_.find(pid);
        if (it != cache_.end() && (!start_time || it->second.start_time == start_time)) {
            cwd = it->second.cwd;
        } else {
            cwd = read_proc_cwd(pid);
            if (cwd.empty()) {
                return path;
            }
            cache_[pid] = {start_time, cwd};
        }
    }

    std::filesystem::path combined = std::filesystem::path(cwd) / path;
    return combined.lexically_normal().string();
}

std::string resolve_relative_path(uint32_t pid, uint64_t start_time, const std::string& path)
{
    return CwdCache::instance().resolve(pid, start_time, path);
}

bool path_exists(const char* path, std::error_code& ec)
{
    ec.clear();
    return std::filesystem::exists(path, ec);
}

Result<std::string> validate_path(const std::string& path)
{
    if (path.empty()) {
        return Error(ErrorCode::InvalidArgument, "Path is empty");
    }
    if (path.size() >= kDenyPathMax) {
        return Error(ErrorCode::PathTooLong, "Path exceeds maximum length", path);
    }
    // Check for null bytes
    if (path.find('\0') != std::string::npos) {
        return Error(ErrorCode::InvalidArgument, "Path contains null bytes", path);
    }
    return path;
}

Result<std::string> validate_existing_path(const std::string& path)
{
    auto validated = validate_path(path);
    if (!validated) {
        return validated.error();
    }

    std::error_code ec;
    std::filesystem::path resolved = std::filesystem::canonical(path, ec);
    if (ec) {
        return Error(ErrorCode::PathNotFound, "Path does not exist or cannot be resolved", path);
    }
    return resolved.string();
}

Result<std::string> validate_cgroup_path(const std::string& path)
{
    auto validated = validate_existing_path(path);
    if (!validated) {
        return validated.error();
    }

    // Verify it's under /sys/fs/cgroup
    std::string resolved = *validated;
    if (resolved.rfind("/sys/fs/cgroup", 0) != 0) {
        return Error(ErrorCode::InvalidArgument, "Path is not under /sys/fs/cgroup", path);
    }

    // Verify it's a directory
    std::error_code ec;
    if (!std::filesystem::is_directory(resolved, ec)) {
        return Error(ErrorCode::InvalidArgument, "Cgroup path is not a directory", path);
    }

    return resolved;
}

std::string read_file_first_line(const std::string& path)
{
    std::ifstream in(path);
    std::string line;
    if (!in.is_open()) {
        return {};
    }
    if (!std::getline(in, line)) {
        return {};
    }
    return line;
}

std::string find_kernel_config_value_in_file(const std::string& path, const std::string& key)
{
    std::ifstream in(path);
    if (!in.is_open()) {
        return {};
    }
    std::string line;
    std::string prefix = key + "=";
    while (std::getline(in, line)) {
        if (line.rfind(prefix, 0) == 0) {
            return line.substr(prefix.size());
        }
    }
    return {};
}

std::string find_kernel_config_value_in_proc(const std::string& key)
{
    if (!std::filesystem::exists("/proc/config.gz")) {
        return {};
    }
    gzFile gz = gzopen("/proc/config.gz", "rb");
    if (gz == nullptr) {
        return {};
    }
    std::string prefix = key + "=";
    char buf[4096];
    std::string value;
    while (gzgets(gz, buf, sizeof(buf)) != nullptr) {
        std::string line(buf);
        if (line.rfind(prefix, 0) == 0) {
            value = line.substr(prefix.size());
            value = trim(value);
            break;
        }
    }
    gzclose(gz);
    return value;
}

std::string kernel_config_value(const std::string& key)
{
    struct utsname uts {};
    if (uname(&uts) == 0) {
        std::string path = std::string("/boot/config-") + uts.release;
        std::string value = find_kernel_config_value_in_file(path, key);
        if (!value.empty()) {
            return value;
        }
    }
    return find_kernel_config_value_in_proc(key);
}

Result<void> atomic_write_file(const std::string& target_path, const std::string& content)
{
    return atomic_write_stream(target_path, [&](std::ostream& out) -> bool {
        out << content;
        return out.good();
    });
}

Result<void> atomic_write_stream(const std::string& target_path,
                                 const std::function<bool(std::ostream&)>& writer)
{
    // Build temp path in the same directory as target to ensure same filesystem for rename().
    std::string dir;
    auto slash = target_path.rfind('/');
    if (slash != std::string::npos) {
        dir = target_path.substr(0, slash + 1);
    } else {
        dir = "./";
    }
    std::string tmpl = dir + ".aegis_tmp_XXXXXX";
    std::vector<char> tmpl_buf(tmpl.begin(), tmpl.end());
    tmpl_buf.push_back('\0');

    int fd = mkstemp(tmpl_buf.data());
    if (fd < 0) {
        return Error::system(errno, "mkstemp failed for atomic write to " + target_path);
    }
    std::string tmp_path(tmpl_buf.data());

    // Write content through ofstream wrapping the fd.
    // Close the fd first, then open via path (portable approach).
    ::close(fd);

    {
        std::ofstream out(tmp_path, std::ios::trunc);
        if (!out.is_open()) {
            std::remove(tmp_path.c_str());
            return Error(ErrorCode::IoError, "Failed to open temp file for atomic write", tmp_path);
        }
        if (!writer(out)) {
            out.close();
            std::remove(tmp_path.c_str());
            return Error(ErrorCode::IoError, "Failed to write temp file for atomic write", tmp_path);
        }
        out.flush();
        if (!out.good()) {
            out.close();
            std::remove(tmp_path.c_str());
            return Error(ErrorCode::IoError, "Flush failed for atomic write", tmp_path);
        }
    }

    // fsync the temp file to ensure data is on disk before rename.
    {
        int sync_fd = ::open(tmp_path.c_str(), O_RDONLY);
        if (sync_fd >= 0) {
            ::fsync(sync_fd);
            ::close(sync_fd);
        }
    }

    // Atomic rename
    if (std::rename(tmp_path.c_str(), target_path.c_str()) != 0) {
        int saved_errno = errno;
        std::remove(tmp_path.c_str());
        return Error::system(saved_errno, "rename failed for atomic write to " + target_path);
    }

    return {};
}

DenyEntries read_deny_db()
{
    DenyEntries entries;
    std::ifstream in(kDenyDbPath);
    if (!in.is_open()) {
        return entries;
    }
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        uint32_t dev = 0;
        uint64_t ino = 0;
        std::string path;
        if (!(iss >> dev >> ino)) {
            continue;
        }
        if (!(iss >> path)) {
            path.clear();
        }
        InodeId id{};
        id.ino = ino;
        id.dev = dev;
        entries[id] = path;
    }
    return entries;
}

Result<void> write_deny_db(const DenyEntries& entries)
{
    auto db_result = ensure_db_dir();
    if (!db_result) {
        return db_result.error();
    }
    return atomic_write_stream(kDenyDbPath, [&](std::ostream& out) -> bool {
        for (const auto& kv : entries) {
            out << kv.first.dev << " " << kv.first.ino;
            if (!kv.second.empty()) {
                out << " " << kv.second;
            }
            out << "\n";
        }
        return out.good();
    });
}

std::string build_exec_id(uint32_t pid, uint64_t start_time)
{
    if (pid == 0 || start_time == 0) {
        return {};
    }
    return std::to_string(start_time) + "-" + std::to_string(pid);
}

bool detect_break_glass()
{
    // Check 1: Boot parameter in /proc/cmdline
    std::string cmdline = read_file_first_line("/proc/cmdline");
    if (cmdline.find("aegisbpf.break_glass=1") != std::string::npos) {
        return true;
    }

    // Check 2: File flag at /etc/aegisbpf/break_glass
    std::error_code ec;
    if (std::filesystem::exists(kBreakGlassPath, ec) && !ec) {
        return true;
    }

    // Check 3: File flag at /var/lib/aegisbpf/break_glass
    if (std::filesystem::exists(kBreakGlassVarPath, ec) && !ec) {
        return true;
    }

    // Check 4: Signed break-glass token
    if (std::filesystem::exists(kBreakGlassTokenPath, ec) && !ec) {
        // Validate token file permissions
        auto perm = validate_file_permissions(kBreakGlassTokenPath, geteuid() == 0);
        if (!perm) {
            logger().log(SLOG_WARN("Break-glass token has bad permissions")
                             .field("path", kBreakGlassTokenPath)
                             .field("error", perm.error().to_string()));
        } else {
            // Read and validate token content
            auto keys = load_trusted_keys();
            if (keys && !keys->empty()) {
                std::string token_content = read_file_first_line(kBreakGlassTokenPath);
                if (validate_break_glass_token(token_content, *keys)) {
                    return true;
                }
                logger().log(
                    SLOG_WARN("Break-glass token failed validation").field("path", kBreakGlassTokenPath));
            } else {
                logger().log(SLOG_WARN("No trusted keys available to validate break-glass token"));
            }
        }
    }

    return false;
}

// cppcheck-suppress unusedFunction
Result<std::pair<InodeId, std::string>> canonicalize_path(const std::string& path)
{
    if (path.empty()) {
        return Error(ErrorCode::InvalidArgument, "Path is empty");
    }

    std::error_code ec;
    std::filesystem::path resolved = std::filesystem::canonical(path, ec);
    if (ec) {
        return Error(ErrorCode::PathResolutionFailed, "Failed to canonicalize path", path + ": " + ec.message());
    }

    std::string resolved_str = resolved.string();

    struct stat st {};
    if (stat(resolved_str.c_str(), &st) != 0) {
        return Error::system(errno, "stat failed for " + resolved_str);
    }

    InodeId id{};
    id.ino = st.st_ino;
    id.dev = encode_dev(st.st_dev);
    id.pad = 0;

    return std::make_pair(id, resolved_str);
}

// cppcheck-suppress unusedFunction
Result<InodeId> resolve_to_inode(const std::string& path, bool follow_symlinks)
{
    if (path.empty()) {
        return Error(ErrorCode::InvalidArgument, "Path is empty");
    }

    struct stat st {};
    int rc;
    if (follow_symlinks) {
        rc = stat(path.c_str(), &st);
    } else {
        rc = lstat(path.c_str(), &st);
    }

    if (rc != 0) {
        return Error::system(errno, "stat failed for " + path);
    }

    InodeId id{};
    id.ino = st.st_ino;
    id.dev = encode_dev(st.st_dev);
    id.pad = 0;
    return id;
}

Result<void> validate_config_directory_permissions(const std::string& path)
{
    struct stat st {};
    if (stat(path.c_str(), &st) != 0) {
        if (errno == ENOENT) {
            // Directory doesn't exist - this is okay, it will be created
            return {};
        }
        return Error::system(errno, "Failed to stat config directory: " + path);
    }

    // Must be a directory
    if (!S_ISDIR(st.st_mode)) {
        return Error(ErrorCode::InvalidArgument, "Config path is not a directory", path);
    }

    // Must be owned by root (uid 0)
    if (st.st_uid != 0) {
        return Error(ErrorCode::PermissionDenied, "Config directory must be owned by root",
                     path + " (owner uid=" + std::to_string(st.st_uid) + ")");
    }

    // Check permissions: must not be world-writable (no 'other' write bit)
    // Acceptable modes: 0700, 0750, 0755
    mode_t mode = st.st_mode & 0777;
    if (mode & S_IWOTH) {
        return Error(ErrorCode::PermissionDenied, "Config directory must not be world-writable",
                     path + " (mode=" + std::to_string(mode) + ")");
    }

    // Warn if group-writable but not fail (some setups may need this)
    if (mode & S_IWGRP) {
        // Just a warning, not an error
    }

    return {};
}

Result<void> validate_file_permissions(const std::string& path, bool require_root_owner)
{
    struct stat st {};
    if (stat(path.c_str(), &st) != 0) {
        if (errno == ENOENT) {
            // File doesn't exist - this may be okay depending on context
            return Error(ErrorCode::PathNotFound, "File not found", path);
        }
        return Error::system(errno, "Failed to stat file: " + path);
    }

    // Must be a regular file
    if (!S_ISREG(st.st_mode)) {
        return Error(ErrorCode::InvalidArgument, "Path is not a regular file", path);
    }

    // Must be owned by root if required
    if (require_root_owner && st.st_uid != 0) {
        return Error(ErrorCode::PermissionDenied, "File must be owned by root",
                     path + " (owner uid=" + std::to_string(st.st_uid) + ")");
    }

    // Check permissions: must not be world-writable
    mode_t mode = st.st_mode & 0777;
    if (mode & S_IWOTH) {
        return Error(ErrorCode::PermissionDenied, "File must not be world-writable",
                     path + " (mode=" + std::to_string(mode) + ")");
    }

    // Warn if group-writable (but don't fail)
    if (mode & S_IWGRP) {
        // Could add logging here
    }

    return {};
}

} // namespace aegis
