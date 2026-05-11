// cppcheck-suppress-file missingIncludeSystem
#include "bpf_link_pin.hpp"

#include <bpf/libbpf.h>

#include <linux/magic.h>

#include <dirent.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include <cerrno>
#include <cstring>

#include "bpf_ops.hpp"
#include "logging.hpp"

namespace aegis {

bool is_bpffs_mounted(const std::string& path)
{
    struct statfs sfs {};
    if (statfs(path.c_str(), &sfs) != 0) {
        return false;
    }
    // BPF_FS_MAGIC is defined in <linux/magic.h>. Cast both sides to the
    // same width because f_type is signed on glibc but the magic is a
    // small positive constant.
    return static_cast<unsigned long>(sfs.f_type) == static_cast<unsigned long>(BPF_FS_MAGIC);
}

Result<void> ensure_pin_root(const std::string& dir)
{
    struct stat st {};
    if (stat(dir.c_str(), &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            return Error(ErrorCode::IoError, "Pin root exists but is not a directory: " + dir);
        }
        return {};
    }
    if (errno != ENOENT) {
        return Error(ErrorCode::IoError, std::string("stat(pin_root) failed: ") + std::strerror(errno));
    }
    if (mkdir(dir.c_str(), 0700) != 0) {
        return Error(ErrorCode::IoError, std::string("mkdir(pin_root) failed: ") + std::strerror(errno));
    }
    return {};
}

size_t count_existing_pins(const std::string& pin_root)
{
    DIR* d = opendir(pin_root.c_str());
    if (!d) {
        return 0;
    }
    size_t count = 0;
    struct dirent* entry = nullptr;
    while ((entry = readdir(d)) != nullptr) {
        // Skip "." and ".." — only count real pin entries.
        if (entry->d_name[0] == '.' &&
            (entry->d_name[1] == '\0' || (entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) {
            continue;
        }
        ++count;
    }
    closedir(d);
    return count;
}

namespace {

// Reject program names containing '/' or '..' so a hostile or buggy BPF
// object can never escape `pin_root`. libbpf-derived program names are
// already constrained to C identifiers, but defense in depth costs nothing.
bool is_safe_program_name(const std::string& name)
{
    if (name.empty() || name == "." || name == "..") {
        return false;
    }
    for (char c : name) {
        if (c == '/' || c == '\0') {
            return false;
        }
    }
    if (name.find("..") != std::string::npos) {
        return false;
    }
    return true;
}

} // namespace

Result<void> pin_attached_link(const std::string& program_name, bpf_link* link, const std::string& pin_root,
                               BpfState& state)
{
    if (!link) {
        return Error(ErrorCode::InvalidArgument, "pin_attached_link: null link");
    }
    if (!is_safe_program_name(program_name)) {
        return Error(ErrorCode::InvalidArgument, "pin_attached_link: unsafe program name '" + program_name + "'");
    }
    const std::string pin_path = pin_root + "/" + program_name;
    int err = bpf_link__pin(link, pin_path.c_str());
    if (err) {
        return Error::bpf_error(err, "bpf_link__pin failed for " + pin_path);
    }
    PinnedHook hook;
    hook.program_name = program_name;
    hook.link = link;
    hook.pin_path = pin_path;
    state.pinned_hooks.push_back(std::move(hook));
    return {};
}

size_t verify_pinned_hooks(BpfState& state)
{
    size_t missing = 0;
    for (const auto& hook : state.pinned_hooks) {
        struct stat st {};
        if (stat(hook.pin_path.c_str(), &st) != 0) {
            ++missing;
            logger().log(SLOG_ERROR("Pinned LSM hook missing — enforcement may be degraded")
                             .field("program", hook.program_name)
                             .field("pin_path", hook.pin_path)
                             .field("errno", static_cast<int64_t>(errno)));
        }
    }
    return missing;
}

} // namespace aegis
