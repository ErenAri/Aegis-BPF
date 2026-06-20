// cppcheck-suppress-file missingIncludeSystem
#include "btf_loader.hpp"

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <string_view>

namespace aegis {

namespace {

// Wrapper around access(2) so tests can stub a vfs without dragging
// in std::filesystem. R_OK because libbpf will need to read the blob.
bool readable(const std::string& path)
{
    return ::access(path.c_str(), R_OK) == 0;
}

bool safe_kernel_release(std::string_view release)
{
    if (release.empty() || release.size() > 256) {
        return false;
    }
    for (unsigned char c : release) {
        if (std::isalnum(c) != 0 || c == '.' || c == '-' || c == '_' || c == '+' || c == '~') {
            continue;
        }
        return false;
    }
    return true;
}

bool run_btfgen(const std::string& btfgen, const std::string& kernel_release, const std::string& output_dir)
{
    pid_t pid = ::fork();
    if (pid < 0) {
        return false;
    }

    if (pid == 0) {
        int dev_null = ::open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (dev_null >= 0) {
            (void)::dup2(dev_null, STDOUT_FILENO);
            (void)::dup2(dev_null, STDERR_FILENO);
            (void)::close(dev_null);
        }

        ::execl(btfgen.c_str(), btfgen.c_str(), kernel_release.c_str(), "--output-dir", output_dir.c_str(), "--quiet",
                static_cast<char*>(nullptr));
        _exit(127);
    }

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

// Attempt to download a BTF blob from BTFhub-archive by invoking
// btfgen.sh as a child process.  Returns the path on success, or
// empty string on failure.  This is opt-in: only called when
// AEGIS_BTF_AUTO_DOWNLOAD=1.
std::string try_btfhub_download(const std::string& kernel_release, const std::string& output_dir)
{
    if (!safe_kernel_release(kernel_release)) {
        return {};
    }

    // Locate btfgen.sh: first look relative to the running binary
    // (../scripts/btfgen.sh from bin/), then fall back to $PATH.
    // We also accept an explicit override via AEGIS_BTFGEN_PATH.
    std::string btfgen;
    const char* env_btfgen = ::getenv("AEGIS_BTFGEN_PATH");
    if (env_btfgen != nullptr && readable(env_btfgen)) {
        btfgen = env_btfgen;
    } else {
        // Try well-known locations.
        for (const auto& candidate : {
                 std::string("/usr/lib/aegisbpf/scripts/btfgen.sh"),
                 std::string("/usr/share/aegisbpf/scripts/btfgen.sh"),
             }) {
            if (readable(candidate)) {
                btfgen = candidate;
                break;
            }
        }
    }
    if (btfgen.empty()) {
        return {};
    }

    if (!run_btfgen(btfgen, kernel_release, output_dir)) {
        return {};
    }

    std::string dest = output_dir + "/" + kernel_release + ".btf";
    if (readable(dest)) {
        return dest;
    }
    return {};
}

} // namespace

std::string btf_path_env_override()
{
    const char* v = ::getenv("AEGIS_BTF_PATH");
    return v ? std::string(v) : std::string();
}

BtfResolution resolve_btf_path(const std::string& kernel_release, const std::string& override)
{
    BtfResolution out;

    // 1. Explicit override (highest priority — operator knows best).
    if (!override.empty()) {
        out.searched.push_back(override);
        if (readable(override)) {
            out.path = override;
            out.source = "override";
            return out;
        }
        // Override set but unreadable: signal the mismatch so the
        // caller can choose to fail rather than silently falling
        // back to the kernel-built-in path (which might cause subtle
        // CO-RE relocation drift).
        out.source = "override-missing";
        return out;
    }

    // 2. Kernel built-in: fast path. Empty `path` tells libbpf to use
    // /sys/kernel/btf/vmlinux automatically — we don't need to set
    // btf_custom_path at all.
    if (readable("/sys/kernel/btf/vmlinux")) {
        out.source = "kernel";
        return out;
    }

    if (kernel_release.empty()) {
        out.source = "none";
        return out;
    }

    // 3-6. BTFhub-style fallback locations, ordered by preference.
    const std::vector<std::pair<std::string, std::string>> candidates = {
        {"/lib/modules/" + kernel_release + "/btf/vmlinux", "modules"},
        {"/var/lib/aegisbpf/btfs/" + kernel_release + ".btf", "var-lib"},
        {"/usr/lib/aegisbpf/btfs/" + kernel_release + ".btf", "usr-lib"},
        {"/etc/aegisbpf/btfs/" + kernel_release + ".btf", "etc"},
    };

    for (const auto& [path, tag] : candidates) {
        out.searched.push_back(path);
        if (readable(path)) {
            out.path = path;
            out.source = tag;
            return out;
        }
    }

    // 7. Auto-download from BTFhub-archive (opt-in).
    const char* auto_dl = ::getenv("AEGIS_BTF_AUTO_DOWNLOAD");
    if (auto_dl != nullptr && std::string(auto_dl) == "1") {
        const std::string var_lib_dir = "/var/lib/aegisbpf/btfs";
        const std::string downloaded = try_btfhub_download(kernel_release, var_lib_dir);
        if (!downloaded.empty()) {
            out.path = downloaded;
            out.source = "btfhub-download";
            out.searched.push_back(downloaded);
            return out;
        }
        out.searched.push_back("btfhub-archive (download attempted, failed)");
    }

    out.source = "none";
    return out;
}

} // namespace aegis
