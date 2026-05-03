// cppcheck-suppress-file missingIncludeSystem
#include "btf_loader.hpp"

#include <unistd.h>

#include <cstdlib>

namespace aegis {

namespace {

// Wrapper around access(2) so tests can stub a vfs without dragging
// in std::filesystem. R_OK because libbpf will need to read the blob.
bool readable(const std::string& path)
{
    return ::access(path.c_str(), R_OK) == 0;
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

    out.source = "none";
    return out;
}

} // namespace aegis
