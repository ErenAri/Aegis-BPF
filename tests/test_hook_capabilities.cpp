// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file syntaxError
#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <set>
#include <string>

#include "hook_capabilities.hpp"

namespace aegis {
namespace {

TEST(HookCapabilities, CatalogShapeIsStable)
{
    bool btf_available = false;
    auto hooks = probe_hook_capabilities(&btf_available);

    // The catalog is part of the public capability contract; size and the
    // set of names must not silently drift. If you intentionally add or
    // remove a hook, update this expectation AND docs/CAPABILITY_REPORT.md.
    EXPECT_EQ(hooks.size(), 14u);

    const std::set<std::string> expected_names = {
        "lsm_file_open",     "lsm_inode_permission", "lsm_bprm_check_security", "lsm_bprm_ima_check",
        "lsm_file_mmap",     "lsm_socket_connect",   "lsm_socket_bind",         "lsm_socket_listen",
        "lsm_socket_accept", "lsm_socket_sendmsg",   "lsm_socket_recvmsg",      "lsm_ptrace_access_check",
        "lsm_locked_down",   "lsm_inode_copy_up",
    };
    std::set<std::string> actual_names;
    for (const auto& h : hooks) {
        actual_names.insert(h.name);
    }
    EXPECT_EQ(actual_names, expected_names);
}

TEST(HookCapabilities, BtfSymbolsUseBpfLsmPrefix)
{
    auto hooks = probe_hook_capabilities();
    for (const auto& h : hooks) {
        EXPECT_EQ(h.btf_symbol.rfind("bpf_lsm_", 0), 0u) << "hook " << h.name << " has unexpected BTF symbol "
                                                         << h.btf_symbol << " (expected bpf_lsm_<hook> prefix)";
    }
}

TEST(HookCapabilities, RequiredFlagMatchesContract)
{
    // Only file_open and inode_permission are required to run AegisBPF;
    // every other hook is optional and may be missing on older kernels.
    auto hooks = probe_hook_capabilities();
    std::set<std::string> required;
    for (const auto& h : hooks) {
        if (h.required) {
            required.insert(h.name);
        }
    }
    const std::set<std::string> expected_required = {"lsm_file_open", "lsm_inode_permission"};
    EXPECT_EQ(required, expected_required);
}

TEST(HookCapabilities, BtfMissingMakesAllHooksUnsupported)
{
    // If vmlinux BTF is genuinely unavailable on this host, the probe must
    // signal that via the out-parameter and report every hook as
    // unsupported. We can't force BTF to disappear in a unit test, but we
    // can at least assert the documented invariant when the host happens
    // to lack /sys/kernel/btf/vmlinux.
    if (std::filesystem::exists("/sys/kernel/btf/vmlinux")) {
        GTEST_SKIP() << "vmlinux BTF present; cannot exercise the no-BTF path here";
    }
    bool btf_available = true;
    auto hooks = probe_hook_capabilities(&btf_available);
    EXPECT_FALSE(btf_available);
    for (const auto& h : hooks) {
        EXPECT_FALSE(h.kernel_supported) << "hook " << h.name << " was reported supported with no BTF";
    }
}

TEST(HookCapabilities, RequiredHooksAreSupportedOnHostWithBtf)
{
    // On any kernel new enough to expose vmlinux BTF, the two required
    // hooks must appear: AegisBPF cannot run otherwise. This catches a
    // catalog typo or a BTF-symbol drift the moment it lands.
    if (!std::filesystem::exists("/sys/kernel/btf/vmlinux")) {
        GTEST_SKIP() << "vmlinux BTF not available; skipping host-dependent assertion";
    }
    bool btf_available = false;
    auto hooks = probe_hook_capabilities(&btf_available);
    ASSERT_TRUE(btf_available);
    for (const auto& h : hooks) {
        if (h.required) {
            EXPECT_TRUE(h.kernel_supported)
                << "required hook " << h.name << " (" << h.btf_symbol << ") not found in vmlinux BTF";
        }
    }
}

} // namespace
} // namespace aegis
