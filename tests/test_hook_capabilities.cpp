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

TEST(HookCapabilities, RequiredHooksAreSupportedOnHostWithBtf)
{
    bool btf_available = false;
    auto hooks = probe_hook_capabilities(&btf_available);

    if (!btf_available) {
        GTEST_SKIP() << "Kernel BTF not actually usable (libbpf failed to load it)";
    }

    for (const auto& h : hooks) {
        if (h.required) {
            EXPECT_TRUE(h.kernel_supported)
                << "required hook " << h.name << " (" << h.btf_symbol << ") not found in vmlinux BTF";
        }
    }
}

} // namespace
} // namespace aegis
