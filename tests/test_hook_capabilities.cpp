// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file syntaxError
#include <gtest/gtest.h>

#include <bpf/btf.h>

#include <algorithm>
#include <filesystem>
#include <set>
#include <string>
#include <unordered_map>

#include "bpf_ops.hpp"
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

// Regression coverage for PR #128 (silent disable of every optional LSM
// program). The bug was that `detect_missing_optional_lsm_hooks` looked
// up bare hook names (e.g. "bprm_check_security") in vmlinux BTF instead
// of the `bpf_lsm_<hook>` trampoline FUNC. The tests below pin the
// catalog shape so the lookup symbol can never silently regress to a
// bare-name form again.

TEST(OptionalLsmHookCatalog, NonEmpty)
{
    const auto catalog = optional_lsm_hook_catalog();
    EXPECT_FALSE(catalog.empty());
}

TEST(OptionalLsmHookCatalog, AllSymbolsUseBpfLsmPrefix)
{
    const auto catalog = optional_lsm_hook_catalog();
    for (const auto& spec : catalog) {
        // BPF-LSM attach binds to `bpf_lsm_<hook>` in vmlinux BTF; the bare
        // hook name is *not* a top-level FUNC (it only appears as a struct
        // member of the LSM hooks list).
        EXPECT_EQ(spec.btf_symbol.rfind("bpf_lsm_", 0), 0u)
            << "hook " << spec.hook_name << " has non-`bpf_lsm_` BTF symbol \""
            << spec.btf_symbol << "\" — would silently regress to autoload=false";
    }
}

TEST(OptionalLsmHookCatalog, HookNamesAreUnique)
{
    const auto catalog = optional_lsm_hook_catalog();
    std::set<std::string> seen;
    for (const auto& spec : catalog) {
        EXPECT_TRUE(seen.insert(spec.hook_name).second)
            << "duplicate hook_name in optional catalog: " << spec.hook_name;
    }
}

TEST(OptionalLsmHookCatalog, BtfSymbolsAreUnique)
{
    const auto catalog = optional_lsm_hook_catalog();
    std::set<std::string> seen;
    for (const auto& spec : catalog) {
        EXPECT_TRUE(seen.insert(spec.btf_symbol).second)
            << "duplicate btf_symbol in optional catalog: " << spec.btf_symbol;
    }
}

// The kernel renamed `file_mmap` → `mmap_file` pre-5.6. The operator-facing
// posture key (`lsm_file_mmap`) and the BPF program name (`handle_file_mmap`)
// keep the legacy spelling so JSON consumers stay byte-stable; the catalog
// must encode the rename for the actual BTF lookup.
TEST(OptionalLsmHookCatalog, MmapFileRenameIsEncoded)
{
    const auto catalog = optional_lsm_hook_catalog();
    auto it = std::find_if(catalog.begin(), catalog.end(),
                           [](const OptionalLsmHookSpec& s) { return s.hook_name == "file_mmap"; });
    ASSERT_NE(it, catalog.end()) << "catalog must keep the legacy `file_mmap` hook_name";
    EXPECT_EQ(it->btf_symbol, "bpf_lsm_mmap_file")
        << "`file_mmap` must map to the kernel's renamed `bpf_lsm_mmap_file` trampoline";
}

// The optional catalog (autoload gating, src/bpf_ops.cpp) and the probe
// catalog (operator-facing `aegisbpf probe`, src/hook_capabilities.cpp)
// must agree on the BTF symbol for every shared hook. If they drift, an
// operator could see `aegisbpf probe` report `lsm_<hook>: kernel_supported`
// while the daemon silently disables autoload — exactly the failure mode
// PR #128 fixed. This test pins the cross-catalog consistency.
TEST(OptionalLsmHookCatalog, AgreesWithProbeCatalog)
{
    const auto optional_catalog = optional_lsm_hook_catalog();
    const auto probe_catalog = probe_hook_capabilities();

    std::unordered_map<std::string, std::string> probe_by_name;
    probe_by_name.reserve(probe_catalog.size());
    for (const auto& cap : probe_catalog) {
        probe_by_name.emplace(cap.name, cap.btf_symbol);
    }

    for (const auto& spec : optional_catalog) {
        const std::string probe_key = "lsm_" + spec.hook_name;
        const auto it = probe_by_name.find(probe_key);
        ASSERT_NE(it, probe_by_name.end())
            << "optional hook " << spec.hook_name << " (probe key " << probe_key
            << ") missing from hook_capabilities catalog";
        EXPECT_EQ(it->second, spec.btf_symbol)
            << "btf_symbol drift between catalogs for hook " << spec.hook_name
            << " (optional=" << spec.btf_symbol << ", probe=" << it->second << ")";
    }
}

// On a host that actually has vmlinux BTF, every optional-hook BTF symbol
// the daemon would look up must be resolvable as a `BTF_KIND_FUNC`. This
// asserts the catalog's symbol names are not stale or typo'd against the
// running kernel — the strongest form of the regression check.
TEST(OptionalLsmHookCatalog, AllSymbolsResolveOnBtfHost)
{
    struct btf* vmlinux = btf__load_vmlinux_btf();
    const long btf_err = libbpf_get_error(vmlinux);
    if (btf_err != 0 || vmlinux == nullptr) {
        GTEST_SKIP() << "vmlinux BTF not available on this host";
    }

    const auto catalog = optional_lsm_hook_catalog();
    for (const auto& spec : catalog) {
        const int id = btf__find_by_name_kind(vmlinux, spec.btf_symbol.c_str(), BTF_KIND_FUNC);
        EXPECT_GE(id, 0) << "BTF symbol " << spec.btf_symbol << " (hook " << spec.hook_name
                         << ") not resolvable on host kernel — autoload would be silently disabled";
    }
    btf__free(vmlinux);
}

} // namespace
} // namespace aegis
