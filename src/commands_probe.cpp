// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Kernel probe and capability report command implementations
 */

#include "commands_probe.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#include "hook_capabilities.hpp"
#include "kernel_features.hpp"
#include "logging.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace aegis {

int cmd_probe()
{
    auto features_result = detect_kernel_features();
    if (!features_result) {
        logger().log(
            SLOG_ERROR("Failed to detect kernel features").field("error", features_result.error().to_string()));
        return 1;
    }
    const auto& features = *features_result;
    auto cap = determine_capability(features);

    bool btf_available_for_hooks = false;
    const auto hooks = probe_hook_capabilities(&btf_available_for_hooks);

    std::ostringstream out;
    out << "{\n";
    out << "  \"kernel_release\": \"" << json_escape(features.kernel_version) << "\",\n";
    out << "  \"bpf_lsm_enabled\": " << (features.bpf_lsm ? "true" : "false") << ",\n";
    out << "  \"cgroup_v2\": " << (features.cgroup_v2 ? "true" : "false") << ",\n";
    out << "  \"btf_available\": " << (features.btf ? "true" : "false") << ",\n";
    out << "  \"bpf_syscall\": " << (features.bpf_syscall ? "true" : "false") << ",\n";
    out << "  \"ringbuf\": " << (features.ringbuf ? "true" : "false") << ",\n";
    out << "  \"tracepoints\": " << (features.tracepoints ? "true" : "false") << ",\n";
    out << "  \"bpffs_mounted\": " << (check_bpffs_mounted() ? "true" : "false") << ",\n";
    out << "  \"capability\": \"" << json_escape(capability_name(cap)) << "\",\n";
    out << "  \"can_enforce_files\": " << (features.bpf_lsm ? "true" : "false") << ",\n";
    out << "  \"can_enforce_network\": " << (features.bpf_lsm ? "true" : "false") << ",\n";
    out << "  \"can_use_shadow_maps\": " << (features.bpf_syscall ? "true" : "false") << ",\n";
    out << "  \"hook_probe\": {\n";
    out << "    \"btf_available\": " << (btf_available_for_hooks ? "true" : "false") << ",\n";
    out << "    \"hooks\": {\n";
    for (size_t i = 0; i < hooks.size(); ++i) {
        out << "      \"" << json_escape(hooks[i].name) << "\": {"
            << "\"kernel_supported\": " << (hooks[i].kernel_supported ? "true" : "false")
            << ", \"required\": " << (hooks[i].required ? "true" : "false") << ", \"btf_symbol\": \""
            << json_escape(hooks[i].btf_symbol) << "\"" << ", \"description\": \"" << json_escape(hooks[i].description)
            << "\"}";
        out << (i + 1 == hooks.size() ? "\n" : ",\n");
    }
    out << "    }\n";
    out << "  }\n";
    out << "}\n";
    std::cout << out.str();
    return 0;
}

int cmd_capabilities(bool json_output)
{
    std::error_code ec;
    const char* env = std::getenv("AEGIS_CAPABILITIES_REPORT_PATH");
    const std::string path = (env && *env) ? std::string(env) : std::string(kCapabilitiesReportPath);
    if (!std::filesystem::exists(path, ec) || ec) {
        logger().log(SLOG_ERROR("Capability report not found").field("path", path));
        return 1;
    }
    std::ifstream in(path);
    if (!in.is_open()) {
        logger().log(SLOG_ERROR("Failed to open capability report").field("path", path));
        return 1;
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    const std::string payload = buf.str();
    if (json_output) {
        std::cout << payload;
        if (payload.empty() || payload.back() != '\n') {
            std::cout << "\n";
        }
        return 0;
    }
    std::cout << payload;
    return 0;
}

} // namespace aegis
