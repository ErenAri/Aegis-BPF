// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Health and doctor command implementations
 */

#include "commands_health.hpp"

#include <unistd.h>

#include <array>
#include <cerrno>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

#include "bpf_ops.hpp"
#include "kernel_features.hpp"
#include "logging.hpp"
#include "tracing.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace aegis {

namespace {

Result<void> verify_pinned_map_access(const char* pin_path)
{
    int fd = bpf_obj_get(pin_path);
    if (fd < 0) {
        if (errno == ENOENT) {
            return Error(ErrorCode::ResourceNotFound, "Pinned map not found", pin_path);
        }
        return Error::system(errno, "Failed to open pinned map");
    }
    close(fd);
    return {};
}

struct HealthReport {
    bool ok = false;
    std::string error;
    std::string degradation_reason;
    KernelFeatures features{};
    EnforcementCapability capability = EnforcementCapability::Disabled;
    std::string capability_tier = "Disabled";
    std::string engine_mode = "unavailable";
    std::string kernel_version = "unknown";
    std::string bpf_object_path;
    bool bpffs_mounted = false;
    bool bpf_object_found = false;
    bool bpf_hash_found = false;
    bool bpf_hash_verified = false;
    bool bpf_allow_unsigned = false;
    bool prereqs_ok = false;
    bool bpf_load_ok = false;
    bool required_maps_ok = false;
    bool layout_ok = false;
    bool required_pins_ok = false;
    bool network_maps_present = false;
    bool network_pins_ok = true;
};

struct DoctorAdvice {
    std::string code;
    std::string message;
    std::string remediation;
};

HealthReport collect_health_report(const std::string& trace_id, const std::string& parent_span_id)
{
    HealthReport report;

    ScopedSpan feature_span("health.detect_kernel_features", trace_id, parent_span_id);
    auto features_result = detect_kernel_features();
    if (!features_result) {
        feature_span.fail(features_result.error().to_string());
        logger().log(SLOG_ERROR("Kernel feature detection failed").field("error", features_result.error().to_string()));
        report.error = features_result.error().to_string();
        return report;
    }
    report.features = *features_result;
    report.kernel_version = report.features.kernel_version;
    report.capability = determine_capability(report.features);
    report.capability_tier = capability_name(report.capability);
    report.engine_mode =
        report.capability == EnforcementCapability::Full
            ? "bpf_lsm"
            : (report.capability == EnforcementCapability::AuditOnly ? "tracepoint_audit" : "unavailable");
    report.bpffs_mounted = check_bpffs_mounted();
    report.bpf_object_path = resolve_bpf_obj_path();

    std::error_code ec;
    report.bpf_object_found = std::filesystem::exists(report.bpf_object_path, ec);
    if (!report.bpf_object_found) {
        report.degradation_reason = "bpf_object_missing";
        report.error = "BPF object file not found: " + report.bpf_object_path;
        logger().log(SLOG_ERROR("BPF object file not found").field("path", report.bpf_object_path));
        return report;
    }

    report.bpf_allow_unsigned = allow_unsigned_bpf_enabled();
    auto integrity_result = evaluate_bpf_integrity(false, report.bpf_allow_unsigned);
    if (!integrity_result) {
        report.degradation_reason = "bpf_integrity_failed";
        report.error = integrity_result.error().to_string();
        logger().log(SLOG_ERROR("BPF integrity check failed").field("error", report.error));
        return report;
    }
    report.bpf_hash_found = integrity_result->hash_exists;
    report.bpf_hash_verified = integrity_result->hash_verified;
    if (!integrity_result->reason.empty()) {
        report.degradation_reason = integrity_result->reason;
    }

    report.prereqs_ok = report.features.cgroup_v2 && report.features.btf && report.features.bpf_syscall &&
                        report.bpffs_mounted && report.capability != EnforcementCapability::Disabled;
    if (!report.prereqs_ok) {
        if (report.degradation_reason.empty()) {
            report.degradation_reason = report.capability == EnforcementCapability::AuditOnly
                                            ? "bpf_lsm_unavailable"
                                            : "kernel_prereqs_missing";
        }
        report.error =
            "Kernel prerequisites are not met: " + capability_explanation(report.features, report.capability);
        logger().log(SLOG_ERROR("Kernel prerequisites are not met")
                         .field("explanation", capability_explanation(report.features, report.capability)));
        return report;
    }

    BpfState state;
    ScopedSpan load_span("health.load_bpf", trace_id, parent_span_id);
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        load_span.fail(load_result.error().to_string());
        logger().log(SLOG_ERROR("BPF health check failed - cannot load BPF object")
                         .field("error", load_result.error().to_string()));
        report.error = "BPF load failed: " + load_result.error().to_string();
        return report;
    }
    report.bpf_load_ok = true;

    if (!state.deny_inode || !state.deny_path || !state.allow_cgroup || !state.allow_exec_inode ||
        !state.exec_identity_mode || !state.events) {
        logger().log(SLOG_ERROR("BPF health check failed - missing required maps"));
        report.error = "BPF health check failed - missing required maps";
        return report;
    }
    report.required_maps_ok = true;

    ScopedSpan layout_span("health.ensure_layout_version", trace_id, parent_span_id);
    auto version_result = ensure_layout_version(state);
    if (!version_result) {
        layout_span.fail(version_result.error().to_string());
        logger().log(SLOG_ERROR("BPF health check failed - layout version check failed")
                         .field("error", version_result.error().to_string()));
        report.error = "Layout version check failed: " + version_result.error().to_string();
        return report;
    }
    report.layout_ok = true;

    const std::array<const char*, 11> required_pin_paths = {
        kDenyInodePin,        kDenyPathPin,   kAllowCgroupPin,       kAllowExecInodePin,
        kExecIdentityModePin, kBlockStatsPin, kDenyCgroupStatsPin,   kDenyInodeStatsPin,
        kDenyPathStatsPin,    kAgentMetaPin,  kSurvivalAllowlistPin,
    };
    for (const char* pin_path : required_pin_paths) {
        auto pin_result = verify_pinned_map_access(pin_path);
        if (!pin_result) {
            logger().log(SLOG_ERROR("Pinned map check failed")
                             .field("path", pin_path)
                             .field("error", pin_result.error().to_string()));
            report.error = "Pinned map check failed: " + std::string(pin_path);
            return report;
        }
    }
    report.required_pins_ok = true;

    const std::array<std::pair<bpf_map*, const char*>, 10> optional_network_maps = {{
        {state.deny_ipv4, kDenyIpv4Pin},
        {state.deny_ipv6, kDenyIpv6Pin},
        {state.deny_port, kDenyPortPin},
        {state.deny_ip_port_v4, kDenyIpPortV4Pin},
        {state.deny_ip_port_v6, kDenyIpPortV6Pin},
        {state.deny_cidr_v4, kDenyCidrV4Pin},
        {state.deny_cidr_v6, kDenyCidrV6Pin},
        {state.net_block_stats, kNetBlockStatsPin},
        {state.net_ip_stats, kNetIpStatsPin},
        {state.net_port_stats, kNetPortStatsPin},
    }};
    for (const auto& [map, pin_path] : optional_network_maps) {
        if (!map) {
            continue;
        }
        report.network_maps_present = true;
        auto pin_result = verify_pinned_map_access(pin_path);
        if (!pin_result) {
            report.network_pins_ok = false;
            logger().log(SLOG_ERROR("Network pinned map check failed")
                             .field("path", pin_path)
                             .field("error", pin_result.error().to_string()));
            report.error = "Network pinned map check failed: " + std::string(pin_path);
            return report;
        }
    }

    report.ok = true;
    return report;
}

std::string build_health_json(const HealthReport& report)
{
    std::ostringstream out;
    out << "{" << "\"ok\":" << (report.ok ? "true" : "false") << ",\"capability\":\""
        << json_escape(capability_name(report.capability)) << "\"" << ",\"capability_tier\":\""
        << json_escape(report.capability_tier) << "\"" << ",\"mode\":\""
        << (report.capability == EnforcementCapability::Full
                ? "enforce"
                : (report.capability == EnforcementCapability::AuditOnly ? "audit-only" : "disabled"))
        << "\"" << ",\"engine_mode\":\"" << json_escape(report.engine_mode) << "\"" << ",\"kernel_version\":\""
        << json_escape(report.kernel_version) << "\"" << ",\"features\":{"
        << "\"bpf_lsm\":" << (report.features.bpf_lsm ? "true" : "false")
        << ",\"cgroup_v2\":" << (report.features.cgroup_v2 ? "true" : "false")
        << ",\"btf\":" << (report.features.btf ? "true" : "false")
        << ",\"bpf_syscall\":" << (report.features.bpf_syscall ? "true" : "false")
        << ",\"ringbuf\":" << (report.features.ringbuf ? "true" : "false")
        << ",\"tracepoints\":" << (report.features.tracepoints ? "true" : "false")
        << ",\"bpffs\":" << (report.bpffs_mounted ? "true" : "false") << "}" << ",\"checks\":{"
        << "\"prereqs\":" << (report.prereqs_ok ? "true" : "false")
        << ",\"bpf_load\":" << (report.bpf_load_ok ? "true" : "false")
        << ",\"required_maps\":" << (report.required_maps_ok ? "true" : "false")
        << ",\"layout_version\":" << (report.layout_ok ? "true" : "false")
        << ",\"required_pins\":" << (report.required_pins_ok ? "true" : "false")
        << ",\"network_pins\":" << (report.network_pins_ok ? "true" : "false")
        << ",\"bpf_object\":" << (report.bpf_object_found ? "true" : "false")
        << ",\"bpf_hash_verified\":" << (report.bpf_hash_verified ? "true" : "false") << "}"
        << ",\"bpf_object_path\":\"" << json_escape(report.bpf_object_path) << "\""
        << ",\"bpf_object_found\":" << (report.bpf_object_found ? "true" : "false")
        << ",\"bpf_hash_found\":" << (report.bpf_hash_found ? "true" : "false")
        << ",\"bpf_hash_verified\":" << (report.bpf_hash_verified ? "true" : "false")
        << ",\"allow_unsigned_bpf\":" << (report.bpf_allow_unsigned ? "true" : "false")
        << ",\"network_maps_present\":" << (report.network_maps_present ? "true" : "false");
    if (!report.degradation_reason.empty()) {
        out << ",\"degradation_reason\":\"" << json_escape(report.degradation_reason) << "\"";
    }
    if (!report.error.empty()) {
        out << ",\"error\":\"" << json_escape(report.error) << "\"";
    }
    if (report.bpf_load_ok && report.required_maps_ok) {
        BpfState pressure_state;
        auto pressure_load = load_bpf(true, false, pressure_state);
        if (pressure_load) {
            auto pressure = check_map_pressure(pressure_state);
            out << ",\"map_pressure\":[";
            for (size_t i = 0; i < pressure.maps.size(); ++i) {
                const auto& m = pressure.maps[i];
                if (i > 0) {
                    out << ",";
                }
                out << "{\"name\":\"" << json_escape(m.name) << "\"" << ",\"entries\":" << m.entry_count
                    << ",\"max\":" << m.max_entries << ",\"utilization\":" << std::fixed << std::setprecision(6)
                    << m.utilization << "}";
            }
            out << "]";
        }
    }
    out << "}";
    return out.str();
}

void emit_health_json(const HealthReport& report)
{
    std::cout << build_health_json(report) << '\n';
}

std::vector<DoctorAdvice> build_doctor_advice(const HealthReport& report)
{
    std::vector<DoctorAdvice> advice;
    if (!report.features.bpf_lsm) {
        advice.push_back({"bpf_lsm_disabled", "BPF LSM is not enabled; enforcement will be audit-only.",
                          "Enable BPF LSM via kernel command line (lsm=...,...,bpf) and reboot."});
    }
    if (!report.features.btf) {
        advice.push_back({"missing_btf", "Kernel BTF is missing; verifier compatibility is reduced.",
                          "Use a kernel built with CONFIG_DEBUG_INFO_BTF=y."});
    }
    if (!report.bpffs_mounted) {
        advice.push_back({"bpffs_unmounted", "bpffs is not mounted at /sys/fs/bpf.",
                          "Mount bpffs: sudo mount -t bpf bpffs /sys/fs/bpf."});
    }
    if (report.capability == EnforcementCapability::AuditOnly) {
        advice.push_back({"audit_only", "Enforcement capability is audit-only.",
                          "Ensure BPF LSM is enabled to allow deny enforcement."});
    }
    if (!report.bpf_load_ok) {
        advice.push_back({"bpf_load_failed", "Failed to load BPF programs.",
                          "Check kernel logs and verify libbpf, BTF, and permissions."});
    }
    if (!report.bpf_object_found) {
        advice.push_back({"missing_bpf_object", "BPF object file is missing.",
                          "Build with SKIP_BPF_BUILD=OFF or install /usr/lib/aegisbpf/aegis.bpf.o."});
    }
    if (report.bpf_object_found && !report.bpf_hash_found) {
        advice.push_back({"missing_bpf_hash", "BPF object hash file not found.",
                          "Install /etc/aegisbpf/aegis.bpf.sha256 or /usr/lib/aegisbpf/aegis.bpf.sha256."});
    }
    if (report.bpf_hash_found && !report.bpf_hash_verified) {
        advice.push_back({"bpf_hash_unverified", "BPF object hash could not be verified.",
                          "Verify the BPF object and hash match, or use break-glass only for emergency recovery."});
    }
    if (!report.layout_ok) {
        advice.push_back({"layout_mismatch", "Pinned map layout mismatch detected.",
                          "Run 'sudo aegisbpf block clear' to reset pinned maps."});
    }
    if (report.network_maps_present && !report.network_pins_ok) {
        advice.push_back(
            {"network_pins", "Network pinned map access failed.", "Verify bpffs permissions and pinned network maps."});
    }
    if (report.bpf_load_ok && report.required_maps_ok) {
        BpfState pressure_state;
        auto pressure_load = load_bpf(true, false, pressure_state);
        if (pressure_load) {
            auto pressure = check_map_pressure(pressure_state);
            for (const auto& m : pressure.maps) {
                if (m.utilization >= 1.0) {
                    advice.push_back(
                        {"map_full_" + m.name,
                         "Map '" + m.name + "' is at capacity (" + std::to_string(m.entry_count) + "/" +
                             std::to_string(m.max_entries) + "). New entries will be rejected.",
                         "Increase --max-deny-inodes/--max-deny-paths/--max-network-entries or reduce policy size."});
                } else if (m.utilization >= 0.80) {
                    advice.push_back({"map_pressure_" + m.name,
                                      "Map '" + m.name + "' utilization is " +
                                          std::to_string(static_cast<int>(m.utilization * 100)) + "% (" +
                                          std::to_string(m.entry_count) + "/" + std::to_string(m.max_entries) + ").",
                                      "Consider increasing map capacity before it fills."});
                }
            }
        }
    }
    return advice;
}

void emit_doctor_text(const HealthReport& report, const std::vector<DoctorAdvice>& advice)
{
    std::cout << "AegisBPF Doctor" << '\n';
    std::cout << "status: " << (report.ok ? "ok" : "error") << '\n';
    std::cout << "capability: " << capability_name(report.capability) << '\n';
    std::cout << "engine_mode: " << report.engine_mode << '\n';
    std::cout << "kernel: " << report.kernel_version << '\n';
    std::cout << "checks: prereqs=" << (report.prereqs_ok ? "ok" : "fail")
              << " bpf_load=" << (report.bpf_load_ok ? "ok" : "fail")
              << " required_maps=" << (report.required_maps_ok ? "ok" : "fail")
              << " layout=" << (report.layout_ok ? "ok" : "fail")
              << " required_pins=" << (report.required_pins_ok ? "ok" : "fail")
              << " network_pins=" << (report.network_pins_ok ? "ok" : "fail")
              << " bpf_object=" << (report.bpf_object_found ? "ok" : "fail")
              << " bpf_hash_verified=" << (report.bpf_hash_verified ? "ok" : "fail") << '\n';
    std::cout << "bpf_object_path: " << report.bpf_object_path << '\n';
    if (!report.degradation_reason.empty()) {
        std::cout << "degradation_reason: " << report.degradation_reason << '\n';
    }
    if (!report.error.empty()) {
        std::cout << "error: " << report.error << '\n';
    }
    if (advice.empty()) {
        std::cout << "advice: none" << '\n';
        return;
    }
    std::cout << "advice:" << '\n';
    for (const auto& item : advice) {
        std::cout << "- [" << item.code << "] " << item.message << '\n';
        if (!item.remediation.empty()) {
            std::cout << "  remediation: " << item.remediation << '\n';
        }
    }
}

void emit_doctor_json(const HealthReport& report, const std::vector<DoctorAdvice>& advice)
{
    std::ostringstream out;
    out << "{" << "\"ok\":" << (report.ok ? "true" : "false") << ",\"report\":" << build_health_json(report)
        << ",\"advice\":[";
    for (size_t i = 0; i < advice.size(); ++i) {
        const auto& item = advice[i];
        if (i > 0) {
            out << ",";
        }
        out << "{" << "\"code\":\"" << json_escape(item.code) << "\"" << ",\"message\":\"" << json_escape(item.message)
            << "\"";
        if (!item.remediation.empty()) {
            out << ",\"remediation\":\"" << json_escape(item.remediation) << "\"";
        }
        out << "}";
    }
    out << "]}";
    std::cout << out.str() << '\n';
}

} // namespace

int cmd_health(bool json_output, bool require_enforce)
{
    const std::string trace_id = make_span_id("trace-health");
    ScopedSpan root_span("cli.health", trace_id);
    auto fail = [&](const std::string& error) -> int {
        root_span.fail(error);
        return 1;
    };
    HealthReport report = collect_health_report(trace_id, root_span.span_id());
    const bool enforce_capable = report.capability == EnforcementCapability::Full;
    const bool health_ok = report.ok && (!require_enforce || enforce_capable);

    if (json_output) {
        emit_health_json(report);
        return health_ok ? 0 : 1;
    }

    std::cout << "Kernel version: " << report.kernel_version << '\n';
    std::cout << "Capability: " << capability_name(report.capability) << '\n';
    std::cout << "Engine mode: " << report.engine_mode << '\n';
    std::cout << "BPF object: " << report.bpf_object_path << " (" << (report.bpf_object_found ? "found" : "missing")
              << ")" << '\n';
    std::cout << "BPF hash verified: " << (report.bpf_hash_verified ? "yes" : "no") << '\n';
    if (!report.degradation_reason.empty()) {
        std::cout << "Degradation reason: " << report.degradation_reason << '\n';
    }
    std::cout << "Features:" << '\n';
    std::cout << "  bpf_lsm: " << (report.features.bpf_lsm ? "yes" : "no") << '\n';
    std::cout << "  cgroup_v2: " << (report.features.cgroup_v2 ? "yes" : "no") << '\n';
    std::cout << "  btf: " << (report.features.btf ? "yes" : "no") << '\n';
    std::cout << "  bpf_syscall: " << (report.features.bpf_syscall ? "yes" : "no") << '\n';
    std::cout << "  ringbuf: " << (report.features.ringbuf ? "yes" : "no") << '\n';
    std::cout << "  tracepoints: " << (report.features.tracepoints ? "yes" : "no") << '\n';
    std::cout << "  bpffs: " << (report.bpffs_mounted ? "yes" : "no") << '\n';

    if (!report.ok) {
        return fail(report.error.empty() ? "Health check failed" : report.error);
    }

    if (require_enforce && !enforce_capable) {
        std::cout << "Health check failed (enforce capability required)" << '\n';
        std::cout << "  Reason: current node is not enforce-capable (audit-only)." << '\n';
        return fail("Enforce capability required");
    }

    if (report.capability == EnforcementCapability::AuditOnly) {
        std::cout << "Health check passed (audit-only capability)" << '\n';
        std::cout << "  Note: BPF LSM is unavailable; enforcement actions run in audit mode." << '\n';
        return 0;
    }

    std::cout << "Health check passed" << '\n';
    return 0;
}

int cmd_doctor(bool json_output)
{
    const std::string trace_id = make_span_id("trace-doctor");
    ScopedSpan root_span("cli.doctor", trace_id);

    HealthReport report = collect_health_report(trace_id, root_span.span_id());
    auto advice = build_doctor_advice(report);

    if (!report.ok && !report.error.empty()) {
        root_span.fail(report.error);
    }

    if (json_output) {
        emit_doctor_json(report, advice);
        return report.ok ? 0 : 1;
    }

    emit_doctor_text(report, advice);
    return report.ok ? 0 : 1;
}

} // namespace aegis
