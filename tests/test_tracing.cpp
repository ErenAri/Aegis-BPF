// cppcheck-suppress-file missingIncludeSystem
#include <gtest/gtest.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "bpf_ops.hpp"
#include "daemon.hpp"
#include "daemon_test_hooks.hpp"
#include "logging.hpp"
#include "tracing.hpp"

namespace {

class TracingEnvGuard {
  public:
    explicit TracingEnvGuard(const char* value)
    {
        const char* current = std::getenv("AEGIS_OTEL_SPANS");
        if (current != nullptr) {
            had_previous_ = true;
            previous_ = current;
        }
        if (value != nullptr) {
            setenv("AEGIS_OTEL_SPANS", value, 1);
        } else {
            unsetenv("AEGIS_OTEL_SPANS");
        }
    }

    ~TracingEnvGuard()
    {
        if (had_previous_) {
            setenv("AEGIS_OTEL_SPANS", previous_.c_str(), 1);
        } else {
            unsetenv("AEGIS_OTEL_SPANS");
        }
    }

  private:
    bool had_previous_{false};
    std::string previous_;
};

class ScopedEnvVar {
  public:
    ScopedEnvVar(const char* key, const std::string& value) : key_(key)
    {
        const char* current = std::getenv(key_);
        if (current != nullptr) {
            had_previous_ = true;
            previous_ = current;
        }
        setenv(key_, value.c_str(), 1);
    }

    ~ScopedEnvVar()
    {
        if (had_previous_) {
            setenv(key_, previous_.c_str(), 1);
        } else {
            unsetenv(key_);
        }
    }

  private:
    const char* key_;
    bool had_previous_{false};
    std::string previous_;
};

std::string make_temp_file_path(const std::string& prefix, const std::string& suffix)
{
    std::filesystem::path base = std::filesystem::temp_directory_path();
    return (base / (prefix + "_" + std::to_string(getpid()) + "_" + std::to_string(std::rand()) + suffix)).string();
}

} // namespace

namespace aegis {

namespace {

class DaemonHookGuard {
  public:
    DaemonHookGuard(ValidateConfigDirectoryPermissionsFn config_fn, DetectKernelFeaturesFn detect_fn,
                    BumpMemlockRlimitFn memlock_fn = nullptr, LoadBpfFn load_fn = nullptr,
                    EnsureLayoutVersionFn ensure_layout_fn = nullptr, SetAgentConfigFullFn set_config_fn = nullptr,
                    PopulateSurvivalAllowlistFn populate_survival_fn = nullptr,
                    SetupAgentCgroupFn setup_cgroup_fn = nullptr, AttachAllFn attach_all_fn = nullptr)
    {
        set_validate_config_directory_permissions_for_test(config_fn);
        set_detect_kernel_features_for_test(detect_fn);
        set_bump_memlock_rlimit_for_test(memlock_fn);
        set_load_bpf_for_test(load_fn);
        set_ensure_layout_version_for_test(ensure_layout_fn);
        set_set_agent_config_full_for_test(set_config_fn);
        set_populate_survival_allowlist_for_test(populate_survival_fn);
        set_setup_agent_cgroup_for_test(setup_cgroup_fn);
        set_attach_all_for_test(attach_all_fn);
    }

    ~DaemonHookGuard()
    {
        reset_validate_config_directory_permissions_for_test();
        reset_detect_kernel_features_for_test();
        reset_bump_memlock_rlimit_for_test();
        reset_load_bpf_for_test();
        reset_ensure_layout_version_for_test();
        reset_set_agent_config_full_for_test();
        reset_populate_survival_allowlist_for_test();
        reset_setup_agent_cgroup_for_test();
        reset_attach_all_for_test();
    }
};

class BreakGlassHookGuard {
  public:
    explicit BreakGlassHookGuard(DetectBreakGlassFn fn) { set_detect_break_glass_for_test(fn); }

    ~BreakGlassHookGuard() { reset_detect_break_glass_for_test(); }
};

Result<void> test_config_ok(const std::string&)
{
    return {};
}

Result<void> test_config_fail(const std::string&)
{
    return Error(ErrorCode::PermissionDenied, "forced config validation failure");
}

Result<KernelFeatures> test_detect_fail()
{
    return Error(ErrorCode::Unknown, "forced feature detection failure");
}

Result<KernelFeatures> test_detect_full()
{
    KernelFeatures features{};
    features.bpf_lsm = true;
    features.ringbuf = true;
    features.cgroup_v2 = true;
    features.btf = true;
    features.bpf_syscall = true;
    features.tracepoints = true;
    features.kernel_version = "6.6.0";
    features.kernel_major = 6;
    features.kernel_minor = 6;
    features.kernel_patch = 0;
    return features;
}

Result<KernelFeatures> test_detect_audit_only()
{
    KernelFeatures features{};
    features.bpf_lsm = false;
    features.ringbuf = true;
    features.cgroup_v2 = true;
    features.btf = true;
    features.bpf_syscall = true;
    features.tracepoints = true;
    features.kernel_version = "6.6.0";
    features.kernel_major = 6;
    features.kernel_minor = 6;
    features.kernel_patch = 0;
    return features;
}

bool test_break_glass_true()
{
    return true;
}

Result<void> test_memlock_ok()
{
    return {};
}

Result<void> test_load_bpf_fail(bool, bool, BpfState&)
{
    return Error(ErrorCode::BpfLoadFailed, "forced load_bpf failure");
}

Result<void> test_load_bpf_verifier_fail(bool, bool, BpfState&)
{
    return Error(ErrorCode::BpfLoadFailed, "BPF verifier rejected test program");
}

Result<void> test_load_bpf_ok(bool, bool, BpfState&)
{
    return {};
}

Result<void> test_ensure_layout_ok(BpfState&)
{
    return {};
}

Result<void> test_set_agent_config_ok(BpfState&, const AgentConfig&)
{
    return {};
}

Result<void> test_populate_survival_ok(BpfState&)
{
    return {};
}

Result<void> test_setup_agent_cgroup_ok(BpfState&)
{
    return {};
}

Result<void> test_attach_all_fail(BpfState&, bool, bool, bool, bool)
{
    return Error(ErrorCode::BpfAttachFailed, "forced attach_all failure");
}

Result<void> test_attach_all_partial_contract(BpfState& state, bool lsm_enabled, bool, bool, bool)
{
    state.attach_contract_valid = true;
    state.file_hooks_expected = lsm_enabled ? 2 : 1;
    state.file_hooks_attached = 1;
    return {};
}

Result<void> test_attach_all_full_contract_no_network_hooks(BpfState& state, bool lsm_enabled,
                                                            bool use_inode_permission, bool use_file_open, bool)
{
    state.attach_contract_valid = true;
    if (lsm_enabled) {
        uint8_t expected = 0;
        if (use_inode_permission) {
            ++expected;
        }
        if (use_file_open) {
            ++expected;
        }
        state.file_hooks_expected = expected;
        state.file_hooks_attached = expected;
    } else {
        state.file_hooks_expected = 1;
        state.file_hooks_attached = 1;
    }
    state.socket_connect_hook_attached = false;
    state.socket_bind_hook_attached = false;
    state.exec_identity_hook_attached = false;
    return {};
}

Result<void> test_attach_all_full_contract_with_network_hooks(BpfState& state, bool lsm_enabled,
                                                              bool use_inode_permission, bool use_file_open, bool)
{
    state.attach_contract_valid = true;
    if (lsm_enabled) {
        uint8_t expected = 0;
        if (use_inode_permission) {
            ++expected;
        }
        if (use_file_open) {
            ++expected;
        }
        state.file_hooks_expected = expected;
        state.file_hooks_attached = expected;
    } else {
        state.file_hooks_expected = 1;
        state.file_hooks_attached = 1;
    }
    state.socket_connect_hook_attached = true;
    state.socket_bind_hook_attached = true;
    state.exec_identity_hook_attached = false;
    return {};
}

} // namespace

TEST(TracingTest, MakeSpanIdUsesPrefix)
{
    std::string id = make_span_id("trace-policy");
    EXPECT_EQ(id.rfind("trace-policy-", 0), 0u);
}

TEST(TracingTest, ScopedSpanLogsStartAndEndWhenEnabled)
{
    TracingEnvGuard env("1");
    std::ostringstream output;

    logger().set_output(&output);
    logger().set_json_format(true);
    {
        ScopedSpan span("policy.apply", "trace-id-1");
    }
    logger().set_output(&std::cerr);
    logger().set_json_format(false);

    std::string log = output.str();
    EXPECT_NE(log.find("\"message\":\"otel_span_start\""), std::string::npos);
    EXPECT_NE(log.find("\"message\":\"otel_span_end\""), std::string::npos);
    EXPECT_NE(log.find("\"span_name\":\"policy.apply\""), std::string::npos);
    EXPECT_NE(log.find("\"trace_id\":\"trace-id-1\""), std::string::npos);
    EXPECT_NE(log.find("\"status\":\"ok\""), std::string::npos);
}

TEST(TracingTest, ScopedSpanLogsErrorStatusWhenMarkedFailed)
{
    TracingEnvGuard env("true");
    std::ostringstream output;

    logger().set_output(&output);
    logger().set_json_format(true);
    {
        ScopedSpan span("policy.integrity_check", "trace-id-2");
        span.fail("hash mismatch");
    }
    logger().set_output(&std::cerr);
    logger().set_json_format(false);

    std::string log = output.str();
    EXPECT_NE(log.find("\"status\":\"error\""), std::string::npos);
    EXPECT_NE(log.find("\"error\":\"hash mismatch\""), std::string::npos);
}

TEST(TracingTest, ScopedSpanRestoresThreadLocalContext)
{
    TracingEnvGuard env(nullptr);

    EXPECT_TRUE(current_trace_id().empty());
    EXPECT_TRUE(current_span_id().empty());

    std::string root_span_id;
    {
        ScopedSpan root("daemon.run", "trace-id-ctx");
        root_span_id = root.span_id();
        EXPECT_EQ(current_trace_id(), "trace-id-ctx");
        EXPECT_EQ(current_span_id(), root_span_id);

        {
            ScopedSpan child("daemon.load_bpf", current_trace_id(), current_span_id());
            EXPECT_EQ(current_trace_id(), "trace-id-ctx");
            EXPECT_EQ(current_span_id(), child.span_id());
        }

        EXPECT_EQ(current_trace_id(), "trace-id-ctx");
        EXPECT_EQ(current_span_id(), root_span_id);
    }

    EXPECT_TRUE(current_trace_id().empty());
    EXPECT_TRUE(current_span_id().empty());
}

TEST(TracingTest, NestedSpanLogsParentSpanId)
{
    TracingEnvGuard env("1");
    std::ostringstream output;

    logger().set_output(&output);
    logger().set_json_format(true);
    std::string root_id;
    {
        ScopedSpan root("daemon.run", "trace-id-parent");
        root_id = root.span_id();
        ScopedSpan child("daemon.load_bpf", "trace-id-parent", root_id);
    }
    logger().set_output(&std::cerr);
    logger().set_json_format(false);

    std::string log = output.str();
    EXPECT_NE(log.find("\"span_name\":\"daemon.load_bpf\""), std::string::npos);
    EXPECT_NE(log.find("\"parent_span_id\":\"" + root_id + "\""), std::string::npos);
}

TEST(TracingTest, DaemonRunGuardsSigkillBehindBuildAndRuntimeFlags)
{
    TracingEnvGuard env("1");
    std::ostringstream output;
    logger().set_output(&output);
    logger().set_json_format(true);
    {
        int rc = daemon_run(false, false, 0, kEnforceSignalKill, false, LsmHookMode::FileOpen, 0, 1,
                            kSigkillEscalationThresholdDefault, kSigkillEscalationWindowSecondsDefault);
        EXPECT_EQ(rc, 1);
    }
    logger().set_output(&std::cerr);
    logger().set_json_format(false);

    const std::string log = output.str();
#if AEGIS_ENABLE_SIGKILL_ENFORCEMENT
    EXPECT_NE(log.find("--allow-sigkill"), std::string::npos);
#else
    EXPECT_NE(log.find("SIGKILL enforcement is disabled in this build"), std::string::npos);
#endif
}

TEST(TracingTest, DaemonRunForcesAuditOnlyWhenBreakGlassActive)
{
    TracingEnvGuard env("1");
    std::ostringstream output;
    logger().set_output(&output);
    logger().set_json_format(true);
    {
        BreakGlassHookGuard break_glass(test_break_glass_true);
        DaemonHookGuard hooks(test_config_ok, test_detect_full, test_memlock_ok, test_load_bpf_fail);
        int rc = daemon_run(false, false, 0, kEnforceSignalTerm, false, LsmHookMode::FileOpen, 0, 1,
                            kSigkillEscalationThresholdDefault, kSigkillEscalationWindowSecondsDefault);
        EXPECT_EQ(rc, 1);
    }
    logger().set_output(&std::cerr);
    logger().set_json_format(false);

    const std::string log = output.str();
    EXPECT_NE(log.find("Break-glass mode detected - forcing audit-only mode"), std::string::npos);
}

TEST(TracingTest, DaemonRunMarksRootSpanErrorWhenConfigValidationFails)
{
    TracingEnvGuard env("1");
    std::ostringstream output;
    logger().set_output(&output);
    logger().set_json_format(true);
    {
        DaemonHookGuard hooks(test_config_fail, test_detect_fail);
        int rc = daemon_run(false, false, 0, kEnforceSignalTerm, false, LsmHookMode::FileOpen, 0, 1,
                            kSigkillEscalationThresholdDefault, kSigkillEscalationWindowSecondsDefault);
        EXPECT_EQ(rc, 1);
    }
    logger().set_output(&std::cerr);
    logger().set_json_format(false);

    const std::string log = output.str();
    EXPECT_NE(log.find("\"span_name\":\"daemon.run\""), std::string::npos);
    EXPECT_NE(log.find("\"span_name\":\"daemon.validate_config_dir\""), std::string::npos);
    EXPECT_NE(log.find("\"status\":\"error\""), std::string::npos);
    EXPECT_NE(log.find("\"parent_span_id\":\"span-"), std::string::npos);
    EXPECT_NE(log.find("forced config validation failure"), std::string::npos);
}

TEST(TracingTest, DaemonRunMarksRootSpanErrorWhenFeatureDetectionFails)
{
    TracingEnvGuard env("1");
    std::ostringstream output;
    logger().set_output(&output);
    logger().set_json_format(true);
    {
        DaemonHookGuard hooks(test_config_ok, test_detect_fail);
        int rc = daemon_run(false, false, 0, kEnforceSignalTerm, false, LsmHookMode::FileOpen, 0, 1,
                            kSigkillEscalationThresholdDefault, kSigkillEscalationWindowSecondsDefault);
        EXPECT_EQ(rc, 1);
    }
    logger().set_output(&std::cerr);
    logger().set_json_format(false);

    const std::string log = output.str();
    EXPECT_NE(log.find("\"span_name\":\"daemon.run\""), std::string::npos);
    EXPECT_NE(log.find("\"span_name\":\"daemon.detect_kernel_features\""), std::string::npos);
    EXPECT_NE(log.find("\"span_name\":\"daemon.validate_config_dir\""), std::string::npos);
    EXPECT_NE(log.find("\"status\":\"error\""), std::string::npos);
    EXPECT_NE(log.find("\"parent_span_id\":\"span-"), std::string::npos);
    EXPECT_NE(log.find("forced feature detection failure"), std::string::npos);
}

TEST(TracingTest, DaemonRunMarksLoadSpanErrorWhenLoadBpfFails)
{
    TracingEnvGuard env("1");
    std::ostringstream output;
    logger().set_output(&output);
    logger().set_json_format(true);
    {
        DaemonHookGuard hooks(test_config_ok, test_detect_full, test_memlock_ok, test_load_bpf_fail);
        int rc = daemon_run(false, false, 0, kEnforceSignalTerm, false, LsmHookMode::FileOpen, 0, 1,
                            kSigkillEscalationThresholdDefault, kSigkillEscalationWindowSecondsDefault);
        EXPECT_EQ(rc, 1);
    }
    logger().set_output(&std::cerr);
    logger().set_json_format(false);

    const std::string log = output.str();
    EXPECT_NE(log.find("\"span_name\":\"daemon.detect_kernel_features\""), std::string::npos);
    EXPECT_NE(log.find("\"span_name\":\"daemon.load_bpf\""), std::string::npos);
    EXPECT_NE(log.find("\"span_name\":\"daemon.run\""), std::string::npos);
    EXPECT_NE(log.find("\"status\":\"error\""), std::string::npos);
    EXPECT_NE(log.find("forced load_bpf failure"), std::string::npos);
}

TEST(TracingTest, DaemonRunSurfacesVerifierRejectError)
{
    TracingEnvGuard env("1");
    std::ostringstream output;
    logger().set_output(&output);
    logger().set_json_format(true);
    {
        DaemonHookGuard hooks(test_config_ok, test_detect_full, test_memlock_ok, test_load_bpf_verifier_fail);
        int rc = daemon_run(false, false, 0, kEnforceSignalTerm, false, LsmHookMode::FileOpen, 0, 1,
                            kSigkillEscalationThresholdDefault, kSigkillEscalationWindowSecondsDefault);
        EXPECT_EQ(rc, 1);
    }
    logger().set_output(&std::cerr);
    logger().set_json_format(false);

    const std::string log = output.str();
    EXPECT_NE(log.find("\"span_name\":\"daemon.load_bpf\""), std::string::npos);
    EXPECT_NE(log.find("\"status\":\"error\""), std::string::npos);
    EXPECT_NE(log.find("BPF verifier rejected test program"), std::string::npos);
    EXPECT_NE(log.find("AEGIS_STATE_CHANGE"), std::string::npos);
    EXPECT_NE(log.find("BPF_VERIFIER_REJECT"), std::string::npos);
}

TEST(TracingTest, DaemonRunStrictDegradeFailsWhenEnforceFallsBack)
{
    TracingEnvGuard env("1");
    std::ostringstream output;
    logger().set_output(&output);
    logger().set_json_format(true);
    {
        DaemonHookGuard hooks(test_config_ok, test_detect_audit_only);
        int rc = daemon_run(false, false, 0, kEnforceSignalTerm, false, LsmHookMode::FileOpen, 0, 1,
                            kSigkillEscalationThresholdDefault, kSigkillEscalationWindowSecondsDefault, 0, 3, false,
                            false, true);
        EXPECT_EQ(rc, 1);
    }
    logger().set_output(&std::cerr);
    logger().set_json_format(false);

    const std::string log = output.str();
    EXPECT_NE(log.find("CAPABILITY_AUDIT_ONLY"), std::string::npos);
    EXPECT_NE(log.find("Strict degrade mode triggered failure"), std::string::npos);
}

TEST(TracingTest, DaemonRunMarksAttachSpanErrorWhenAttachAllFails)
{
    TracingEnvGuard env("1");
    std::ostringstream output;
    logger().set_output(&output);
    logger().set_json_format(true);
    {
        DaemonHookGuard hooks(test_config_ok, test_detect_full, test_memlock_ok, test_load_bpf_ok,
                              test_ensure_layout_ok, test_set_agent_config_ok, test_populate_survival_ok,
                              test_setup_agent_cgroup_ok, test_attach_all_fail);
        int rc = daemon_run(false, false, 0, kEnforceSignalTerm, false, LsmHookMode::FileOpen, 0, 1,
                            kSigkillEscalationThresholdDefault, kSigkillEscalationWindowSecondsDefault);
        EXPECT_EQ(rc, 1);
    }
    logger().set_output(&std::cerr);
    logger().set_json_format(false);

    const std::string log = output.str();
    EXPECT_NE(log.find("\"span_name\":\"daemon.attach_programs\""), std::string::npos);
    EXPECT_NE(log.find("\"span_name\":\"daemon.run\""), std::string::npos);
    EXPECT_NE(log.find("\"status\":\"error\""), std::string::npos);
    EXPECT_NE(log.find("forced attach_all failure"), std::string::npos);
}

TEST(TracingTest, DaemonRunRejectsSilentPartialAttachContract)
{
    TracingEnvGuard env("1");
    std::ostringstream output;
    logger().set_output(&output);
    logger().set_json_format(true);
    {
        DaemonHookGuard hooks(test_config_ok, test_detect_full, test_memlock_ok, test_load_bpf_ok,
                              test_ensure_layout_ok, test_set_agent_config_ok, test_populate_survival_ok,
                              test_setup_agent_cgroup_ok, test_attach_all_partial_contract);
        int rc = daemon_run(false, false, 0, kEnforceSignalTerm, false, LsmHookMode::Both, 0, 1,
                            kSigkillEscalationThresholdDefault, kSigkillEscalationWindowSecondsDefault);
        EXPECT_EQ(rc, 1);
    }
    logger().set_output(&std::cerr);
    logger().set_json_format(false);

    const std::string log = output.str();
    EXPECT_NE(log.find("\"span_name\":\"daemon.attach_programs\""), std::string::npos);
    EXPECT_NE(log.find("\"status\":\"error\""), std::string::npos);
    EXPECT_NE(log.find("Attach contract validation failed"), std::string::npos);
    EXPECT_NE(log.find("hooks_expected"), std::string::npos);
    EXPECT_NE(log.find("hooks_attached"), std::string::npos);
}

TEST(TracingTest, DaemonRunFailsClosedWhenNetworkPolicyHooksMissing)
{
    TracingEnvGuard env("1");
    std::ostringstream output;
    logger().set_output(&output);
    logger().set_json_format(true);

    const std::string policy_path = make_temp_file_path("aegis_policy", ".conf");
    {
        std::ofstream policy(policy_path);
        ASSERT_TRUE(policy.is_open());
        policy << "version=2\n\n[deny_cidr]\n10.0.0.0/8\n";
    }
    const std::string capabilities_path = make_temp_file_path("aegis_caps", ".json");

    {
        ScopedEnvVar policy_env("AEGIS_POLICY_APPLIED_PATH", policy_path);
        ScopedEnvVar report_env("AEGIS_CAPABILITIES_REPORT_PATH", capabilities_path);
        DaemonHookGuard hooks(test_config_ok, test_detect_full, test_memlock_ok, test_load_bpf_ok,
                              test_ensure_layout_ok, test_set_agent_config_ok, test_populate_survival_ok,
                              test_setup_agent_cgroup_ok, test_attach_all_full_contract_no_network_hooks);
        int rc = daemon_run(false, false, 0, kEnforceSignalTerm, false, LsmHookMode::FileOpen, 0, 1,
                            kSigkillEscalationThresholdDefault, kSigkillEscalationWindowSecondsDefault);
        EXPECT_EQ(rc, 1);
    }

    logger().set_output(&std::cerr);
    logger().set_json_format(false);

    const std::string log = output.str();
    EXPECT_NE(log.find("Network policy requires unavailable kernel hooks"), std::string::npos);

    std::error_code ec;
    std::filesystem::remove(policy_path, ec);
    std::filesystem::remove(capabilities_path, ec);
}

TEST(TracingTest, DaemonRunFailsClosedWhenImaAppraisalRequiredButUnavailable)
{
    TracingEnvGuard env("1");
    std::ostringstream output;
    logger().set_output(&output);
    logger().set_json_format(true);

    const std::string policy_path = make_temp_file_path("aegis_policy", ".conf");
    {
        std::ofstream policy(policy_path);
        ASSERT_TRUE(policy.is_open());
        policy << "version=5\n\n[protect_connect]\n\n[require_ima_appraisal]\n";
    }

    {
        ScopedEnvVar policy_env("AEGIS_POLICY_APPLIED_PATH", policy_path);
        DaemonHookGuard hooks(test_config_ok, test_detect_full, test_memlock_ok, test_load_bpf_ok,
                              test_ensure_layout_ok, test_set_agent_config_ok, test_populate_survival_ok,
                              test_setup_agent_cgroup_ok, test_attach_all_full_contract_with_network_hooks);
        int rc = daemon_run(false, false, 0, kEnforceSignalTerm, false, LsmHookMode::FileOpen, 0, 1,
                            kSigkillEscalationThresholdDefault, kSigkillEscalationWindowSecondsDefault);
        EXPECT_EQ(rc, 1);
    }

    logger().set_output(&std::cerr);
    logger().set_json_format(false);

    const std::string log = output.str();
    EXPECT_NE(log.find("IMA_APPRAISAL_UNAVAILABLE"), std::string::npos);
    EXPECT_NE(log.find("Policy requires IMA appraisal"), std::string::npos);

    std::error_code ec;
    std::filesystem::remove(policy_path, ec);
}

TEST(TracingTest, DaemonRunWritesCapabilityReportArtifact)
{
    TracingEnvGuard env("1");
    const std::string capabilities_path = make_temp_file_path("aegis_caps", ".json");

    {
        ScopedEnvVar report_env("AEGIS_CAPABILITIES_REPORT_PATH", capabilities_path);
        DaemonHookGuard hooks(test_config_ok, test_detect_full, test_memlock_ok, test_load_bpf_ok,
                              test_ensure_layout_ok, test_set_agent_config_ok, test_populate_survival_ok,
                              test_setup_agent_cgroup_ok, test_attach_all_full_contract_no_network_hooks);
        int rc = daemon_run(true, false, 0, kEnforceSignalTerm, false, LsmHookMode::FileOpen, 0, 1,
                            kSigkillEscalationThresholdDefault, kSigkillEscalationWindowSecondsDefault);
        EXPECT_EQ(rc, 1);
    }

    std::ifstream report(capabilities_path);
    ASSERT_TRUE(report.is_open());
    std::stringstream buffer;
    buffer << report.rdbuf();
    const std::string payload = buffer.str();
    EXPECT_NE(payload.find("\"schema_version\": 1"), std::string::npos);
    EXPECT_NE(payload.find("\"schema_semver\": \"1.2.0\""), std::string::npos);
    EXPECT_NE(payload.find("\"features\""), std::string::npos);
    EXPECT_NE(payload.find("\"ima\""), std::string::npos);
    EXPECT_NE(payload.find("\"ima_appraisal\""), std::string::npos);
    EXPECT_NE(payload.find("\"hooks\""), std::string::npos);
    EXPECT_NE(payload.find("\"requirements\""), std::string::npos);
    EXPECT_NE(payload.find("\"ima_appraisal_required\""), std::string::npos);
    EXPECT_NE(payload.find("\"require_ima_appraisal\""), std::string::npos);
    EXPECT_NE(payload.find("\"requirements_met\""), std::string::npos);
    EXPECT_NE(payload.find("\"runtime_state\": \"AUDIT_FALLBACK\""), std::string::npos);
    EXPECT_NE(payload.find("\"state_transitions\""), std::string::npos);
    EXPECT_NE(payload.find("\"strict_mode\": false"), std::string::npos);
    EXPECT_NE(payload.find("\"enforce_requested\": false"), std::string::npos);

    std::error_code ec;
    std::filesystem::remove(capabilities_path, ec);
}

} // namespace aegis
