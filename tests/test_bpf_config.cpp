// Unit tests for the pure agent-config merge policy used by set_agent_config_full.
//
// Regression guard for the daemon-startup deny-flag reset bug: at startup the
// daemon writes a freshly-zeroed AgentConfig, and the shipped systemd unit runs
// `policy apply` (ExecStartPre) in a *separate* process before `run` attaches.
// If the full-config write does not preserve the policy-apply-owned fields, the
// daemon silently wipes the applied deny flags and resets the expected policy
// generation, which the in-BPF generation gate then treats as a mismatch and
// downgrades enforcement to AUDIT.

#include <gtest/gtest.h>

#include "bpf_config.hpp"
#include "types.hpp"

using namespace aegis;

namespace {

// An AgentConfig as written by a prior `policy apply`: deny flags set, a
// non-zero committed generation, plus some preserved runtime state.
AgentConfig applied_config()
{
    AgentConfig cfg{};
    cfg.deny_ptrace = 1;
    cfg.deny_module_load = 1;
    cfg.deny_bpf = 1;
    cfg.policy_generation = 7;
    cfg.emergency_disable = 1;
    cfg.exec_identity_flags = 0x3;
    cfg.audit_only = 0;
    return cfg;
}

// An AgentConfig as built by daemon startup: deny flags and generation are zero,
// only mode/runtime fields are populated.
AgentConfig daemon_startup_config()
{
    AgentConfig cfg{};
    cfg.audit_only = 0;
    cfg.enforce_signal = 15;
    cfg.event_sample_rate = 1;
    cfg.deadman_enabled = 1;
    cfg.deadman_ttl_seconds = 60;
    // deny_* and policy_generation intentionally left zero
    return cfg;
}

} // namespace

TEST(BpfConfigMerge, PreservesDenyFlagsFromExistingConfig)
{
    AgentConfig merged = merge_preserving_policy_apply_fields(applied_config(), daemon_startup_config());

    EXPECT_EQ(merged.deny_ptrace, 1);
    EXPECT_EQ(merged.deny_module_load, 1);
    EXPECT_EQ(merged.deny_bpf, 1);
}

TEST(BpfConfigMerge, PreservesPolicyGenerationFromExistingConfig)
{
    AgentConfig merged = merge_preserving_policy_apply_fields(applied_config(), daemon_startup_config());

    EXPECT_EQ(merged.policy_generation, 7u);
}

TEST(BpfConfigMerge, PreservesEmergencyDisableAndExecIdentityFlags)
{
    AgentConfig merged = merge_preserving_policy_apply_fields(applied_config(), daemon_startup_config());

    EXPECT_EQ(merged.emergency_disable, 1);
    EXPECT_EQ(merged.exec_identity_flags, 0x3);
}

TEST(BpfConfigMerge, TakesModeAndRuntimeFieldsFromIncomingConfig)
{
    AgentConfig existing = applied_config();
    existing.enforce_signal = 9;     // stale value that must not leak through
    existing.event_sample_rate = 99; // stale value that must not leak through

    AgentConfig incoming = daemon_startup_config();
    incoming.audit_only = 1;

    AgentConfig merged = merge_preserving_policy_apply_fields(existing, incoming);

    EXPECT_EQ(merged.audit_only, 1);
    EXPECT_EQ(merged.enforce_signal, 15);
    EXPECT_EQ(merged.event_sample_rate, 1u);
    EXPECT_EQ(merged.deadman_enabled, 1);
    EXPECT_EQ(merged.deadman_ttl_seconds, 60u);
}

TEST(BpfConfigMerge, NeverLowersAnAppliedPolicyToZero)
{
    // The core invariant: an incoming all-zero deny/generation config (daemon
    // startup) must not clear an already-applied policy.
    AgentConfig existing = applied_config();
    AgentConfig incoming{}; // fully zeroed

    AgentConfig merged = merge_preserving_policy_apply_fields(existing, incoming);

    EXPECT_EQ(merged.deny_module_load, 1);
    EXPECT_EQ(merged.deny_ptrace, 1);
    EXPECT_EQ(merged.deny_bpf, 1);
    EXPECT_EQ(merged.policy_generation, 7u);
}
