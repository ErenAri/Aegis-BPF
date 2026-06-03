// Unit tests for the Tier-3 signal-fallback gate-promotion predicate and the
// No-Pretend invariant it must preserve.
#include <gtest/gtest.h>

#include "daemon_runtime.hpp"
#include "posture_gate.hpp"

using aegis::signal_fallback_enforce_eligible;

namespace {

// Eligible only when ALL hold: capability is audit-only (no BPF-LSM), enforce
// was requested, operator opted into signal-fallback, and the kernel can deliver
// the signal (tracepoints + bpf syscall).
TEST(PostureGate, EligibleWhenOptedInOnNoLsmSignalCapableHost)
{
    EXPECT_TRUE(signal_fallback_enforce_eligible(true, true, true, true, true));
}

TEST(PostureGate, NotEligibleWithoutOptIn)
{
    EXPECT_FALSE(signal_fallback_enforce_eligible(true, true, /*opt_in=*/false, true, true));
}

TEST(PostureGate, NotEligibleInAuditMode)
{
    EXPECT_FALSE(signal_fallback_enforce_eligible(true, /*enforce_requested=*/false, true, true, true));
}

TEST(PostureGate, NotEligibleWithoutSignalCapability)
{
    EXPECT_FALSE(signal_fallback_enforce_eligible(true, true, true, /*tracepoints=*/false, true));
    EXPECT_FALSE(signal_fallback_enforce_eligible(true, true, true, true, /*bpf_syscall=*/false));
}

// No-Pretend cornerstone: the predicate can NEVER fire on a full-enforcement
// (BPF-LSM-capable) host. capability_audit_only is false there, so promotion
// only ever happens where synchronous ENFORCE is genuinely impossible.
TEST(PostureGate, NeverEligibleOnFullEnforcementHost)
{
    for (int er = 0; er <= 1; ++er)
        for (int oi = 0; oi <= 1; ++oi)
            for (int tp = 0; tp <= 1; ++tp)
                for (int bs = 0; bs <= 1; ++bs)
                    EXPECT_FALSE(signal_fallback_enforce_eligible(
                        /*capability_audit_only=*/false, er, oi, tp, bs));
}

// The promoted posture is a distinct, honest state — not ENFORCE.
TEST(PostureGate, EnforceSignalIsADistinctStateName)
{
    EXPECT_STREQ(aegis::runtime_state_name(aegis::RuntimeState::EnforceSignal), "ENFORCE_SIGNAL");
    EXPECT_STRNE(aegis::runtime_state_name(aegis::RuntimeState::EnforceSignal),
                 aegis::runtime_state_name(aegis::RuntimeState::Enforce));
}

} // namespace
