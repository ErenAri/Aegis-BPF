// cppcheck-suppress-file missingIncludeSystem
#pragma once

namespace aegis {

// Tier-3 gate promotion predicate (see docs/GUARANTEES.md "Signal-fallback").
//
// When the kernel cannot do synchronous BPF-LSM enforcement, the daemon would
// normally degrade to audit-only (or fail-closed). If the operator has opted
// into signal-fallback AND the kernel can actually deliver it (tracepoints +
// bpf syscall, which bpf_send_signal needs), we instead run in the honest,
// strictly-weaker ENFORCE_SIGNAL posture: asynchronous kill on a denied
// syscall, NOT synchronous -EPERM.
//
// This is a pure predicate so the No-Pretend invariant is unit-testable: it can
// only return true when the kernel is audit-only-capable (i.e. no BPF-LSM), so
// the promoted posture NEVER coincides with a claim of full ENFORCE.
inline bool signal_fallback_enforce_eligible(bool capability_audit_only, bool enforce_requested,
                                             bool enforce_fallback_signal, bool tracepoints, bool bpf_syscall)
{
    return capability_audit_only && enforce_requested && enforce_fallback_signal && tracepoints && bpf_syscall;
}

} // namespace aegis
