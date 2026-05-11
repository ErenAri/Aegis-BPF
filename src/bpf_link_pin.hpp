// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstddef>
#include <string>

#include "result.hpp"

struct bpf_link;

namespace aegis {

class BpfState;
struct PinnedHook; // defined in bpf_ops.hpp alongside BpfState

/// Default root directory under bpffs where AegisBPF pins LSM links.
/// Kept stable so `aegisbpfd` restarts can detect stale pins from a
/// previously-crashed daemon.
constexpr const char* kDefaultPinRoot = "/sys/fs/bpf/aegisbpf";

/// Returns true iff `path` is on a mounted `bpf` filesystem (probed via
/// `statfs(2)` against `BPF_FS_MAGIC`). When `--enforce-pin-links` is set
/// and this returns false, the daemon refuses to start.
[[nodiscard]] bool is_bpffs_mounted(const std::string& path);

/// Ensure `dir` exists with mode 0700. Creates parent only if `dir` itself
/// is missing; never recursive. Used once at daemon startup before the
/// first `pin_attached_link()` call.
[[nodiscard]] Result<void> ensure_pin_root(const std::string& dir);

/// Returns the count of regular files / pins inside `pin_root`. Used at
/// startup to detect stale pins left by a previously-crashed daemon.
/// On error (directory missing, EACCES) returns 0 and the caller is
/// expected to surface the underlying issue via `ensure_pin_root()`.
[[nodiscard]] size_t count_existing_pins(const std::string& pin_root);

/// Pin `link` at `<pin_root>/<program_name>` and record the pinning in
/// `state.pinned_hooks`. Returns an error if `bpf_link__pin()` fails or
/// if the resulting path would escape `pin_root`.
[[nodiscard]] Result<void> pin_attached_link(const std::string& program_name, bpf_link* link,
                                             const std::string& pin_root, BpfState& state);

/// Per-tick verification (called from the heartbeat thread). For each
/// entry in `state.pinned_hooks`, checks the pin path still exists. Emits
/// a forensic log line for each missing pin so SIEMs see the regression.
///
/// Returns the number of missing pins detected this tick (0 on healthy).
size_t verify_pinned_hooks(BpfState& state);

/// Per-tick verify+heal (called from the heartbeat thread when
/// `state.enable_pin_heal` is true). On each missing pin, calls
/// `bpf_link__pin()` again on the still-live userspace `bpf_link*` to
/// restore the bpffs entry. Does NOT call kernel attach syscalls — the
/// kernel link object remained alive across the missing-pin window
/// because userspace held an fd to it; only the bpffs path needs
/// rewriting. Updates `pin_heal_{attempts,successes,failures}` counters.
///
/// Returns the number of pins still missing AFTER heal attempts (0 on
/// fully healed or already-healthy).
size_t heal_pinned_hooks(BpfState& state);

} // namespace aegis
