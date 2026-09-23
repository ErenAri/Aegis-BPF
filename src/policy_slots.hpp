// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <bpf/libbpf.h>

#include <cstdint>
#include <utility>
#include <vector>

#include "bpf_maps.hpp"
#include "result.hpp"

namespace aegis {

class BpfState;
struct SlottedMap;

/// Resolve the currently-live inner map of a slotted policy map.
///
/// A userspace lookup on an ARRAY_OF_MAPS yields the inner map's *id*, not a
/// file descriptor, so this allocates a new fd via bpf_map_get_fd_by_id(). The
/// returned handle owns and closes it.
///
/// The handle is valid only until the next flip: resolve it per operation and
/// never cache it across a policy reload.
Result<ShadowMap> live_policy_map_from_fds(int outer_fd, int active_slot_fd);

/// Convenience overload resolving through the state's active_slot handle.
Result<ShadowMap> live_policy_map(const BpfState& state, bpf_map* outer);

/// Key size of a slotted map's inner entries, from geometry captured pre-load.
/// Do NOT derive this from bpf_map__inner_map(): that returns NULL once the
/// object is loaded, and a zero key size silently makes every entry count 0.
size_t inner_key_size(const SlottedMap& m);

/// Size an inner policy map for a rule count, leaving headroom so runtime
/// single-element inserts (dynamic/TTL denies) do not hit max_entries between
/// reloads. A rule_count of 0 yields the floor.
uint32_t inner_size_for(uint32_t rule_count);

/// Create a new inner map for a slotted policy map, sized to max_entries (or
/// the template size where the kernel cannot vary it). Built from geometry
/// captured pre-load, since bpf_map__inner_map() is unavailable afterwards.
Result<ShadowMap> create_inner_map(const SlottedMap& m, uint32_t max_entries);

/// Atomically install a new policy generation.
///
/// Stages each (outer map, new inner map fd) pair into the currently-inactive
/// slot -- writes no hook observes -- then flips active_slot with a single u32
/// write that commits every staged map together. On any staging failure it
/// returns an error WITHOUT flipping, leaving the previous generation live and
/// enforcing. After a successful flip the retired slot is cleared so the kernel
/// can RCU-free the old inner maps.
Result<void> commit_policy_slot(BpfState& state, const std::vector<std::pair<SlottedMap*, int>>& staged);

/// Every slotted policy map bound on this state, in a stable order.
///
/// This is the completeness set for a commit: active_slot is ONE u32 shared by
/// every outer map, so flipping it switches all of them at once. A map left
/// out of a commit has nothing in the target slot, and after the flip its
/// policy_inner() resolves to NULL -- which hooks read as an empty map. For a
/// deny map that silently drops every rule; for trusted_exec_hash under
/// ima_fail_closed it would deny everything. commit_policy_slot() therefore
/// refuses to flip unless the staged set covers this list.
std::vector<SlottedMap*> all_slotted_maps(BpfState& state);

/// Ensure every slotted map has an inner map in the currently-active slot.
///
/// At first load the outer arrays are empty, so policy_inner() resolves to
/// NULL and every userspace write lands on fd -1. Nothing can be written --
/// not even the agent's own cgroup allowlist entry -- until a generation
/// exists, and the first policy apply is far too late for that.
///
/// Bootstrap therefore installs an empty generation: create an inner map for
/// any slotted map whose active slot is unpopulated, then resolve the cached
/// read handles. On a restart that reused pinned outers the active slot is
/// already populated and those maps are left untouched, which is what carries
/// the previous generation across a daemon restart.
Result<void> bootstrap_policy_slots(BpfState& state);

/// Generation id of the policy currently live, resolved through active_slot.
///
/// This is the generation ORACLE: it reports the id recorded on the slot the
/// hooks are reading, so the id and the rules come from the same place. 0 means
/// no generation has been committed yet.
uint64_t live_policy_generation(const BpfState& state);

/// Id to stamp on the next generation: one above the highest recorded on either
/// slot, so ids are monotonic across daemon restarts and never reused.
uint64_t next_policy_generation(const BpfState& state);

/// Entry count and capacity of a slotted map's currently-live inner map.
///
/// Capacity is the inner map's own max_entries, which varies because inner maps
/// are right-sized per reload -- it is NOT the outer map's slot count.
struct LivePolicyStats {
    size_t entries = 0;
    size_t capacity = 0;
    bool resolved = false;
};
LivePolicyStats live_policy_stats(const BpfState& state, const SlottedMap& m);

} // namespace aegis
