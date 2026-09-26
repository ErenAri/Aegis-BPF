#include "policy_slots.hpp"

#include <bpf/bpf.h>

#include <cerrno>
#include <cstdint>
#include <cstring>

#include "bpf_ops.hpp"
#include "logging.hpp"

namespace aegis {

Result<ShadowMap> live_policy_map_from_fds(int outer_fd, int active_slot_fd)
{
    if (outer_fd < 0 || active_slot_fd < 0) {
        return Error(ErrorCode::InvalidArgument, "Invalid fd resolving live policy map");
    }

    uint32_t key = 0;
    uint32_t slot = 0;
    if (bpf_map_lookup_elem(active_slot_fd, &key, &slot) != 0) {
        return Error::system(errno, "Failed to read active_slot");
    }
    // Mask to the slot count, mirroring the BPF-side policy_active_slot().
    slot &= 1u;

    // A lookup on an ARRAY_OF_MAPS yields the inner map's id, not an fd.
    uint32_t inner_id = 0;
    if (bpf_map_lookup_elem(outer_fd, &slot, &inner_id) != 0) {
        return Error::system(errno, "Failed to resolve inner map for live slot");
    }
    if (inner_id == 0) {
        return Error(ErrorCode::BpfMapOperationFailed, "Live policy slot is unpopulated");
    }

    const int inner_fd = bpf_map_get_fd_by_id(inner_id);
    if (inner_fd < 0) {
        return Error::system(errno, "Failed to open inner policy map by id");
    }
    // ShadowMap owns the descriptor and closes it.
    return ShadowMap(inner_fd);
}

Result<ShadowMap> live_policy_map(const BpfState& state, bpf_map* outer)
{
    if (!outer) {
        return Error(ErrorCode::InvalidArgument, "Slotted policy map handle is null");
    }
    if (!state.active_slot) {
        return Error(ErrorCode::BpfMapOperationFailed, "active_slot map not available");
    }
    return live_policy_map_from_fds(bpf_map__fd(outer), bpf_map__fd(state.active_slot));
}

size_t inner_key_size(const SlottedMap& m)
{
    return m.inner_key_size;
}

LivePolicyStats live_policy_stats(const BpfState& state, const SlottedMap& m)
{
    LivePolicyStats stats;
    auto live = live_policy_map(state, m.outer);
    if (!live) {
        // Unpopulated or unresolvable slot: report nothing rather than
        // inventing a count. Callers treat this as "no live policy".
        return stats;
    }

    struct bpf_map_info info = {};
    __u32 len = sizeof(info);
    if (bpf_obj_get_info_by_fd(live->fd(), &info, &len) != 0) {
        return stats;
    }

    stats.entries = map_fd_entry_count(live->fd(), info.key_size);
    stats.capacity = info.max_entries;
    stats.resolved = true;
    return stats;
}

uint32_t inner_size_for(uint32_t rule_count)
{
    // Floor keeps tiny policies from thrashing on the first few runtime adds.
    const uint32_t doubled = rule_count > 0 ? rule_count * 2u : 0u;
    return doubled > 64u ? doubled : 64u;
}

// --- SlottedMap self-resolution and helper overloads ----------------------
//
// These let code written against plain bpf_map* keep its call shape while
// operating on the live inner map of the current generation.

Result<ShadowMap> SlottedMap::live() const
{
    if (!outer || !slot_map) {
        return Error(ErrorCode::BpfMapOperationFailed, "Slotted map not bound (outer or active_slot missing)");
    }
    return live_policy_map_from_fds(bpf_map__fd(outer), bpf_map__fd(slot_map));
}

Result<void> SlottedMap::refresh_live()
{
    auto resolved = live();
    if (!resolved) {
        live_handle = ShadowMap();
        return resolved.error();
    }
    live_handle = std::move(*resolved);
    return {};
}

size_t map_entry_count(const SlottedMap& m)
{
    auto live = m.live();
    if (!live) {
        return 0;
    }
    return map_fd_entry_count(live->fd(), inner_key_size(m));
}

Result<void> clear_map_entries(const SlottedMap& m)
{
    auto live = m.live();
    if (!live) {
        // An unpopulated slot has nothing to clear; that is not an error.
        return {};
    }
    return clear_map_fd_entries(live->fd(), inner_key_size(m));
}

Result<void> verify_map_entry_count(const SlottedMap& m, size_t expected)
{
    auto live = m.live();
    if (!live) {
        return live.error();
    }
    return verify_map_fd_entry_count(live->fd(), inner_key_size(m), expected);
}

Result<ShadowMap> create_shadow_map(const SlottedMap& m, uint32_t max_entries_override)
{
    // A slotted map's shadow IS the next generation's inner map, so it is built
    // from the captured template rather than cloned from a live map.
    return create_inner_map(m, max_entries_override);
}

std::vector<SlottedMap*> all_slotted_maps(BpfState& state)
{
    std::vector<SlottedMap*> maps;
    for (SlottedMap* m :
         {&state.deny_inode, &state.deny_path, &state.deny_comm, &state.allow_cgroup, &state.allow_exec_inode,
          &state.trusted_exec_hash, &state.deny_ipv4, &state.deny_ipv6, &state.deny_cidr_v4, &state.deny_cidr_v6,
          &state.deny_port, &state.deny_ip_port_v4, &state.deny_ip_port_v6, &state.deny_cgroup_inode,
          &state.deny_cgroup_ipv4, &state.deny_cgroup_port}) {
        if (m->outer) {
            maps.push_back(m);
        }
    }
    return maps;
}

uint64_t live_policy_generation(const BpfState& state)
{
    if (!state.active_slot || !state.slot_generation) {
        return 0;
    }
    uint32_t key = 0;
    uint32_t slot = 0;
    if (bpf_map_lookup_elem(bpf_map__fd(state.active_slot), &key, &slot) != 0) {
        return 0;
    }
    slot &= 1u;
    uint64_t generation = 0;
    if (bpf_map_lookup_elem(bpf_map__fd(state.slot_generation), &slot, &generation) != 0) {
        return 0;
    }
    return generation;
}

uint64_t next_policy_generation(const BpfState& state)
{
    // Monotonic across restarts: derived from whatever is already recorded in
    // the pinned maps, never from a process-local counter. Two generations can
    // therefore never share an id, so an id names an exact policy.
    uint64_t highest = 0;
    if (state.slot_generation) {
        for (uint32_t slot = 0; slot < 2; ++slot) {
            uint64_t v = 0;
            if (bpf_map_lookup_elem(bpf_map__fd(state.slot_generation), &slot, &v) == 0 && v > highest) {
                highest = v;
            }
        }
    }
    return highest + 1;
}

Result<void> bootstrap_policy_slots(BpfState& state)
{
    if (!state.active_slot) {
        return Error(ErrorCode::BpfMapOperationFailed, "active_slot map not available");
    }
    const int slot_fd = bpf_map__fd(state.active_slot);

    uint32_t key = 0;
    uint32_t active = 0;
    if (bpf_map_lookup_elem(slot_fd, &key, &active) != 0) {
        // An ARRAY map always has element 0, so a failure here is real.
        return Error::system(errno, "Failed to read active_slot during bootstrap");
    }
    active &= 1u;

    size_t created = 0;
    for (SlottedMap* m : all_slotted_maps(state)) {
        // Populated already (reused pin after a restart): keep that generation.
        if (auto existing = m->live(); existing) {
            m->live_handle = std::move(*existing);
            continue;
        }
        auto inner = create_inner_map(*m, 0);
        if (!inner) {
            return inner.error();
        }
        uint32_t value = static_cast<uint32_t>(inner->fd());
        if (bpf_map_update_elem(bpf_map__fd(m->outer), &active, &value, BPF_ANY) != 0) {
            return Error::system(errno, std::string("Failed to bootstrap slot for ") + bpf_map__name(m->outer));
        }
        ++created;
        auto resolved = m->refresh_live();
        if (!resolved) {
            return resolved.error();
        }
    }

    logger().log(SLOG_INFO("Policy slots bootstrapped")
                     .field("active_slot", static_cast<int64_t>(active))
                     .field("inner_maps_created", static_cast<int64_t>(created)));
    return {};
}

Result<void> commit_policy_slot(BpfState& state, const std::vector<std::pair<SlottedMap*, int>>& staged)
{
    if (!state.active_slot) {
        return Error(ErrorCode::BpfMapOperationFailed, "active_slot map not available");
    }
    const int slot_fd = bpf_map__fd(state.active_slot);

    // Completeness gate. One u32 switches every outer map, so a map missing
    // from `staged` would resolve to an empty inner after the flip. Refusing
    // here turns a silent policy hole into a failed reload that leaves the
    // previous generation enforcing.
    for (SlottedMap* bound : all_slotted_maps(state)) {
        bool covered = false;
        for (const auto& [m, fd] : staged) {
            if (m == bound) {
                covered = true;
                break;
            }
        }
        if (!covered) {
            const char* name = bound->outer ? bpf_map__name(bound->outer) : "<unnamed>";
            logger().log(SLOG_ERROR("Atomic policy commit is incomplete; refusing to flip")
                             .field("stage", "completeness_gate")
                             .field("missing_map", name)
                             .field("active_generation_changed", "no")
                             .field("why", "one active_slot governs every slotted map, so an omitted map "
                                           "would resolve to an empty inner map after the flip"));
            return Error(ErrorCode::InvalidArgument, "Policy commit does not cover every slotted map; refusing to flip",
                         name);
        }
    }

    uint32_t key = 0;
    uint32_t live = 0;
    if (bpf_map_lookup_elem(slot_fd, &key, &live) != 0) {
        return Error::system(errno, "Failed to read active_slot");
    }
    live &= 1u;
    const uint32_t target = live ^ 1u;

    // Stage into the inactive slot. These writes are individually non-atomic,
    // but no hook can observe them: active_slot still names the other slot.
    for (const auto& [m, inner_fd] : staged) {
        if (!m || !m->outer || inner_fd < 0) {
            return Error(ErrorCode::InvalidArgument, "Invalid staged policy map");
        }
        uint32_t value = static_cast<uint32_t>(inner_fd);
        if (bpf_map_update_elem(bpf_map__fd(m->outer), &target, &value, BPF_ANY) != 0) {
            // Fail-safe: no flip, so the previous generation stays live. Name
            // the map and slot -- "staging failed" alone does not tell an
            // operator which domain ran out of room.
            const int saved = errno;
            logger().log(SLOG_ERROR("Atomic policy staging failed")
                             .field("stage", "stage_inner_map")
                             .field("map", bpf_map__name(m->outer))
                             .field("target_slot", static_cast<int64_t>(target))
                             .field("errno", std::strerror(saved))
                             .field("active_slot", static_cast<int64_t>(live))
                             .field("active_generation_changed", "no"));
            errno = saved;
            return Error::system(saved, std::string("Failed to stage inner map into inactive slot: ") +
                                            bpf_map__name(m->outer));
        }
    }

    // Stamp the generation id on the target slot BEFORE the flip, so the
    // oracle is already correct the instant the slot becomes live. A reader
    // that resolves slot -> generation can never see a slot whose id still
    // belongs to the generation it replaced.
    const uint64_t generation = next_policy_generation(state);
    if (state.slot_generation) {
        if (bpf_map_update_elem(bpf_map__fd(state.slot_generation), &target, &generation, BPF_ANY) != 0) {
            return Error::system(errno, "Failed to stamp generation id on the staged slot");
        }
    }

    // The single atomic commit. Every slotted domain switches generation here.
    if (bpf_map_update_elem(slot_fd, &key, &target, BPF_ANY) != 0) {
        const int saved = errno;
        logger().log(SLOG_ERROR("Atomic policy commit failed at the flip")
                         .field("stage", "active_slot_commit")
                         .field("target_slot", static_cast<int64_t>(target))
                         .field("errno", std::strerror(saved))
                         .field("active_generation_changed", "no"));
        errno = saved;
        return Error::system(saved, "Failed to flip active_slot");
    }

    // Re-point the cached read handles at the generation that is now live.
    // Done here, inside the commit, so it cannot be forgotten by a caller.
    for (SlottedMap* m : all_slotted_maps(state)) {
        auto refreshed = m->refresh_live();
        if (!refreshed) {
            logger().log(SLOG_WARN("Failed to refresh live handle after commit")
                             .field("map", bpf_map__name(m->outer))
                             .field("error", refreshed.error().to_string()));
        }
    }

    // Retire the previous generation so the kernel can RCU-free it.
    for (const auto& [m, inner_fd] : staged) {
        (void)inner_fd;
        bpf_map_delete_elem(bpf_map__fd(m->outer), &live);
    }
    return {};
}

Result<ShadowMap> create_inner_map(const SlottedMap& m, uint32_t max_entries)
{
    if (m.inner_key_size == 0) {
        return Error(ErrorCode::BpfMapOperationFailed,
                     "Slotted map inner geometry not captured (capture_inner_geometry must run pre-load)");
    }

    uint32_t entries = m.inner_max_entries;
    if (max_entries > 0 && supports_variable_inner_max_entries()) {
        entries = max_entries;
    }

    // bpf_map_create() is libbpf 0.7+. Ubuntu 22.04 is a supported platform and
    // ships 0.5, so keep the pre-0.7 spelling too rather than quietly raising
    // the floor on a platform the support policy commits to.
    int fd = -1;
#ifdef bpf_map_create_opts__last_field
    struct bpf_map_create_opts opts = {};
    opts.sz = sizeof(opts);
    opts.map_flags = m.inner_flags;
    fd = bpf_map_create(static_cast<enum bpf_map_type>(m.inner_type), "aegis_inner", m.inner_key_size,
                        m.inner_value_size, entries, &opts);
#else
    fd = bpf_create_map_name(static_cast<enum bpf_map_type>(m.inner_type), "aegis_inner",
                             static_cast<int>(m.inner_key_size), static_cast<int>(m.inner_value_size),
                             static_cast<int>(entries), m.inner_flags);
#endif
    if (fd < 0) {
        return Error::system(errno, "Failed to create inner policy map");
    }
    return ShadowMap(fd);
}

} // namespace aegis
