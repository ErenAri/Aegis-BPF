#include "policy_slots.hpp"

#include <bpf/bpf.h>

#include <cerrno>
#include <cstdint>

#include "bpf_ops.hpp"

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

Result<void> commit_policy_slot(const BpfState& state, const std::vector<std::pair<bpf_map*, int>>& staged)
{
    if (!state.active_slot) {
        return Error(ErrorCode::BpfMapOperationFailed, "active_slot map not available");
    }
    const int slot_fd = bpf_map__fd(state.active_slot);

    uint32_t key = 0;
    uint32_t live = 0;
    if (bpf_map_lookup_elem(slot_fd, &key, &live) != 0) {
        return Error::system(errno, "Failed to read active_slot");
    }
    live &= 1u;
    const uint32_t target = live ^ 1u;

    // Stage into the inactive slot. These writes are individually non-atomic,
    // but no hook can observe them: active_slot still names the other slot.
    for (const auto& [outer, inner_fd] : staged) {
        if (!outer || inner_fd < 0) {
            return Error(ErrorCode::InvalidArgument, "Invalid staged policy map");
        }
        uint32_t value = static_cast<uint32_t>(inner_fd);
        if (bpf_map_update_elem(bpf_map__fd(outer), &target, &value, BPF_ANY) != 0) {
            // Fail-safe: no flip, so the previous generation stays live.
            return Error::system(errno, "Failed to stage inner map into inactive slot");
        }
    }

    // The single atomic commit. Every staged domain switches generation here.
    if (bpf_map_update_elem(slot_fd, &key, &target, BPF_ANY) != 0) {
        return Error::system(errno, "Failed to flip active_slot");
    }

    // Retire the previous generation so the kernel can RCU-free it.
    for (const auto& [outer, inner_fd] : staged) {
        (void)inner_fd;
        bpf_map_delete_elem(bpf_map__fd(outer), &live);
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

    struct bpf_map_create_opts opts = {};
    opts.sz = sizeof(opts);
    opts.map_flags = m.inner_flags;
    const int fd = bpf_map_create(static_cast<enum bpf_map_type>(m.inner_type), "aegis_inner", m.inner_key_size,
                                  m.inner_value_size, entries, &opts);
    if (fd < 0) {
        return Error::system(errno, "Failed to create inner policy map");
    }
    return ShadowMap(fd);
}

} // namespace aegis
