#include "policy_slots.hpp"

#include <bpf/bpf.h>

#include <cerrno>

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

} // namespace aegis
