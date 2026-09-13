// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <bpf/libbpf.h>

#include <cstdint>

#include "bpf_maps.hpp"
#include "result.hpp"

namespace aegis {

class BpfState;

/// Resolve the currently-live inner map of a slotted policy map.
///
/// A userspace lookup on an ARRAY_OF_MAPS yields the inner map's *id*, not a
/// file descriptor, so this allocates a new fd via bpf_map_get_fd_by_id(). The
/// returned handle owns and closes it.
///
/// The handle is valid only until the next flip: resolve it per operation and
/// never cache it across a policy reload.
Result<ShadowMap> live_policy_map_from_fds(int outer_fd, int active_slot_fd);

} // namespace aegis
