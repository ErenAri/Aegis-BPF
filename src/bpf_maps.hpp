// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <bpf/libbpf.h>

#include <string>
#include <vector>

#include "result.hpp"

namespace aegis {

class BpfState;

size_t map_entry_count(bpf_map* map);
Result<void> clear_map_entries(bpf_map* map);

Result<void> verify_map_entry_count(bpf_map* map, size_t expected);

class ShadowMap {
  public:
    ShadowMap() = default;
    explicit ShadowMap(int fd) : fd_(fd) {}
    ~ShadowMap();
    ShadowMap(ShadowMap&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    ShadowMap& operator=(ShadowMap&& o) noexcept;
    ShadowMap(const ShadowMap&) = delete;
    ShadowMap& operator=(const ShadowMap&) = delete;
    [[nodiscard]] int fd() const { return fd_; }
    [[nodiscard]] explicit operator bool() const { return fd_ >= 0; }

  private:
    int fd_ = -1;
};

struct ShadowMapSet {
    ShadowMap deny_inode;
    ShadowMap deny_path;
    ShadowMap deny_comm;
    ShadowMap allow_cgroup;
    ShadowMap allow_exec_inode;
    ShadowMap trusted_exec_hash;
    ShadowMap deny_ipv4;
    ShadowMap deny_ipv6;
    ShadowMap deny_port;
    ShadowMap deny_ip_port_v4;
    ShadowMap deny_ip_port_v6;
    ShadowMap deny_cidr_v4;
    ShadowMap deny_cidr_v6;
    // Cgroup-scoped deny maps
    ShadowMap deny_cgroup_inode;
    ShadowMap deny_cgroup_ipv4;
    ShadowMap deny_cgroup_port;
};

Result<ShadowMap> create_shadow_map(bpf_map* live_map, uint32_t max_entries_override = 0);
/// Same as create_shadow_map but clones from a raw fd rather than a libbpf map
/// handle. Used by the policy slot builder, which works in fds.
///
/// max_entries_override of 0 means "clone the source size". A non-zero value is
/// honoured only where supports_variable_inner_max_entries() is true.
Result<ShadowMap> create_shadow_map_from_fd(int live_fd, uint32_t max_entries_override = 0);
// Slotted-map overloads. Each resolves the live inner map for the current
// generation and operates on that, so a caller written against the plain maps
// keeps working and keeps meaning the same thing.
struct SlottedMap;
size_t map_entry_count(const SlottedMap& m);
Result<void> clear_map_entries(const SlottedMap& m);
Result<void> verify_map_entry_count(const SlottedMap& m, size_t expected);
Result<ShadowMap> create_shadow_map(const SlottedMap& m, uint32_t max_entries_override = 0);
/// Rule counts used to right-size slotted inner maps. Zero means "use the
/// template size"; non-zero sizes the new inner map to the policy.
struct ShadowSizeHints {
    uint32_t deny_inode_rules = 0;
};

Result<ShadowMapSet> create_shadow_map_set(const BpfState& state, const ShadowSizeHints& hints = {});
size_t map_fd_entry_count(int fd, size_t key_size);
/// fd-based variants of the handle helpers above, for slotted policy maps whose
/// entries live in an inner map reached through live_policy_map().
Result<void> clear_map_fd_entries(int fd, size_t key_size);
Result<void> verify_map_fd_entry_count(int fd, size_t key_size, size_t expected);

// sync_from_shadow() used to copy a shadow map's entries into the live map,
// deleting whatever was not in the shadow. That was the non-atomic apply
// path: it destroyed the live policy to build the new one and needed the
// audit-only window to hide the gap. Every policy map is now slotted and
// installed by a single active_slot flip, so nothing writes a live policy
// map in place. The function is deleted rather than left unused, so the
// non-atomic path cannot be reintroduced by calling something that still
// exists.

/// True when a pinned map's layout matches what this build expects.
///
/// bpf_map__reuse_fd() does NOT reject a type mismatch, so a pin left behind by
/// a different agent version binds silently and only fails much later inside
/// the verifier with an opaque message. Compares type, key size and value size;
/// deliberately NOT max_entries, which legitimately varies (runtime tuning and
/// right-sized inner maps).
bool pinned_map_layout_matches(int fd, uint32_t type, uint32_t key_size, uint32_t value_size);

/// True when the kernel accepts an inner map whose max_entries differs from the
/// outer map's template. The kernel stopped comparing max_entries in
/// bpf_map_meta_equal() in 5.11; below that, inner maps must be created at the
/// template's size. Probed once on first call, then cached.
///
/// Returns false when map creation is not permitted (no CAP_BPF) as well as
/// when the kernel lacks support. Both collapse to the same safe fallback:
/// template-sized inner maps, which costs memory but never correctness.
bool supports_variable_inner_max_entries();

struct MapPressure {
    std::string name;
    size_t entry_count;
    size_t max_entries;
    double utilization;
};

struct MapPressureReport {
    std::vector<MapPressure> maps;
    bool any_warning;
    bool any_critical;
    bool any_full;
};

MapPressureReport check_map_pressure(const BpfState& state);

} // namespace aegis
