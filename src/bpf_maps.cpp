// cppcheck-suppress-file missingIncludeSystem
#include "bpf_maps.hpp"

#include "logging.hpp"

#include <unistd.h>

#include <cerrno>
#include <vector>

#include "bpf_ops.hpp"
#include "policy_slots.hpp"

namespace aegis {

size_t map_entry_count(bpf_map* map)
{
    if (!map) {
        return 0;
    }
    const size_t key_sz = bpf_map__key_size(map);
    std::vector<uint8_t> key(key_sz);
    std::vector<uint8_t> next_key(key_sz);
    size_t count = 0;
    int fd = bpf_map__fd(map);
    int rc = bpf_map_get_next_key(fd, nullptr, key.data());
    while (!rc) {
        ++count;
        rc = bpf_map_get_next_key(fd, key.data(), next_key.data());
        key.swap(next_key);
    }
    return count;
}

Result<void> verify_map_entry_count(bpf_map* map, size_t expected)
{
    if (!map) {
        if (expected == 0) {
            return {};
        }
        return Error(ErrorCode::BpfMapOperationFailed, "Map is null but expected entries", std::to_string(expected));
    }
    size_t actual = map_entry_count(map);
    if (actual != expected) {
        return Error(ErrorCode::BpfMapOperationFailed, "Map entry count mismatch",
                     "expected=" + std::to_string(expected) + " actual=" + std::to_string(actual));
    }
    return {};
}

bool pinned_map_layout_matches(int fd, uint32_t type, uint32_t key_size, uint32_t value_size)
{
    if (fd < 0) {
        return false;
    }
    struct bpf_map_info info = {};
    __u32 len = sizeof(info);
    if (bpf_obj_get_info_by_fd(fd, &info, &len) != 0) {
        return false;
    }
    return info.type == type && info.key_size == key_size && info.value_size == value_size;
}

Result<void> clear_map_fd_entries(int fd, size_t key_size)
{
    if (fd < 0) {
        return Error(ErrorCode::InvalidArgument, "Invalid fd clearing map entries");
    }
    std::vector<uint8_t> key(key_size);
    std::vector<uint8_t> next_key(key_size);
    int rc = bpf_map_get_next_key(fd, nullptr, key.data());
    while (!rc) {
        rc = bpf_map_get_next_key(fd, key.data(), next_key.data());
        bpf_map_delete_elem(fd, key.data());
        if (!rc) {
            key.swap(next_key);
        }
    }
    return {};
}

Result<void> verify_map_fd_entry_count(int fd, size_t key_size, size_t expected)
{
    const size_t actual = map_fd_entry_count(fd, key_size);
    if (actual != expected) {
        return Error(ErrorCode::BpfMapOperationFailed, "Map entry count mismatch",
                     "expected=" + std::to_string(expected) + " actual=" + std::to_string(actual));
    }
    return {};
}

Result<void> clear_map_entries(bpf_map* map)
{
    if (!map) {
        return Error(ErrorCode::InvalidArgument, "Map is null");
    }
    int fd = bpf_map__fd(map);
    const size_t key_sz = bpf_map__key_size(map);
    std::vector<uint8_t> key(key_sz);
    std::vector<uint8_t> next_key(key_sz);
    int rc = bpf_map_get_next_key(fd, nullptr, key.data());
    while (!rc) {
        rc = bpf_map_get_next_key(fd, key.data(), next_key.data());
        bpf_map_delete_elem(fd, key.data());
        if (!rc) {
            key.swap(next_key);
        }
    }
    return {};
}

ShadowMap::~ShadowMap()
{
    if (fd_ >= 0) {
        close(fd_);
    }
}

ShadowMap& ShadowMap::operator=(ShadowMap&& o) noexcept
{
    if (this != &o) {
        if (fd_ >= 0) {
            close(fd_);
        }
        fd_ = o.fd_;
        o.fd_ = -1;
    }
    return *this;
}

namespace {

// Creates a throwaway outer/inner pair and tries to insert an inner map whose
// max_entries differs from the template. Succeeds only on kernels where
// bpf_map_meta_equal() ignores max_entries (5.11+). All fds are closed before
// returning; nothing is pinned.
bool probe_variable_inner_max_entries()
{
    struct bpf_map_create_opts opts = {};
    opts.sz = sizeof(opts);

    int tmpl = bpf_map_create(BPF_MAP_TYPE_HASH, "aegis_tmpl", 4, 1, 16, &opts);
    if (tmpl < 0) {
        return false;
    }

    struct bpf_map_create_opts outer_opts = {};
    outer_opts.sz = sizeof(outer_opts);
    outer_opts.inner_map_fd = static_cast<__u32>(tmpl);
    int outer = bpf_map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS, "aegis_probe", 4, 4, 1, &outer_opts);
    if (outer < 0) {
        close(tmpl);
        return false;
    }

    // Deliberately a different max_entries than the template.
    int big = bpf_map_create(BPF_MAP_TYPE_HASH, "aegis_big", 4, 1, 64, &opts);
    if (big < 0) {
        close(outer);
        close(tmpl);
        return false;
    }

    __u32 key = 0;
    __u32 value = static_cast<__u32>(big);
    const bool ok = bpf_map_update_elem(outer, &key, &value, BPF_ANY) == 0;

    close(big);
    close(outer);
    close(tmpl);
    return ok;
}

} // namespace

bool supports_variable_inner_max_entries()
{
    static const bool cached = probe_variable_inner_max_entries();
    return cached;
}

namespace {

Result<ShadowMap> create_shadow_like(enum bpf_map_type type, uint32_t key_size, uint32_t value_size,
                                     uint32_t max_entries, uint32_t flags, uint32_t max_entries_override)
{
    uint32_t entries = max_entries;
    if (max_entries_override > 0 && supports_variable_inner_max_entries()) {
        entries = max_entries_override;
    }

    int fd = -1;
#ifdef bpf_map_create_opts__last_field
    struct bpf_map_create_opts opts = {};
    opts.sz = sizeof(opts);
    opts.map_flags = flags;
    fd = bpf_map_create(type, "shadow", key_size, value_size, entries, &opts);
#else
    fd = bpf_create_map_name(type, "shadow", static_cast<int>(key_size), static_cast<int>(value_size),
                             static_cast<int>(entries), flags);
#endif
    if (fd < 0) {
        return Error::system(errno, "Failed to create shadow map");
    }
    return ShadowMap(fd);
}

} // namespace

Result<ShadowMap> create_shadow_map(bpf_map* live_map, uint32_t max_entries_override)
{
    if (!live_map) {
        return Error(ErrorCode::InvalidArgument, "Cannot create shadow for null map");
    }

    return create_shadow_like(static_cast<enum bpf_map_type>(bpf_map__type(live_map)), bpf_map__key_size(live_map),
                              bpf_map__value_size(live_map), bpf_map__max_entries(live_map),
                              bpf_map__map_flags(live_map), max_entries_override);
}

Result<ShadowMap> create_shadow_map_from_fd(int live_fd, uint32_t max_entries_override)
{
    struct bpf_map_info info = {};
    __u32 len = sizeof(info);
    if (bpf_obj_get_info_by_fd(live_fd, &info, &len) != 0) {
        return Error::system(errno, "Failed to read map info for shadow clone");
    }

    return create_shadow_like(static_cast<enum bpf_map_type>(info.type), info.key_size, info.value_size,
                              info.max_entries, info.map_flags, max_entries_override);
}

Result<ShadowMapSet> create_shadow_map_set(const BpfState& state, const ShadowSizeHints& hints)
{
    ShadowMapSet set;

    auto mk = [](auto&& m) -> Result<ShadowMap> {
        if (!m) {
            return ShadowMap();
        }
        auto r = create_shadow_map(m);
        if (!r) {
            logger().log(SLOG_ERROR("Could not allocate an inner map for the next policy generation")
                             .field("stage", "allocate_inner_map")
                             .field("error", r.error().to_string())
                             .field("active_generation_changed", "no"));
        }
        return r;
    };

    // deny_inode is slotted: its "shadow" IS the next generation's inner map, so
    // it is cloned from the outer map's inner template and right-sized to the
    // policy rather than allocated at the template maximum.
    if (!state.deny_inode.outer) {
        return Error(ErrorCode::BpfMapOperationFailed, "deny_inode outer map not available");
    }
    auto r = create_inner_map(state.deny_inode, inner_size_for(hints.deny_inode_rules));
    if (!r) {
        return r.error();
    }
    set.deny_inode = std::move(*r);

    r = mk(state.deny_path);
    if (!r) {
        return r.error();
    }
    set.deny_path = std::move(*r);

    r = mk(state.deny_comm);
    if (!r) {
        return r.error();
    }
    set.deny_comm = std::move(*r);

    r = mk(state.allow_cgroup);
    if (!r) {
        return r.error();
    }
    set.allow_cgroup = std::move(*r);

    r = mk(state.trusted_exec_hash);
    if (!r) {
        return r.error();
    }
    set.trusted_exec_hash = std::move(*r);

    r = mk(state.allow_exec_inode);
    if (!r) {
        return r.error();
    }
    set.allow_exec_inode = std::move(*r);

    r = mk(state.deny_ipv4);
    if (!r) {
        return r.error();
    }
    set.deny_ipv4 = std::move(*r);

    r = mk(state.deny_ipv6);
    if (!r) {
        return r.error();
    }
    set.deny_ipv6 = std::move(*r);

    r = mk(state.deny_port);
    if (!r) {
        return r.error();
    }
    set.deny_port = std::move(*r);

    r = mk(state.deny_ip_port_v4);
    if (!r) {
        return r.error();
    }
    set.deny_ip_port_v4 = std::move(*r);

    r = mk(state.deny_ip_port_v6);
    if (!r) {
        return r.error();
    }
    set.deny_ip_port_v6 = std::move(*r);

    r = mk(state.deny_cidr_v4);
    if (!r) {
        return r.error();
    }
    set.deny_cidr_v4 = std::move(*r);

    r = mk(state.deny_cidr_v6);
    if (!r) {
        return r.error();
    }
    set.deny_cidr_v6 = std::move(*r);

    // Cgroup-scoped deny maps
    r = mk(state.deny_cgroup_inode);
    if (!r) {
        return r.error();
    }
    set.deny_cgroup_inode = std::move(*r);

    r = mk(state.deny_cgroup_ipv4);
    if (!r) {
        return r.error();
    }
    set.deny_cgroup_ipv4 = std::move(*r);

    r = mk(state.deny_cgroup_port);
    if (!r) {
        return r.error();
    }
    set.deny_cgroup_port = std::move(*r);

    return set;
}

size_t map_fd_entry_count(int fd, size_t key_size)
{
    if (fd < 0) {
        return 0;
    }
    std::vector<uint8_t> key(key_size);
    std::vector<uint8_t> next_key(key_size);
    size_t count = 0;
    int rc = bpf_map_get_next_key(fd, nullptr, key.data());
    while (!rc) {
        ++count;
        rc = bpf_map_get_next_key(fd, key.data(), next_key.data());
        key.swap(next_key);
    }
    return count;
}

Result<void> sync_from_shadow(bpf_map* live_map, int shadow_fd)
{
    if (!live_map || shadow_fd < 0) {
        return {};
    }

    int live_fd = bpf_map__fd(live_map);
    size_t key_sz = bpf_map__key_size(live_map);
    size_t val_sz = bpf_map__value_size(live_map);

    std::vector<uint8_t> key(key_sz);
    std::vector<uint8_t> next_key(key_sz);
    std::vector<uint8_t> val(val_sz);

    int rc = bpf_map_get_next_key(shadow_fd, nullptr, key.data());
    while (!rc) {
        if (bpf_map_lookup_elem(shadow_fd, key.data(), val.data()) == 0) {
            if (bpf_map_update_elem(live_fd, key.data(), val.data(), BPF_ANY)) {
                return Error::system(errno, "sync_from_shadow: upsert failed");
            }
        }
        rc = bpf_map_get_next_key(shadow_fd, key.data(), next_key.data());
        key.swap(next_key);
    }

    std::vector<std::vector<uint8_t>> stale_keys;
    rc = bpf_map_get_next_key(live_fd, nullptr, key.data());
    while (!rc) {
        if (bpf_map_lookup_elem(shadow_fd, key.data(), val.data()) != 0) {
            if (errno != ENOENT) {
                return Error::system(errno, "sync_from_shadow: shadow lookup failed");
            }
            stale_keys.push_back(key);
        }
        rc = bpf_map_get_next_key(live_fd, key.data(), next_key.data());
        key.swap(next_key);
    }
    for (const auto& sk : stale_keys) {
        bpf_map_delete_elem(live_fd, sk.data());
    }

    return {};
}

MapPressureReport check_map_pressure(const BpfState& state)
{
    static constexpr size_t kMaxDenyPaths = 16384;
    static constexpr size_t kMaxAllowCgroups = 1024;
    static constexpr size_t kMaxAllowExecInodes = 65536;
    static constexpr size_t kMaxDenyIpv4 = 65536;
    static constexpr size_t kMaxDenyIpv6 = 65536;
    static constexpr size_t kMaxDenyPorts = 4096;
    static constexpr size_t kMaxDenyIpPortV4 = 4096;
    static constexpr size_t kMaxDenyIpPortV6 = 4096;
    static constexpr size_t kMaxDenyCidrV4 = 16384;
    static constexpr size_t kMaxDenyCidrV6 = 16384;

    MapPressureReport report{};
    report.any_warning = false;
    report.any_critical = false;
    report.any_full = false;

    // Shared tail for both directly-addressable and slotted maps.
    auto add_fd_map = [&](const char* name, size_t count, size_t max_entries) {
        double util = max_entries > 0 ? static_cast<double>(count) / static_cast<double>(max_entries) : 0.0;
        report.maps.push_back({name, count, max_entries, util});
        if (util >= 1.0) {
            report.any_full = true;
        }
        if (util >= 0.95) {
            report.any_critical = true;
        }
        if (util >= 0.80) {
            report.any_warning = true;
        }
    };

    // Generic so it accepts both plain maps and slotted ones; map_entry_count()
    // overloads to the live inner map for the latter.
    auto add_map = [&](const char* name, auto&& map, size_t max_entries) {
        if (!map) {
            return;
        }
        size_t count = map_entry_count(map);
        double util = max_entries > 0 ? static_cast<double>(count) / static_cast<double>(max_entries) : 0.0;
        report.maps.push_back({name, count, max_entries, util});
        if (util >= 1.0) {
            report.any_full = true;
        }
        if (util >= 0.95) {
            report.any_critical = true;
        }
        if (util >= 0.80) {
            report.any_warning = true;
        }
    };

    // deny_inode is slotted; pressure is measured on the live inner map.
    if (const auto live = live_policy_stats(state, state.deny_inode); live.resolved) {
        add_fd_map("deny_inode", live.entries, live.capacity);
    }
    add_map("deny_path", state.deny_path, kMaxDenyPaths);
    add_map("allow_cgroup", state.allow_cgroup, kMaxAllowCgroups);
    add_map("allow_exec_inode", state.allow_exec_inode, kMaxAllowExecInodes);
    add_map("deny_ipv4", state.deny_ipv4, kMaxDenyIpv4);
    add_map("deny_ipv6", state.deny_ipv6, kMaxDenyIpv6);
    add_map("deny_port", state.deny_port, kMaxDenyPorts);
    add_map("deny_ip_port_v4", state.deny_ip_port_v4, kMaxDenyIpPortV4);
    add_map("deny_ip_port_v6", state.deny_ip_port_v6, kMaxDenyIpPortV6);
    add_map("deny_cidr_v4", state.deny_cidr_v4, kMaxDenyCidrV4);
    add_map("deny_cidr_v6", state.deny_cidr_v6, kMaxDenyCidrV6);

    // Cgroup-scoped deny maps
    static constexpr size_t kMaxDenyCgroupInode = 65536;
    static constexpr size_t kMaxDenyCgroupIpv4 = 65536;
    static constexpr size_t kMaxDenyCgroupPort = 4096;
    add_map("deny_cgroup_inode", state.deny_cgroup_inode, kMaxDenyCgroupInode);
    add_map("deny_cgroup_ipv4", state.deny_cgroup_ipv4, kMaxDenyCgroupIpv4);
    add_map("deny_cgroup_port", state.deny_cgroup_port, kMaxDenyCgroupPort);

    return report;
}

} // namespace aegis
