// cppcheck-suppress-file missingIncludeSystem
#include "bpf_maps.hpp"

#include <unistd.h>

#include <cerrno>
#include <vector>

#include "bpf_ops.hpp"

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

Result<ShadowMap> create_shadow_map(bpf_map* live_map)
{
    if (!live_map) {
        return Error(ErrorCode::InvalidArgument, "Cannot create shadow for null map");
    }

    const auto type = static_cast<enum bpf_map_type>(bpf_map__type(live_map));
    const auto key_size = bpf_map__key_size(live_map);
    const auto value_size = bpf_map__value_size(live_map);
    const auto max_entries = bpf_map__max_entries(live_map);
    const auto flags = bpf_map__map_flags(live_map);

    int fd = -1;
#ifdef bpf_map_create_opts__last_field
    struct bpf_map_create_opts opts = {};
    opts.sz = sizeof(opts);
    opts.map_flags = flags;
    fd = bpf_map_create(type, "shadow", key_size, value_size, max_entries, &opts);
#else
    fd = bpf_create_map_name(type, "shadow", static_cast<int>(key_size), static_cast<int>(value_size),
                             static_cast<int>(max_entries), flags);
#endif
    if (fd < 0) {
        return Error::system(errno, "Failed to create shadow map");
    }
    return ShadowMap(fd);
}

Result<ShadowMapSet> create_shadow_map_set(const BpfState& state)
{
    ShadowMapSet set;

    auto mk = [](bpf_map* m) -> Result<ShadowMap> {
        if (!m) {
            return ShadowMap();
        }
        return create_shadow_map(m);
    };

    auto r = mk(state.deny_inode);
    if (!r) {
        return r.error();
    }
    set.deny_inode = std::move(*r);

    r = mk(state.deny_path);
    if (!r) {
        return r.error();
    }
    set.deny_path = std::move(*r);

    r = mk(state.allow_cgroup);
    if (!r) {
        return r.error();
    }
    set.allow_cgroup = std::move(*r);

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
    static constexpr size_t kMaxDenyInodes = 65536;
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

    auto add_map = [&](const char* name, bpf_map* map, size_t max_entries) {
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

    add_map("deny_inode", state.deny_inode, kMaxDenyInodes);
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

    return report;
}

} // namespace aegis
