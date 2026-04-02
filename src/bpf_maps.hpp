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
    ShadowMap allow_cgroup;
    ShadowMap allow_exec_inode;
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

Result<ShadowMap> create_shadow_map(bpf_map* live_map);
Result<ShadowMapSet> create_shadow_map_set(const BpfState& state);
size_t map_fd_entry_count(int fd, size_t key_size);
Result<void> sync_from_shadow(bpf_map* live_map, int shadow_fd);

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
