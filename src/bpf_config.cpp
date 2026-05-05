// cppcheck-suppress-file missingIncludeSystem
#include "bpf_config.hpp"

#include <cerrno>
#include <vector>

#include "bpf_ops.hpp"

namespace aegis {

namespace {

bool map_is_empty(bpf_map* map)
{
    if (!map) {
        return true;
    }
    int fd = bpf_map__fd(map);
    if (fd < 0) {
        return false;
    }
    const size_t key_sz = bpf_map__key_size(map);
    std::vector<uint8_t> key(key_sz);
    errno = 0;
    int rc = bpf_map_get_next_key(fd, nullptr, key.data());
    if (rc == 0) {
        return false;
    }
    return errno == ENOENT;
}

AgentConfig default_agent_config()
{
    AgentConfig cfg{};
    cfg.enforce_signal = kEnforceSignalTerm;
    cfg.event_sample_rate = 1;
    cfg.sigkill_escalation_threshold = kSigkillEscalationThresholdDefault;
    cfg.sigkill_escalation_window_seconds = kSigkillEscalationWindowSecondsDefault;
    return cfg;
}

bool file_policy_maps_empty(const BpfState& state)
{
    return map_is_empty(state.deny_inode) && map_is_empty(state.deny_path) && map_is_empty(state.deny_cgroup_inode);
}

bool path_policy_map_empty(const BpfState& state)
{
    return map_is_empty(state.deny_path);
}

bool net_policy_maps_empty(const BpfState& state)
{
    return map_is_empty(state.deny_ipv4) && map_is_empty(state.deny_ipv6) && map_is_empty(state.deny_port) &&
           map_is_empty(state.deny_ip_port_v4) && map_is_empty(state.deny_ip_port_v6) &&
           map_is_empty(state.deny_cidr_v4) && map_is_empty(state.deny_cidr_v6) &&
           map_is_empty(state.deny_cgroup_ipv4) && map_is_empty(state.deny_cgroup_port);
}

} // namespace

Result<void> set_agent_config(BpfState& state, bool audit_only)
{
    if (!state.config_map) {
        return Error(ErrorCode::BpfMapOperationFailed, "Config map not found");
    }

    uint32_t key = 0;
    AgentConfig cfg = default_agent_config();
    cfg.audit_only = audit_only ? 1 : 0;
    if (bpf_map_update_elem(bpf_map__fd(state.config_map), &key, &cfg, BPF_ANY)) {
        return Error::system(errno, "Failed to configure BPF audit mode");
    }
    return {};
}

Result<void> ensure_layout_version(BpfState& state)
{
    if (!state.agent_meta) {
        return Error(ErrorCode::BpfMapOperationFailed, "Agent meta map not found");
    }

    uint32_t key = 0;
    AgentMeta meta{};
    int fd = bpf_map__fd(state.agent_meta);
    if (bpf_map_lookup_elem(fd, &key, &meta) && errno != ENOENT) {
        return Error::system(errno, "Failed to read agent_meta_map");
    }
    if (meta.layout_version == 0) {
        meta.layout_version = kLayoutVersion;
        if (bpf_map_update_elem(fd, &key, &meta, BPF_ANY)) {
            return Error::system(errno, "Failed to set agent layout version");
        }
        return {};
    }
    if (meta.layout_version != kLayoutVersion) {
        return Error(ErrorCode::LayoutVersionMismatch, "Pinned maps layout version mismatch",
                     "found " + std::to_string(meta.layout_version) + ", expected " + std::to_string(kLayoutVersion) +
                         ". Run 'sudo aegisbpf block clear' to reset pins.");
    }
    return {};
}

Result<void> set_exec_identity_flags(BpfState& state, uint8_t flags)
{
    if (!state.config_map) {
        return Error(ErrorCode::BpfMapOperationFailed, "Config map not found");
    }

    uint32_t key = 0;
    AgentConfig cfg{};
    int fd = bpf_map__fd(state.config_map);
    if (bpf_map_lookup_elem(fd, &key, &cfg)) {
        if (errno != ENOENT) {
            return Error::system(errno, "Failed to read agent config");
        }
        cfg = default_agent_config();
    }

    cfg.exec_identity_flags = flags;

    if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY)) {
        return Error::system(errno, "Failed to set exec identity flags");
    }
    return {};
}

Result<void> set_kernel_security_flags(BpfState& state, bool deny_ptrace, bool deny_module_load, bool deny_bpf)
{
    if (!state.config_map) {
        return Error(ErrorCode::BpfMapOperationFailed, "Config map not found");
    }

    uint32_t key = 0;
    AgentConfig cfg{};
    int fd = bpf_map__fd(state.config_map);
    if (bpf_map_lookup_elem(fd, &key, &cfg)) {
        if (errno != ENOENT) {
            return Error::system(errno, "Failed to read agent config");
        }
        cfg = default_agent_config();
    }

    cfg.deny_ptrace = deny_ptrace ? 1 : 0;
    cfg.deny_module_load = deny_module_load ? 1 : 0;
    cfg.deny_bpf = deny_bpf ? 1 : 0;

    if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY)) {
        return Error::system(errno, "Failed to set kernel security flags");
    }
    return {};
}

Result<void> set_agent_config_full(BpfState& state, const AgentConfig& config)
{
    if (!state.config_map) {
        return Error(ErrorCode::BpfMapOperationFailed, "Config map not found");
    }

    AgentConfig normalized = config;
    if (normalized.event_sample_rate == 0) {
        normalized.event_sample_rate = 1;
    }
    if (normalized.sigkill_escalation_threshold == 0) {
        normalized.sigkill_escalation_threshold = kSigkillEscalationThresholdDefault;
    }
    if (normalized.sigkill_escalation_window_seconds == 0) {
        normalized.sigkill_escalation_window_seconds = kSigkillEscalationWindowSecondsDefault;
    }

    uint32_t key = 0;
    AgentConfig existing{};
    int fd = bpf_map__fd(state.config_map);
    if (bpf_map_lookup_elem(fd, &key, &existing) == 0) {
        normalized.emergency_disable = existing.emergency_disable;
        normalized.exec_identity_flags = existing.exec_identity_flags;
    } else if (errno != ENOENT) {
        return Error::system(errno, "Failed to read agent config");
    }

    normalized.file_policy_empty = file_policy_maps_empty(state) ? 1 : 0;
    normalized.net_policy_empty = net_policy_maps_empty(state) ? 1 : 0;
    normalized.path_policy_empty = path_policy_map_empty(state) ? 1 : 0;
    if (normalized.exec_identity_flags & kExecIdentityFlagProtectConnect) {
        normalized.net_policy_empty = 0;
    }

    if (bpf_map_update_elem(fd, &key, &normalized, BPF_ANY)) {
        return Error::system(errno, "Failed to configure BPF agent config");
    }
    return {};
}

Result<void> set_emergency_disable(BpfState& state, bool disable)
{
    if (!state.config_map) {
        return Error(ErrorCode::BpfMapOperationFailed, "Config map not found");
    }

    uint32_t key = 0;
    AgentConfig cfg{};
    int fd = bpf_map__fd(state.config_map);

    if (bpf_map_lookup_elem(fd, &key, &cfg)) {
        if (errno != ENOENT) {
            return Error::system(errno, "Failed to read agent config");
        }
        cfg = default_agent_config();
    }

    cfg.emergency_disable = disable ? 1 : 0;

    if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY)) {
        return Error::system(errno, "Failed to set emergency disable");
    }
    return {};
}

Result<bool> read_emergency_disable(BpfState& state)
{
    if (!state.config_map) {
        return Error(ErrorCode::BpfMapOperationFailed, "Config map not found");
    }

    uint32_t key = 0;
    AgentConfig cfg{};
    int fd = bpf_map__fd(state.config_map);
    if (bpf_map_lookup_elem(fd, &key, &cfg) == 0) {
        return cfg.emergency_disable != 0;
    }
    if (errno == ENOENT) {
        return false;
    }
    return Error::system(errno, "Failed to read agent config");
}

Result<void> refresh_policy_empty_hints(BpfState& state)
{
    if (!state.config_map) {
        return Error(ErrorCode::BpfMapOperationFailed, "Config map not found");
    }

    const bool file_empty = file_policy_maps_empty(state);
    const bool net_empty = net_policy_maps_empty(state);

    uint32_t key = 0;
    AgentConfig cfg{};
    int fd = bpf_map__fd(state.config_map);
    if (bpf_map_lookup_elem(fd, &key, &cfg) && errno != ENOENT) {
        return Error::system(errno, "Failed to read agent config");
    }

    cfg.file_policy_empty = file_empty ? 1 : 0;
    cfg.net_policy_empty = net_empty ? 1 : 0;
    cfg.path_policy_empty = path_policy_map_empty(state) ? 1 : 0;
    if (cfg.exec_identity_flags & kExecIdentityFlagProtectConnect) {
        cfg.net_policy_empty = 0;
    }

    if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY)) {
        return Error::system(errno, "Failed to update policy empty hints");
    }
    return {};
}

Result<void> update_deadman_deadline(BpfState& state, uint64_t deadline_ns)
{
    if (!state.config_map) {
        return Error(ErrorCode::BpfMapOperationFailed, "Config map not found");
    }

    uint32_t key = 0;
    AgentConfig cfg{};
    int fd = bpf_map__fd(state.config_map);

    if (bpf_map_lookup_elem(fd, &key, &cfg)) {
        if (errno != ENOENT) {
            return Error::system(errno, "Failed to read agent config");
        }
        cfg = default_agent_config();
    }

    cfg.deadman_deadline_ns = deadline_ns;

    if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY)) {
        return Error::system(errno, "Failed to update deadman deadline");
    }
    return {};
}

Result<uint64_t> bump_policy_generation(BpfState& state)
{
    if (!state.config_map) {
        return Error(ErrorCode::BpfMapOperationFailed, "config_map not available");
    }

    int fd = bpf_map__fd(state.config_map);
    uint32_t key = 0;
    AgentConfig cfg{};
    if (bpf_map_lookup_elem(fd, &key, &cfg)) {
        return Error::system(errno, "Failed to read agent config for generation bump");
    }

    cfg.policy_generation += 1;

    if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY)) {
        return Error::system(errno, "Failed to write bumped policy generation");
    }

    return cfg.policy_generation;
}

Result<void> commit_policy_generation(BpfState& state, uint64_t generation)
{
    if (!state.policy_generation_map) {
        return {}; // map not present (older BPF object) — skip
    }

    int fd = bpf_map__fd(state.policy_generation_map);
    uint32_t key = 0;
    if (bpf_map_update_elem(fd, &key, &generation, BPF_ANY)) {
        return Error::system(errno, "Failed to commit policy generation to map");
    }
    return {};
}

} // namespace aegis
