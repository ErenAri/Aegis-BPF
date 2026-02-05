// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include "result.hpp"
#include "types.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <string>
#include <utility>
#include <vector>

namespace aegis {

/**
 * RAII wrapper for BPF state
 *
 * Automatically cleans up BPF resources (links, object) when destroyed.
 * Non-copyable but movable.
 */
class BpfState {
  public:
    BpfState() = default;
    ~BpfState() { cleanup(); }

    // Non-copyable
    BpfState(const BpfState&) = delete;
    BpfState& operator=(const BpfState&) = delete;

    // Movable
    BpfState(BpfState&& other) noexcept { *this = std::move(other); }
    BpfState& operator=(BpfState&& other) noexcept
    {
        if (this != &other) {
            cleanup();
            obj = other.obj;
            events = other.events;
            deny_inode = other.deny_inode;
            deny_path = other.deny_path;
            allow_cgroup = other.allow_cgroup;
            block_stats = other.block_stats;
            deny_cgroup_stats = other.deny_cgroup_stats;
            deny_inode_stats = other.deny_inode_stats;
            deny_path_stats = other.deny_path_stats;
            agent_meta = other.agent_meta;
            config_map = other.config_map;
            survival_allowlist = other.survival_allowlist;
            links = std::move(other.links);
            inode_reused = other.inode_reused;
            deny_path_reused = other.deny_path_reused;
            cgroup_reused = other.cgroup_reused;
            block_stats_reused = other.block_stats_reused;
            deny_cgroup_stats_reused = other.deny_cgroup_stats_reused;
            deny_inode_stats_reused = other.deny_inode_stats_reused;
            deny_path_stats_reused = other.deny_path_stats_reused;
            agent_meta_reused = other.agent_meta_reused;
            survival_allowlist_reused = other.survival_allowlist_reused;

            // Network maps
            deny_ipv4 = other.deny_ipv4;
            deny_ipv6 = other.deny_ipv6;
            deny_port = other.deny_port;
            deny_cidr_v4 = other.deny_cidr_v4;
            deny_cidr_v6 = other.deny_cidr_v6;
            net_block_stats = other.net_block_stats;
            net_ip_stats = other.net_ip_stats;
            net_port_stats = other.net_port_stats;
            deny_ipv4_reused = other.deny_ipv4_reused;
            deny_ipv6_reused = other.deny_ipv6_reused;
            deny_port_reused = other.deny_port_reused;
            deny_cidr_v4_reused = other.deny_cidr_v4_reused;
            deny_cidr_v6_reused = other.deny_cidr_v6_reused;
            net_block_stats_reused = other.net_block_stats_reused;
            net_ip_stats_reused = other.net_ip_stats_reused;
            net_port_stats_reused = other.net_port_stats_reused;
            attach_contract_valid = other.attach_contract_valid;
            file_hooks_expected = other.file_hooks_expected;
            file_hooks_attached = other.file_hooks_attached;

            // Reset other to prevent double-free
            other.obj = nullptr;
            other.survival_allowlist = nullptr;
            other.deny_ipv4 = nullptr;
            other.deny_ipv6 = nullptr;
            other.deny_port = nullptr;
            other.deny_cidr_v4 = nullptr;
            other.deny_cidr_v6 = nullptr;
            other.net_block_stats = nullptr;
            other.net_ip_stats = nullptr;
            other.net_port_stats = nullptr;
            other.attach_contract_valid = false;
            other.file_hooks_expected = 0;
            other.file_hooks_attached = 0;
            other.links.clear();
        }
        return *this;
    }

    // Check if loaded successfully
    [[nodiscard]] bool is_loaded() const { return obj != nullptr; }
    [[nodiscard]] explicit operator bool() const { return is_loaded(); }

    // Cleanup resources
    void cleanup();

    // BPF object and maps
    bpf_object* obj = nullptr;
    bpf_map* events = nullptr;
    bpf_map* deny_inode = nullptr;
    bpf_map* deny_path = nullptr;
    bpf_map* allow_cgroup = nullptr;
    bpf_map* block_stats = nullptr;
    bpf_map* deny_cgroup_stats = nullptr;
    bpf_map* deny_inode_stats = nullptr;
    bpf_map* deny_path_stats = nullptr;
    bpf_map* agent_meta = nullptr;
    bpf_map* config_map = nullptr;
    std::vector<bpf_link*> links;

    // Reuse flags
    bool inode_reused = false;
    bool deny_path_reused = false;
    bool cgroup_reused = false;
    bool block_stats_reused = false;
    bool deny_cgroup_stats_reused = false;
    bool deny_inode_stats_reused = false;
    bool deny_path_stats_reused = false;
    bool agent_meta_reused = false;
    bool survival_allowlist_reused = false;

    // Survival allowlist map
    bpf_map* survival_allowlist = nullptr;

    // Network maps
    bpf_map* deny_ipv4 = nullptr;
    bpf_map* deny_ipv6 = nullptr;
    bpf_map* deny_port = nullptr;
    bpf_map* deny_cidr_v4 = nullptr;
    bpf_map* deny_cidr_v6 = nullptr;
    bpf_map* net_block_stats = nullptr;
    bpf_map* net_ip_stats = nullptr;
    bpf_map* net_port_stats = nullptr;

    // Network reuse flags
    bool deny_ipv4_reused = false;
    bool deny_ipv6_reused = false;
    bool deny_port_reused = false;
    bool deny_cidr_v4_reused = false;
    bool deny_cidr_v6_reused = false;
    bool net_block_stats_reused = false;
    bool net_ip_stats_reused = false;
    bool net_port_stats_reused = false;

    // Attach contract summary for post-attach safety validation.
    bool attach_contract_valid = false;
    uint8_t file_hooks_expected = 0;
    uint8_t file_hooks_attached = 0;
};

// BPF loading and lifecycle
Result<void> load_bpf(bool reuse_pins, bool attach_links, BpfState& state);
Result<void> attach_all(BpfState& state, bool lsm_enabled, bool use_inode_permission, bool use_file_open);
void set_ringbuf_bytes(uint32_t bytes);
void cleanup_bpf(BpfState& state);

// Map operations
Result<void> reuse_pinned_map(bpf_map* map, const char* path, bool& reused);
Result<void> pin_map(bpf_map* map, const char* path);
size_t map_entry_count(bpf_map* map);
Result<void> clear_map_entries(bpf_map* map);

// Stats operations
Result<BlockStats> read_block_stats_map(bpf_map* map);
Result<std::vector<std::pair<uint64_t, uint64_t>>> read_cgroup_block_counts(bpf_map* map);
Result<std::vector<std::pair<InodeId, uint64_t>>> read_inode_block_counts(bpf_map* map);
Result<std::vector<std::pair<std::string, uint64_t>>> read_path_block_counts(bpf_map* map);
Result<std::vector<uint64_t>> read_allow_cgroup_ids(bpf_map* map);
Result<void> reset_block_stats_map(bpf_map* map);

// Configuration
Result<void> set_agent_config(BpfState& state, bool audit_only);
Result<void> set_agent_config_full(BpfState& state, const AgentConfig& config);
Result<void> update_deadman_deadline(BpfState& state, uint64_t deadline_ns);
Result<void> ensure_layout_version(BpfState& state);

// Survival allowlist operations
Result<void> populate_survival_allowlist(BpfState& state);
Result<void> add_survival_entry(BpfState& state, const InodeId& id);
Result<std::vector<InodeId>> read_survival_allowlist(BpfState& state);

// Deny/allow operations
Result<void> add_deny_inode(BpfState& state, const InodeId& id, DenyEntries& entries);
Result<void> add_deny_path(BpfState& state, const std::string& path, DenyEntries& entries);
Result<void> add_allow_cgroup(BpfState& state, uint64_t cgid);
Result<void> add_allow_cgroup_path(BpfState& state, const std::string& path);

// System checks
bool kernel_bpf_lsm_enabled();
Result<void> bump_memlock_rlimit();
Result<void> ensure_pin_dir();
Result<void> ensure_db_dir();
Result<bool> check_prereqs();

// BPF object path resolution
std::string resolve_bpf_obj_path();

// RAII wrapper for ring_buffer
class RingBufferGuard {
  public:
    explicit RingBufferGuard(ring_buffer* rb) : rb_(rb) {}
    ~RingBufferGuard()
    {
        if (rb_) ring_buffer__free(rb_);
    }

    RingBufferGuard(const RingBufferGuard&) = delete;
    RingBufferGuard& operator=(const RingBufferGuard&) = delete;

    RingBufferGuard(RingBufferGuard&& other) noexcept : rb_(other.rb_) { other.rb_ = nullptr; }
    RingBufferGuard& operator=(RingBufferGuard&& other) noexcept
    {
        if (this != &other) {
            if (rb_) ring_buffer__free(rb_);
            rb_ = other.rb_;
            other.rb_ = nullptr;
        }
        return *this;
    }

    [[nodiscard]] ring_buffer* get() const { return rb_; }
    [[nodiscard]] explicit operator bool() const { return rb_ != nullptr; }

    // cppcheck-suppress unusedFunction
    ring_buffer* release()
    {
        ring_buffer* tmp = rb_;
        rb_ = nullptr;
        return tmp;
    }

  private:
    ring_buffer* rb_;
};

}  // namespace aegis
