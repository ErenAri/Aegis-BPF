// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <string>
#include <utility>
#include <vector>

#include "bpf_attach.hpp"
#include "bpf_config.hpp"
#include "bpf_integrity.hpp"
#include "bpf_maps.hpp"
#include "result.hpp"
#include "types.hpp"

namespace aegis {

/// One pinned LSM/tracepoint hook tracked alongside `BpfState::links` so
/// the heartbeat thread can verify the bpffs pin still exists. The `link`
/// pointer is **borrowed** — its lifetime is owned by `BpfState::links`
/// and freed by `cleanup_bpf()`; this struct does not own it.
struct PinnedHook {
    /// libbpf program name (`bpf_program__name()`), used both as the
    /// basename of the pin path and as a stable key for diagnostics.
    std::string program_name;

    /// Borrowed; do NOT destroy from this struct.
    bpf_link* link = nullptr;

    /// Absolute pin path, e.g. `/sys/fs/bpf/aegisbpf/handle_inode_permission`.
    std::string pin_path;
};

/**
 * Trivially-copyable BPF load state: every borrowed `bpf_map*` handle plus the
 * reuse-flag, attach-status, and pin-heal counters that travel with them.
 *
 * These are all **borrowed** (the maps are owned by `BpfState::obj`) or plain
 * value state, so they move by a single plain copy. Grouping them in this base
 * is deliberate: `BpfState`'s move only has to copy this base wholesale, so a
 * newly-added map or flag is moved automatically and can never be silently
 * dropped from the move path — the footgun behind the `policy_generation` and
 * `deny_comm` unpinned-map regressions. **Add new maps/flags here.**
 */
struct BpfMapState {
    // BPF maps (borrowed; owned by BpfState::obj)
    bpf_map* events = nullptr;
    bpf_map* deny_inode = nullptr;
    bpf_map* deny_path = nullptr;
    bpf_map* deny_comm = nullptr;
    bpf_map* allow_cgroup = nullptr;
    bpf_map* allow_exec_inode = nullptr;
    bpf_map* trusted_exec_hash = nullptr;
    bpf_map* exec_identity_mode = nullptr;
    bpf_map* block_stats = nullptr;
    bpf_map* deny_cgroup_stats = nullptr;
    bpf_map* deny_inode_stats = nullptr;
    bpf_map* deny_path_stats = nullptr;
    bpf_map* agent_meta = nullptr;
    bpf_map* config_map = nullptr;
    bpf_map* survival_allowlist = nullptr;
    bpf_map* policy_generation_map = nullptr;
    bpf_map* deny_cgroup_inode = nullptr;
    bpf_map* deny_cgroup_ipv4 = nullptr;
    bpf_map* deny_cgroup_port = nullptr;
    bpf_map* diagnostics = nullptr;
    bpf_map* dead_processes = nullptr;
    bpf_map* hook_latency = nullptr;
    bpf_map* event_approver_inode = nullptr;
    bpf_map* event_approver_path = nullptr;
    bpf_map* priority_events = nullptr;
    bpf_map* deny_ipv4 = nullptr;
    bpf_map* deny_ipv6 = nullptr;
    bpf_map* deny_port = nullptr;
    bpf_map* deny_ip_port_v4 = nullptr;
    bpf_map* deny_ip_port_v6 = nullptr;
    bpf_map* deny_cidr_v4 = nullptr;
    bpf_map* deny_cidr_v6 = nullptr;
    bpf_map* net_block_stats = nullptr;
    bpf_map* net_ip_stats = nullptr;
    bpf_map* net_port_stats = nullptr;
    bpf_map* backpressure = nullptr;

    // Pinned-link fail-safe config + heal counters (trivial value state; the
    // owning `pin_root`/`pinned_hooks` live in BpfState). See BpfState docs.
    bool enforce_pin_links = false;
    bool enable_pin_heal = false;
    uint64_t pin_heal_attempts = 0;
    uint64_t pin_heal_successes = 0;
    uint64_t pin_heal_failures = 0;

    // Reuse flags: set when the corresponding map was reused from a bpffs pin
    // (vs freshly created). Drives the need_pins decision in load_bpf.
    bool inode_reused = false;
    bool deny_path_reused = false;
    bool deny_comm_reused = false;
    bool cgroup_reused = false;
    bool allow_exec_inode_reused = false;
    bool trusted_exec_hash_reused = false;
    bool exec_identity_mode_reused = false;
    bool block_stats_reused = false;
    bool deny_cgroup_stats_reused = false;
    bool deny_inode_stats_reused = false;
    bool deny_path_stats_reused = false;
    bool agent_meta_reused = false;
    bool config_map_reused = false;
    bool policy_generation_reused = false;
    bool survival_allowlist_reused = false;
    bool deny_ipv4_reused = false;
    bool deny_ipv6_reused = false;
    bool deny_port_reused = false;
    bool deny_ip_port_v4_reused = false;
    bool deny_ip_port_v6_reused = false;
    bool deny_cidr_v4_reused = false;
    bool deny_cidr_v6_reused = false;
    bool net_block_stats_reused = false;
    bool net_ip_stats_reused = false;
    bool net_port_stats_reused = false;

    // Attach contract summary for post-attach safety validation.
    bool attach_contract_valid = false;
    uint8_t file_hooks_expected = 0;
    uint8_t file_hooks_attached = 0;
    bool exec_identity_hook_attached = false;
    bool exec_identity_runtime_deps_hook_attached = false;
    bool socket_connect_hook_attached = false;
    bool socket_bind_hook_attached = false;
    bool socket_listen_hook_attached = false;
    bool socket_accept_hook_attached = false;
    bool socket_sendmsg_hook_attached = false;
    bool socket_recvmsg_hook_attached = false;
    bool ptrace_hook_attached = false;
    bool module_load_hook_attached = false;
    bool bpf_hook_attached = false;
    bool overlay_copy_up_hook_attached = false;
    bool ima_hook_attached = false;
};

/**
 * RAII wrapper for BPF state
 *
 * Automatically cleans up BPF resources (links, object) when destroyed.
 * Non-copyable but movable. The borrowed map handles and trivially-copyable
 * flags live in the `BpfMapState` base; only the *owning* members (`obj`,
 * `links`, `pin_root`, `pinned_hooks`) need explicit move handling here.
 */
class BpfState : public BpfMapState {
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
            // All borrowed map handles + reuse/attach flags + counters are in
            // the BpfMapState base and are trivially copyable: one assignment
            // moves every one of them, so a newly-added map/flag is a single
            // edit to BpfMapState and can never be silently dropped from the
            // move path. Owning members are moved explicitly below.
            static_cast<BpfMapState&>(*this) = static_cast<const BpfMapState&>(other);
            obj = other.obj;
            links = std::move(other.links);
            pin_root = std::move(other.pin_root);
            pinned_hooks = std::move(other.pinned_hooks);

            // Reset the source so its destructor/cleanup is a no-op.
            static_cast<BpfMapState&>(other) = BpfMapState{};
            other.obj = nullptr;
            other.links.clear();
            other.pinned_hooks.clear();
        }
        return *this;
    }

    // Check if loaded successfully
    [[nodiscard]] bool is_loaded() const { return obj != nullptr; }
    [[nodiscard]] explicit operator bool() const { return is_loaded(); }

    // Cleanup resources
    void cleanup();

    // ------------------------------------------------------------------
    // Owning members (everything that holds a resource and needs explicit
    // move/cleanup). Borrowed maps + value flags are in the BpfMapState base.
    // ------------------------------------------------------------------
    bpf_object* obj = nullptr;
    std::vector<bpf_link*> links;

    // ------------------------------------------------------------------
    // Pinned-link fail-safe (gated by `enforce_pin_links`, default OFF)
    // ------------------------------------------------------------------
    // When `enforce_pin_links` is true, each successful attach in
    // `attach_prog()` is immediately pinned at
    // `<pin_root>/<program_name>` inside bpffs. This keeps LSM hooks
    // active even if `aegisbpfd` segfaults / is OOM-killed, so a hostile
    // process cannot disable enforcement just by killing the daemon.
    //
    // `pinned_hooks` records each pin so the heartbeat thread can
    // periodically verify the pin still exists. The `enforce_pin_links`,
    // `enable_pin_heal`, and `pin_heal_*` flags/counters live in the
    // BpfMapState base (trivial value state).
    std::string pin_root; // populated only when enforce_pin_links is true
    std::vector<PinnedHook> pinned_hooks;
};

// BPF loading and lifecycle
/**
 * One entry in the optional-LSM-hook autoload-gating catalog.
 *
 * `hook_name` is the bare hook symbol (matches the keys passed to
 * `disable_optional_program(...)` and the keys used internally by
 * `detect_missing_optional_lsm_hooks`).
 *
 * `btf_symbol` is the `bpf_lsm_<hook>` trampoline FUNC entry that
 * actually appears in vmlinux BTF and that the BPF-LSM attach path
 * binds to. The two names diverge for `mmap_file` (kernel hook
 * renamed from `file_mmap` pre-5.6); the catalog records the rename
 * explicitly so it can be unit-tested against `hook_capabilities.cpp`.
 */
struct OptionalLsmHookSpec {
    std::string hook_name;
    std::string btf_symbol;
};

/**
 * Catalog of optional LSM hooks that AegisBPF gates via
 * `bpf_program__set_autoload(false)` when the kernel does not expose
 * the matching `bpf_lsm_<hook>` trampoline. Returned by-value so
 * tests can pin the catalog shape without reaching into TU-private
 * state.
 */
std::vector<OptionalLsmHookSpec> optional_lsm_hook_catalog();

Result<void> load_bpf(bool reuse_pins, bool attach_links, BpfState& state);
void set_ringbuf_bytes(uint32_t bytes);
void set_max_deny_inodes(uint32_t count);
void set_max_deny_paths(uint32_t count);
void set_max_network_entries(uint32_t count);
void cleanup_bpf(BpfState& state);

// Map operations
Result<void> reuse_pinned_map(bpf_map* map, const char* path, bool& reused);
Result<void> pin_map(bpf_map* map, const char* path);

// Stats operations
Result<BlockStats> read_block_stats_map(bpf_map* map);
Result<std::vector<std::pair<uint64_t, uint64_t>>> read_cgroup_block_counts(bpf_map* map);
Result<std::vector<std::pair<InodeId, uint64_t>>> read_inode_block_counts(bpf_map* map);
Result<std::vector<std::pair<std::string, uint64_t>>> read_path_block_counts(bpf_map* map);
Result<std::vector<uint64_t>> read_allow_cgroup_ids(bpf_map* map);
Result<void> reset_block_stats_map(bpf_map* map);

// Backpressure telemetry (aggregates per-CPU PERCPU_ARRAY counters)
Result<BackpressureStats> read_backpressure_stats(BpfState& state);

// Hook latency telemetry (reads PERCPU_ARRAY and aggregates per hook)
Result<std::vector<std::pair<uint32_t, HookLatencyEntry>>> read_hook_latency_entries(BpfState& state);

// Survival allowlist operations
Result<void> populate_survival_allowlist(BpfState& state);
Result<void> add_survival_entry(BpfState& state, const InodeId& id);
Result<std::vector<InodeId>> read_survival_allowlist(BpfState& state);

// Deny/allow operations
Result<void> add_deny_inode(BpfState& state, const InodeId& id, DenyEntries& entries);
Result<void> add_deny_path(BpfState& state, const std::string& path, DenyEntries& entries);
Result<void> add_allow_cgroup(BpfState& state, uint64_t cgid);
Result<void> add_allow_cgroup_path(BpfState& state, const std::string& path);
Result<void> add_allow_exec_inode(BpfState& state, const InodeId& id);
Result<void> set_exec_identity_mode(BpfState& state, bool enabled);

// Access-control rules share the deny maps; the value is a bitmask.
// - kRuleFlagDenyAlways: unconditional deny
// - kRuleFlagProtectByVerifiedExec: deny only when process is not VERIFIED_EXEC
Result<void> add_rule_inode_to_fd(int inode_fd, const InodeId& id, uint8_t flags, DenyEntries& entries);
Result<void> add_rule_path_to_fds(int inode_fd, int path_fd, const std::string& path, uint8_t flags,
                                  DenyEntries& entries);

// FD-accepting overloads for shadow map population
Result<void> add_deny_inode_to_fd(int inode_fd, const InodeId& id, DenyEntries& entries);
Result<void> add_deny_path_to_fds(int inode_fd, int path_fd, const std::string& path, DenyEntries& entries);
Result<void> add_allow_cgroup_to_fd(int cgroup_fd, uint64_t cgid);
Result<void> add_allow_cgroup_path_to_fd(int cgroup_fd, const std::string& path);
Result<void> add_allow_exec_inode_to_fd(int allow_exec_inode_fd, const InodeId& id);
Result<void> add_deny_comm_to_fd(int deny_comm_fd, const std::string& comm);

// Cgroup-scoped deny operations (FD-based for shadow or live maps)
Result<void> add_cgroup_deny_inode_to_fd(int map_fd, uint64_t cgid, const InodeId& inode);
Result<void> add_cgroup_deny_ipv4_to_fd(int map_fd, uint64_t cgid, const std::string& ip);
Result<void> add_cgroup_deny_port_to_fd(int map_fd, uint64_t cgid, const PortRule& rule);
// Resolve a cgroup identifier (path or "cgid:<N>") to a numeric cgroup ID.
Result<uint64_t> resolve_cgroup_identifier(const std::string& cgroup_str);

// System checks
bool kernel_bpf_lsm_enabled();
Result<void> bump_memlock_rlimit();
Result<void> ensure_pin_dir();
Result<void> ensure_db_dir();
Result<bool> check_prereqs();

// RAII wrapper for ring_buffer
class RingBufferGuard {
  public:
    explicit RingBufferGuard(ring_buffer* rb) : rb_(rb) {}
    ~RingBufferGuard()
    {
        if (rb_)
            ring_buffer__free(rb_);
    }

    RingBufferGuard(const RingBufferGuard&) = delete;
    RingBufferGuard& operator=(const RingBufferGuard&) = delete;

    RingBufferGuard(RingBufferGuard&& other) noexcept : rb_(other.rb_) { other.rb_ = nullptr; }
    RingBufferGuard& operator=(RingBufferGuard&& other) noexcept
    {
        if (this != &other) {
            if (rb_)
                ring_buffer__free(rb_);
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

} // namespace aegis
