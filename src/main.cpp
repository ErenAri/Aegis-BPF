/*
 * AegisBPF - eBPF-based runtime security agent
 *
 * Main entry point for the userspace daemon and CLI commands.
 */

#include "bpf_ops.hpp"
#include "crypto.hpp"
#include "events.hpp"
#include "kernel_features.hpp"
#include "logging.hpp"
#include "policy.hpp"
#include "seccomp.hpp"
#include "sha256.hpp"
#include "types.hpp"
#include "utils.hpp"

#include <bpf/libbpf.h>
#include <atomic>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

namespace aegis {

static volatile sig_atomic_t g_exiting = 0;
static std::atomic<bool> g_heartbeat_running{false};

enum class LsmHookMode {
    FileOpen,
    InodePermission,
    Both
};

static const char* lsm_hook_name(LsmHookMode mode)
{
    switch (mode) {
    case LsmHookMode::FileOpen:
        return "file_open";
    case LsmHookMode::InodePermission:
        return "inode_permission";
    case LsmHookMode::Both:
        return "both";
    default:
        return "unknown";
    }
}

static bool parse_lsm_hook(const std::string& value, LsmHookMode& out)
{
    if (value == "file" || value == "file_open") {
        out = LsmHookMode::FileOpen;
        return true;
    }
    if (value == "inode" || value == "inode_permission") {
        out = LsmHookMode::InodePermission;
        return true;
    }
    if (value == "both") {
        out = LsmHookMode::Both;
        return true;
    }
    return false;
}

static void handle_signal(int)
{
    g_exiting = 1;
}

// Heartbeat thread for deadman switch - updates deadline every TTL/2
static void heartbeat_thread(BpfState* state, uint32_t ttl_seconds)
{
    uint32_t sleep_interval = ttl_seconds / 2;
    if (sleep_interval < 1) {
        sleep_interval = 1;
    }

    while (g_heartbeat_running.load() && !g_exiting) {
        // Calculate new deadline
        struct timespec ts{};
        clock_gettime(CLOCK_BOOTTIME, &ts);
        uint64_t now_ns = static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec);
        uint64_t new_deadline = now_ns + (static_cast<uint64_t>(ttl_seconds) * 1000000000ULL);

        auto result = update_deadman_deadline(*state, new_deadline);
        if (!result) {
            logger().log(SLOG_WARN("Failed to update deadman deadline")
                             .field("error", result.error().to_string()));
        }

        // Sleep for TTL/2, but check exit flag more frequently
        for (uint32_t i = 0; i < sleep_interval && g_heartbeat_running.load() && !g_exiting; ++i) {
            sleep(1);
        }
    }
}

static Result<void> setup_agent_cgroup(BpfState& state)
{
    static constexpr const char* kAgentCgroup = "/sys/fs/cgroup/aegis_agent";

    std::error_code ec;
    std::filesystem::create_directories(kAgentCgroup, ec);
    if (ec) {
        return Error(ErrorCode::IoError, "Failed to create cgroup", ec.message());
    }

    std::ofstream procs(std::string(kAgentCgroup) + "/cgroup.procs", std::ios::out | std::ios::trunc);
    if (!procs.is_open()) {
        return Error(ErrorCode::IoError, "Failed to open cgroup.procs", kAgentCgroup);
    }
    procs << getpid();
    procs.close();

    struct stat st{};
    if (stat(kAgentCgroup, &st) != 0) {
        return Error::system(errno, "stat failed for " + std::string(kAgentCgroup));
    }

    uint64_t cgid = static_cast<uint64_t>(st.st_ino);

    TRY(bump_memlock_rlimit());

    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.allow_cgroup), &cgid, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update allow_cgroup_map");
    }

    return {};
}

static int run(bool audit_only,
               bool enable_seccomp,
               uint32_t deadman_ttl,
               LsmHookMode lsm_hook,
               uint32_t ringbuf_bytes,
               uint32_t event_sample_rate)
{
    // Check for break-glass mode FIRST
    bool break_glass_active = detect_break_glass();
    if (break_glass_active) {
        logger().log(SLOG_WARN("Break-glass mode detected - forcing audit-only mode"));
        audit_only = true;
    }

    // Detect kernel features for graceful degradation
    auto features_result = detect_kernel_features();
    if (!features_result) {
        logger().log(SLOG_ERROR("Failed to detect kernel features")
                         .field("error", features_result.error().to_string()));
        return 1;
    }
    KernelFeatures features = *features_result;

    // Determine enforcement capability
    EnforcementCapability cap = determine_capability(features);
    logger().log(SLOG_INFO("Kernel feature detection complete")
                     .field("kernel_version", features.kernel_version)
                     .field("capability", capability_name(cap))
                     .field("bpf_lsm", features.bpf_lsm)
                     .field("cgroup_v2", features.cgroup_v2)
                     .field("btf", features.btf)
                     .field("ringbuf", features.ringbuf));

    // Handle capability-based decisions
    if (cap == EnforcementCapability::Disabled) {
        logger().log(SLOG_ERROR("Cannot run AegisBPF on this system")
                         .field("explanation", capability_explanation(features, cap)));
        return 1;
    }

    bool lsm_enabled = features.bpf_lsm;

    if (cap == EnforcementCapability::AuditOnly) {
        if (!audit_only) {
            logger().log(SLOG_WARN("Full enforcement not available; falling back to audit-only mode")
                             .field("explanation", capability_explanation(features, cap)));
            audit_only = true;
        }
        else {
            logger().log(SLOG_INFO("Running in audit-only mode")
                             .field("explanation", capability_explanation(features, cap)));
        }
    }

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit")
                         .field("error", rlimit_result.error().to_string()));
        return 1;
    }

    if (ringbuf_bytes > 0) {
        set_ringbuf_bytes(ringbuf_bytes);
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    auto version_result = ensure_layout_version(state);
    if (!version_result) {
        logger().log(SLOG_ERROR("Layout version check failed")
                         .field("error", version_result.error().to_string()));
        return 1;
    }

    // Set up full agent config with deadman switch and break-glass
    AgentConfig config{};
    config.audit_only = audit_only ? 1 : 0;
    config.break_glass_active = break_glass_active ? 1 : 0;
    config.deadman_enabled = (deadman_ttl > 0) ? 1 : 0;
    config.deadman_ttl_seconds = deadman_ttl;
    config.event_sample_rate = event_sample_rate ? event_sample_rate : 1;
    if (config.deadman_enabled) {
        // Set initial deadline to now + TTL
        struct timespec ts{};
        clock_gettime(CLOCK_BOOTTIME, &ts);
        uint64_t now_ns = static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec);
        config.deadman_deadline_ns = now_ns + (static_cast<uint64_t>(deadman_ttl) * 1000000000ULL);
    }

    auto config_result = set_agent_config_full(state, config);
    if (!config_result) {
        logger().log(SLOG_ERROR("Failed to set agent config")
                         .field("error", config_result.error().to_string()));
        return 1;
    }

    // Populate survival allowlist with critical binaries
    auto survival_result = populate_survival_allowlist(state);
    if (!survival_result) {
        logger().log(SLOG_WARN("Failed to populate survival allowlist")
                         .field("error", survival_result.error().to_string()));
        // Not fatal - continue with startup
    }

    auto cgroup_result = setup_agent_cgroup(state);
    if (!cgroup_result) {
        logger().log(SLOG_ERROR("Failed to setup agent cgroup")
                         .field("error", cgroup_result.error().to_string()));
        return 1;
    }

    bool use_inode_permission = (lsm_hook == LsmHookMode::Both || lsm_hook == LsmHookMode::InodePermission);
    bool use_file_open = (lsm_hook == LsmHookMode::Both || lsm_hook == LsmHookMode::FileOpen);
    auto attach_result = attach_all(state, lsm_enabled, use_inode_permission, use_file_open);
    if (!attach_result) {
        logger().log(SLOG_ERROR("Failed to attach programs")
                         .field("error", attach_result.error().to_string()));
        return 1;
    }

    RingBufferGuard rb(ring_buffer__new(bpf_map__fd(state.events), handle_event, nullptr, nullptr));
    if (!rb) {
        logger().log(SLOG_ERROR("Failed to create ring buffer"));
        return 1;
    }

    // Apply seccomp filter after all initialization is complete
    if (enable_seccomp) {
        auto seccomp_result = apply_seccomp_filter();
        if (!seccomp_result) {
            logger().log(SLOG_ERROR("Failed to apply seccomp filter")
                             .field("error", seccomp_result.error().to_string()));
            return 1;
        }
    }

    logger().log(SLOG_INFO("Agent started")
                     .field("audit_only", audit_only)
                     .field("lsm_enabled", lsm_enabled)
                     .field("lsm_hook", lsm_hook_name(lsm_hook))
                     .field("event_sample_rate", static_cast<int64_t>(config.event_sample_rate))
                     .field("ringbuf_bytes", static_cast<int64_t>(ringbuf_bytes))
                     .field("seccomp", enable_seccomp)
                     .field("break_glass", break_glass_active)
                     .field("deadman_ttl", static_cast<int64_t>(deadman_ttl)));

    // Start heartbeat thread if deadman switch is enabled
    std::thread heartbeat;
    if (deadman_ttl > 0) {
        g_heartbeat_running.store(true);
        heartbeat = std::thread(heartbeat_thread, &state, deadman_ttl);
        logger().log(SLOG_INFO("Deadman switch heartbeat started")
                         .field("ttl_seconds", static_cast<int64_t>(deadman_ttl)));
    }

    int err = 0;
    while (!g_exiting) {
        err = ring_buffer__poll(rb.get(), 250);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            logger().log(SLOG_ERROR("Ring buffer poll failed").error_code(-err));
            break;
        }
    }

    // Stop heartbeat thread
    if (deadman_ttl > 0 && heartbeat.joinable()) {
        g_heartbeat_running.store(false);
        heartbeat.join();
    }

    logger().log(SLOG_INFO("Agent stopped"));
    return err < 0 ? 1 : 0;
}

static int block_file(const std::string& path)
{
    // Validate path before processing
    auto validated = validate_existing_path(path);
    if (!validated) {
        logger().log(SLOG_ERROR("Invalid path").field("error", validated.error().to_string()));
        return 1;
    }

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit")
                         .field("error", rlimit_result.error().to_string()));
        return 1;
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    auto entries = read_deny_db();
    auto add_result = add_deny_path(state, *validated, entries);
    if (!add_result) {
        logger().log(SLOG_ERROR("Failed to add deny path")
                         .field("error", add_result.error().to_string()));
        return 1;
    }

    auto write_result = write_deny_db(entries);
    if (!write_result) {
        logger().log(SLOG_ERROR("Failed to write deny database")
                         .field("error", write_result.error().to_string()));
        return 1;
    }

    return 0;
}

static int block_add(const std::string& path)
{
    return block_file(path);
}

static int block_del(const std::string& path)
{
    auto inode_result = path_to_inode(path);
    if (!inode_result) {
        logger().log(SLOG_ERROR("Failed to get inode")
                         .field("error", inode_result.error().to_string()));
        return 1;
    }
    InodeId id = *inode_result;

    int map_fd = bpf_obj_get(kDenyInodePin);
    if (map_fd < 0) {
        logger().log(SLOG_ERROR("deny_inode_map not found"));
        return 1;
    }
    bpf_map_delete_elem(map_fd, &id);
    close(map_fd);

    std::error_code ec;
    std::filesystem::path resolved = std::filesystem::canonical(path, ec);
    std::string resolved_path = ec ? path : resolved.string();
    PathKey path_key{};
    fill_path_key(resolved_path, path_key);
    int path_fd = bpf_obj_get(kDenyPathPin);
    if (path_fd >= 0) {
        bpf_map_delete_elem(path_fd, &path_key);
        if (resolved_path != path) {
            PathKey raw_key{};
            fill_path_key(path, raw_key);
            bpf_map_delete_elem(path_fd, &raw_key);
        }
        close(path_fd);
    }
    else {
        logger().log(SLOG_WARN("deny_path_map not found"));
    }

    auto entries = read_deny_db();
    entries.erase(id);
    auto write_result = write_deny_db(entries);
    if (!write_result) {
        logger().log(SLOG_ERROR("Failed to write deny database")
                         .field("error", write_result.error().to_string()));
        return 1;
    }
    return 0;
}

static int block_list()
{
    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    auto db = read_deny_db();
    InodeId key{};
    InodeId next_key{};
    int rc = bpf_map_get_next_key(bpf_map__fd(state.deny_inode), nullptr, &key);
    while (!rc) {
        auto it = db.find(key);
        if (it != db.end() && !it->second.empty()) {
            std::cout << it->second << " (" << inode_to_string(key) << ")" << std::endl;
        }
        else {
            std::cout << inode_to_string(key) << std::endl;
        }
        rc = bpf_map_get_next_key(bpf_map__fd(state.deny_inode), &key, &next_key);
        key = next_key;
    }

    return 0;
}

static int block_clear()
{
    std::remove(kDenyInodePin);
    std::remove(kDenyPathPin);
    std::remove(kAllowCgroupPin);
    std::remove(kDenyCgroupStatsPin);
    std::remove(kDenyInodeStatsPin);
    std::remove(kDenyPathStatsPin);
    std::remove(kAgentMetaPin);
    std::remove(kSurvivalAllowlistPin);
    std::filesystem::remove(kDenyDbPath);
    std::filesystem::remove(kPolicyAppliedPath);
    std::filesystem::remove(kPolicyAppliedPrevPath);
    std::filesystem::remove(kPolicyAppliedHashPath);

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit")
                         .field("error", rlimit_result.error().to_string()));
        return 1;
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to reload BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }
    if (state.block_stats) {
        auto reset_result = reset_block_stats_map(state.block_stats);
        if (!reset_result) {
            logger().log(SLOG_WARN("Failed to reset block stats")
                             .field("error", reset_result.error().to_string()));
        }
    }
    return 0;
}

static int allow_add(const std::string& path)
{
    // Validate cgroup path
    auto validated = validate_cgroup_path(path);
    if (!validated) {
        logger().log(SLOG_ERROR("Invalid cgroup path").field("error", validated.error().to_string()));
        return 1;
    }

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit")
                         .field("error", rlimit_result.error().to_string()));
        return 1;
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    auto add_result = add_allow_cgroup_path(state, *validated);
    if (!add_result) {
        logger().log(SLOG_ERROR("Failed to add allow cgroup")
                         .field("error", add_result.error().to_string()));
        return 1;
    }

    return 0;
}

static int allow_del(const std::string& path)
{
    auto cgid_result = path_to_cgid(path);
    if (!cgid_result) {
        logger().log(SLOG_ERROR("Failed to get cgroup ID")
                         .field("error", cgid_result.error().to_string()));
        return 1;
    }
    uint64_t cgid = *cgid_result;

    int fd = bpf_obj_get(kAllowCgroupPin);
    if (fd < 0) {
        logger().log(SLOG_ERROR("allow_cgroup_map not found"));
        return 1;
    }
    bpf_map_delete_elem(fd, &cgid);
    close(fd);
    return 0;
}

static int allow_list()
{
    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    auto ids_result = read_allow_cgroup_ids(state.allow_cgroup);
    if (!ids_result) {
        logger().log(SLOG_ERROR("Failed to read allow cgroup IDs")
                         .field("error", ids_result.error().to_string()));
        return 1;
    }

    for (uint64_t id : *ids_result) {
        std::cout << id << std::endl;
    }

    return 0;
}

static int survival_list()
{
    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    auto entries_result = read_survival_allowlist(state);
    if (!entries_result) {
        logger().log(SLOG_ERROR("Failed to read survival allowlist")
                         .field("error", entries_result.error().to_string()));
        return 1;
    }

    auto entries = *entries_result;
    if (entries.empty()) {
        std::cout << "Survival allowlist is empty" << std::endl;
        return 0;
    }

    std::cout << "Survival allowlist entries: " << entries.size() << std::endl;
    for (const auto& id : entries) {
        std::cout << "  " << inode_to_string(id) << std::endl;
    }
    return 0;
}

static int survival_verify()
{
    // List of critical binaries that should be in the survival allowlist
    static const char* binaries[] = {
        "/sbin/init",
        "/lib/systemd/systemd",
        "/usr/lib/systemd/systemd",
        "/usr/bin/kubelet",
        "/usr/local/bin/kubelet",
        "/usr/sbin/sshd",
        "/usr/bin/ssh",
        "/usr/bin/containerd",
        "/usr/bin/runc",
        "/usr/bin/dockerd",
        "/usr/bin/sudo",
        "/bin/bash",
        "/usr/bin/bash",
        "/bin/sh",
        nullptr};

    std::cout << "Verifying critical binaries exist on system:" << std::endl;
    int found = 0;
    int missing = 0;

    for (int i = 0; binaries[i] != nullptr; ++i) {
        struct stat st{};
        if (stat(binaries[i], &st) == 0) {
            std::cout << "  [OK] " << binaries[i] << " (" << encode_dev(st.st_dev) << ":" << st.st_ino << ")"
                      << std::endl;
            ++found;
        }
        else {
            std::cout << "  [--] " << binaries[i] << " (not found)" << std::endl;
            ++missing;
        }
    }

    std::cout << "\nFound: " << found << ", Missing: " << missing << std::endl;
    return 0;
}

static int keys_list()
{
    auto keys_result = load_trusted_keys();
    if (!keys_result) {
        logger().log(SLOG_ERROR("Failed to load trusted keys")
                         .field("error", keys_result.error().to_string()));
        return 1;
    }

    auto keys = *keys_result;
    if (keys.empty()) {
        std::cout << "No trusted keys found in /etc/aegisbpf/keys/" << std::endl;
        return 0;
    }

    std::cout << "Trusted keys (" << keys.size() << "):" << std::endl;
    for (const auto& key : keys) {
        std::cout << "  " << encode_hex(key) << std::endl;
    }
    return 0;
}

static int keys_add(const std::string& key_file)
{
    std::ifstream in(key_file);
    if (!in.is_open()) {
        logger().log(SLOG_ERROR("Failed to open key file").field("path", key_file));
        return 1;
    }

    std::string line;
    if (!std::getline(in, line)) {
        logger().log(SLOG_ERROR("Failed to read key from file"));
        return 1;
    }

    auto key_result = decode_public_key(line);
    if (!key_result) {
        logger().log(SLOG_ERROR("Invalid public key format")
                         .field("error", key_result.error().to_string()));
        return 1;
    }

    // Create keys directory if needed
    std::error_code ec;
    std::filesystem::create_directories("/etc/aegisbpf/keys", ec);
    if (ec) {
        logger().log(SLOG_ERROR("Failed to create keys directory")
                         .field("error", ec.message()));
        return 1;
    }

    // Generate output filename from key fingerprint
    std::string key_hex = encode_hex(*key_result);
    std::string out_path = "/etc/aegisbpf/keys/" + key_hex.substr(0, 16) + ".pub";

    std::ofstream out(out_path);
    if (!out.is_open()) {
        logger().log(SLOG_ERROR("Failed to create key file").field("path", out_path));
        return 1;
    }

    out << key_hex << std::endl;
    std::cout << "Added trusted key: " << out_path << std::endl;
    return 0;
}

static int policy_sign(const std::string& policy_path, const std::string& key_path,
                       const std::string& output_path)
{
    // Read policy file
    std::ifstream policy_in(policy_path);
    if (!policy_in.is_open()) {
        logger().log(SLOG_ERROR("Failed to open policy file").field("path", policy_path));
        return 1;
    }
    std::stringstream policy_ss;
    policy_ss << policy_in.rdbuf();
    std::string policy_content = policy_ss.str();

    // Read private key file (64 bytes hex = 128 chars, or binary)
    std::ifstream key_in(key_path);
    if (!key_in.is_open()) {
        logger().log(SLOG_ERROR("Failed to open private key file").field("path", key_path));
        return 1;
    }
    std::string key_hex;
    std::getline(key_in, key_hex);

    SecretKey secret_key{};
    if (key_hex.size() == 128) {
        // Hex encoded
        for (size_t i = 0; i < 64; ++i) {
            char hi = key_hex[2 * i];
            char lo = key_hex[2 * i + 1];
            auto hex_val = [](char c) -> uint8_t {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return 10 + c - 'a';
                if (c >= 'A' && c <= 'F') return 10 + c - 'A';
                return 0;
            };
            secret_key[i] = (hex_val(hi) << 4) | hex_val(lo);
        }
    }
    else {
        logger().log(SLOG_ERROR("Invalid private key format (expected 128 hex chars)"));
        return 1;
    }

    // Get current version and increment
    uint64_t version = read_version_counter() + 1;

    // Create signed bundle
    auto bundle_result = create_signed_bundle(policy_content, secret_key, version, 0);
    if (!bundle_result) {
        logger().log(SLOG_ERROR("Failed to create signed bundle")
                         .field("error", bundle_result.error().to_string()));
        return 1;
    }

    // Write output
    std::ofstream out(output_path);
    if (!out.is_open()) {
        logger().log(SLOG_ERROR("Failed to create output file").field("path", output_path));
        return 1;
    }

    out << *bundle_result;
    std::cout << "Created signed policy bundle: " << output_path << std::endl;
    std::cout << "Policy version: " << version << std::endl;
    return 0;
}

static int policy_apply_signed(const std::string& bundle_path, bool require_signature)
{
    // Read bundle file
    std::ifstream in(bundle_path);
    if (!in.is_open()) {
        logger().log(SLOG_ERROR("Failed to open bundle file").field("path", bundle_path));
        return 1;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    std::string content = ss.str();

    // Check if it's a signed bundle
    if (content.find("AEGIS-POLICY-BUNDLE") == 0) {
        // Parse signed bundle
        auto bundle_result = parse_signed_bundle(content);
        if (!bundle_result) {
            logger().log(SLOG_ERROR("Failed to parse signed bundle")
                             .field("error", bundle_result.error().to_string()));
            return 1;
        }
        auto bundle = *bundle_result;

        // Load trusted keys
        auto keys_result = load_trusted_keys();
        if (!keys_result) {
            logger().log(SLOG_ERROR("Failed to load trusted keys")
                             .field("error", keys_result.error().to_string()));
            return 1;
        }
        auto trusted_keys = *keys_result;

        if (trusted_keys.empty()) {
            logger().log(SLOG_ERROR("No trusted keys configured - cannot verify signed policy"));
            return 1;
        }

        // Verify bundle
        auto verify_result = verify_bundle(bundle, trusted_keys);
        if (!verify_result) {
            logger().log(SLOG_ERROR("Bundle verification failed")
                             .field("error", verify_result.error().to_string()));
            return 1;
        }

        // Check anti-rollback
        if (!check_version_acceptable(bundle)) {
            logger().log(SLOG_ERROR("Policy version rollback rejected")
                             .field("bundle_version", static_cast<int64_t>(bundle.policy_version))
                             .field("current_version", static_cast<int64_t>(read_version_counter())));
            return 1;
        }

        logger().log(SLOG_INFO("Signed bundle verified successfully")
                         .field("version", static_cast<int64_t>(bundle.policy_version))
                         .field("signer", encode_hex(bundle.signer_key).substr(0, 16) + "..."));

        // Write policy content to temp file and apply
        std::string temp_path = "/tmp/aegisbpf_policy_" + std::to_string(getpid()) + ".conf";
        {
            std::ofstream temp_out(temp_path);
            temp_out << bundle.policy_content;
        }

        auto apply_result = policy_apply(temp_path, false, bundle.policy_sha256, "", true);
        std::remove(temp_path.c_str());

        if (!apply_result) {
            return 1;
        }

        // Update version counter
        auto write_result = write_version_counter(bundle.policy_version);
        if (!write_result) {
            logger().log(SLOG_WARN("Failed to update version counter")
                             .field("error", write_result.error().to_string()));
        }

        return 0;
    }

    // Not a signed bundle
    if (require_signature) {
        logger().log(SLOG_ERROR("Unsigned policy rejected (--require-signature specified)"));
        return 1;
    }

    // Fall back to regular policy apply
    auto apply_result = policy_apply(bundle_path, false, "", "", true);
    return apply_result ? 0 : 1;
}

static int health()
{
    bool ok = true;
    std::error_code ec;

    // Detect kernel features
    auto features_result = detect_kernel_features();
    KernelFeatures features;
    if (features_result) {
        features = *features_result;
    }

    bool cgroup_ok = features.cgroup_v2;
    bool bpffs_ok = check_bpffs_mounted();
    bool btf_ok = features.btf;
    std::string obj_path = resolve_bpf_obj_path();
    bool obj_ok = path_exists(obj_path.c_str(), ec);

    if (!cgroup_ok || !bpffs_ok || !btf_ok || !obj_ok) {
        ok = false;
    }

    bool is_root = geteuid() == 0;
    std::cout << "euid: " << geteuid() << "\n";
    std::cout << "kernel_version: " << features.kernel_version << "\n";
    std::cout << "cgroup_v2: " << (cgroup_ok ? "ok" : "missing") << "\n";
    std::cout << "bpffs: " << (bpffs_ok ? "ok" : "missing") << "\n";
    std::cout << "btf: " << (btf_ok ? "ok" : "missing") << "\n";
    std::cout << "bpf_obj_path: " << obj_path << (obj_ok ? "" : " (missing)") << "\n";

    bool lsm_enabled = features.bpf_lsm;
    std::cout << "bpf_lsm_enabled: " << (lsm_enabled ? "yes" : "no") << "\n";
    std::cout << "ringbuf_support: " << (features.ringbuf ? "yes" : "no") << "\n";
    std::cout << "tracepoints: " << (features.tracepoints ? "yes" : "no") << "\n";

    // Determine enforcement capability
    EnforcementCapability cap = determine_capability(features);
    std::cout << "enforcement_capability: " << capability_name(cap) << "\n";
    std::cout << "capability_explanation: " << capability_explanation(features, cap) << "\n";

    // Check for break-glass mode
    bool break_glass = detect_break_glass();
    std::cout << "break_glass_active: " << (break_glass ? "yes" : "no") << "\n";

    std::string lsm_list = read_file_first_line("/sys/kernel/security/lsm");
    if (!lsm_list.empty()) {
        std::cout << "lsm_list: " << lsm_list << "\n";
    }

    struct KernelConfigCheck {
        const char* key;
        const char* label;
    };
    const KernelConfigCheck config_checks[] = {
        {"CONFIG_BPF", "kernel_config_bpf"},
        {"CONFIG_BPF_SYSCALL", "kernel_config_bpf_syscall"},
        {"CONFIG_BPF_JIT", "kernel_config_bpf_jit"},
        {"CONFIG_BPF_LSM", "kernel_config_bpf_lsm"},
        {"CONFIG_CGROUPS", "kernel_config_cgroups"},
        {"CONFIG_CGROUP_BPF", "kernel_config_cgroup_bpf"},
    };
    for (const auto& check : config_checks) {
        std::string value = kernel_config_value(check.key);
        if (value.empty()) {
            value = "unknown";
        }
        std::cout << check.label << ": " << value << "\n";
    }

    struct PinInfo {
        const char* name;
        const char* path;
    };
    const PinInfo pins[] = {
        {"deny_inode", kDenyInodePin},
        {"deny_path", kDenyPathPin},
        {"allow_cgroup", kAllowCgroupPin},
        {"block_stats", kBlockStatsPin},
        {"deny_cgroup_stats", kDenyCgroupStatsPin},
        {"deny_inode_stats", kDenyInodeStatsPin},
        {"deny_path_stats", kDenyPathStatsPin},
        {"agent_meta", kAgentMetaPin},
        {"survival_allowlist", kSurvivalAllowlistPin},
    };

    if (is_root) {
        std::vector<std::string> present;
        std::vector<std::string> missing;
        std::vector<std::string> unreadable;
        for (const auto& pin : pins) {
            bool exists = path_exists(pin.path, ec);
            if (ec) {
                unreadable.emplace_back(pin.name);
            }
            else if (exists) {
                present.emplace_back(pin.name);
            }
            else {
                missing.emplace_back(pin.name);
            }
        }
        if (!present.empty()) {
            std::cout << "pins_present: " << join_list(present) << "\n";
        }
        if (!missing.empty()) {
            std::cout << "pins_missing: " << join_list(missing) << "\n";
        }
        if (!unreadable.empty()) {
            std::cout << "pins_unreadable: " << join_list(unreadable) << "\n";
        }

        if (path_exists(kAgentMetaPin, ec)) {
            int fd = bpf_obj_get(kAgentMetaPin);
            if (fd < 0) {
                std::cout << "layout_version: unreadable (" << std::strerror(errno) << ")\n";
            }
            else {
                uint32_t key = 0;
                AgentMeta meta{};
                if (bpf_map_lookup_elem(fd, &key, &meta) == 0) {
                    if (meta.layout_version == kLayoutVersion) {
                        std::cout << "layout_version: ok (" << meta.layout_version << ")\n";
                    }
                    else {
                        std::cout << "layout_version: mismatch (found " << meta.layout_version
                                  << ", expected " << kLayoutVersion << ")\n";
                    }
                }
                else {
                    std::cout << "layout_version: unavailable (" << std::strerror(errno) << ")\n";
                }
                close(fd);
            }
        }
    }
    else {
        std::cout << "pins_present: skipped (requires root)\n";
        std::cout << "layout_version: skipped (requires root)\n";
    }

    return ok ? 0 : 1;
}

static int print_metrics(const std::string& out_path)
{
    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    auto stats_result = read_block_stats_map(state.block_stats);
    if (!stats_result) {
        logger().log(SLOG_ERROR("Failed to read block stats")
                         .field("error", stats_result.error().to_string()));
        return 1;
    }
    BlockStats stats = *stats_result;

    auto cgroup_result = read_cgroup_block_counts(state.deny_cgroup_stats);
    if (!cgroup_result) {
        logger().log(SLOG_ERROR("Failed to read cgroup block counts")
                         .field("error", cgroup_result.error().to_string()));
        return 1;
    }
    auto cgroup_blocks = *cgroup_result;

    auto inode_result = read_inode_block_counts(state.deny_inode_stats);
    if (!inode_result) {
        logger().log(SLOG_ERROR("Failed to read inode block counts")
                         .field("error", inode_result.error().to_string()));
        return 1;
    }
    auto inode_blocks = *inode_result;

    auto path_result = read_path_block_counts(state.deny_path_stats);
    if (!path_result) {
        logger().log(SLOG_ERROR("Failed to read path block counts")
                         .field("error", path_result.error().to_string()));
        return 1;
    }
    auto path_blocks = *path_result;

    size_t deny_sz = map_entry_count(state.deny_inode);
    size_t deny_path_sz = map_entry_count(state.deny_path);
    size_t allow_sz = map_entry_count(state.allow_cgroup);

    std::ostringstream oss;
    oss << "# HELP aegisbpf_blocks_total Total number of block events.\n";
    oss << "# TYPE aegisbpf_blocks_total counter\n";
    oss << "aegisbpf_blocks_total " << stats.blocks << "\n";
    oss << "# HELP aegisbpf_ringbuf_drops_total Total ringbuf drops.\n";
    oss << "# TYPE aegisbpf_ringbuf_drops_total counter\n";
    oss << "aegisbpf_ringbuf_drops_total " << stats.ringbuf_drops << "\n";
    oss << "# HELP aegisbpf_deny_inode_entries Number of deny inode entries.\n";
    oss << "# TYPE aegisbpf_deny_inode_entries gauge\n";
    oss << "aegisbpf_deny_inode_entries " << deny_sz << "\n";
    oss << "# HELP aegisbpf_deny_path_entries Number of deny path entries.\n";
    oss << "# TYPE aegisbpf_deny_path_entries gauge\n";
    oss << "aegisbpf_deny_path_entries " << deny_path_sz << "\n";
    oss << "# HELP aegisbpf_allow_cgroup_entries Number of allow cgroup entries.\n";
    oss << "# TYPE aegisbpf_allow_cgroup_entries gauge\n";
    oss << "aegisbpf_allow_cgroup_entries " << allow_sz << "\n";

    if (!cgroup_blocks.empty()) {
        oss << "# HELP aegisbpf_blocks_by_cgroup_total Block events by cgroup.\n";
        oss << "# TYPE aegisbpf_blocks_by_cgroup_total counter\n";
        for (const auto& kv : cgroup_blocks) {
            std::string cgpath = resolve_cgroup_path(kv.first);
            oss << "aegisbpf_blocks_by_cgroup_total{cgid=\"" << kv.first << "\",cgroup_path=\""
                << prometheus_escape_label(cgpath) << "\"} " << kv.second << "\n";
        }
    }
    if (!inode_blocks.empty()) {
        oss << "# HELP aegisbpf_blocks_by_inode_total Block events by inode.\n";
        oss << "# TYPE aegisbpf_blocks_by_inode_total counter\n";
        for (const auto& kv : inode_blocks) {
            oss << "aegisbpf_blocks_by_inode_total{dev=\"" << kv.first.dev << "\",ino=\""
                << kv.first.ino << "\"} " << kv.second << "\n";
        }
    }
    if (!path_blocks.empty()) {
        oss << "# HELP aegisbpf_blocks_by_path_total Block events by path.\n";
        oss << "# TYPE aegisbpf_blocks_by_path_total counter\n";
        for (const auto& kv : path_blocks) {
            if (kv.first.empty()) {
                continue;
            }
            oss << "aegisbpf_blocks_by_path_total{path=\"" << prometheus_escape_label(kv.first)
                << "\"} " << kv.second << "\n";
        }
    }

    if (out_path.empty() || out_path == "-") {
        std::cout << oss.str();
    }
    else {
        std::ofstream out(out_path, std::ios::trunc);
        if (!out.is_open()) {
            logger().log(SLOG_ERROR("Failed to write metrics").field("path", out_path));
            return 1;
        }
        out << oss.str();
    }

    return 0;
}

static int print_stats()
{
    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    auto stats_result = read_block_stats_map(state.block_stats);
    if (!stats_result) {
        logger().log(SLOG_ERROR("Failed to read block stats")
                         .field("error", stats_result.error().to_string()));
        return 1;
    }
    BlockStats stats = *stats_result;

    auto cgroup_result = read_cgroup_block_counts(state.deny_cgroup_stats);
    if (!cgroup_result) {
        logger().log(SLOG_ERROR("Failed to read cgroup block counts")
                         .field("error", cgroup_result.error().to_string()));
        return 1;
    }
    auto cgroup_blocks = *cgroup_result;

    auto inode_result = read_inode_block_counts(state.deny_inode_stats);
    if (!inode_result) {
        logger().log(SLOG_ERROR("Failed to read inode block counts")
                         .field("error", inode_result.error().to_string()));
        return 1;
    }
    auto inode_blocks = *inode_result;

    auto path_result = read_path_block_counts(state.deny_path_stats);
    if (!path_result) {
        logger().log(SLOG_ERROR("Failed to read path block counts")
                         .field("error", path_result.error().to_string()));
        return 1;
    }
    auto path_blocks = *path_result;

    size_t deny_sz = map_entry_count(state.deny_inode);
    size_t deny_path_sz = map_entry_count(state.deny_path);
    size_t allow_sz = map_entry_count(state.allow_cgroup);

    std::cout << "deny_inode entries: " << deny_sz << "\n"
              << "deny_path entries: " << deny_path_sz << "\n"
              << "allow_cgroup entries: " << allow_sz << "\n"
              << "blocks: " << stats.blocks << "\n"
              << "ringbuf_drops: " << stats.ringbuf_drops << std::endl;

    if (!cgroup_blocks.empty()) {
        std::cout << "blocks_by_cgroup:\n";
        for (const auto& kv : cgroup_blocks) {
            std::string cgpath = resolve_cgroup_path(kv.first);
            if (!cgpath.empty()) {
                std::cout << "  " << cgpath << " (" << kv.first << "): " << kv.second << "\n";
            }
            else {
                std::cout << "  " << kv.first << ": " << kv.second << "\n";
            }
        }
    }
    if (!inode_blocks.empty()) {
        auto db = read_deny_db();
        std::cout << "blocks_by_inode:\n";
        for (const auto& kv : inode_blocks) {
            auto it = db.find(kv.first);
            if (it != db.end() && !it->second.empty()) {
                std::cout << "  " << it->second << " (" << inode_to_string(kv.first) << "): " << kv.second << "\n";
            }
            else {
                std::cout << "  " << inode_to_string(kv.first) << ": " << kv.second << "\n";
            }
        }
    }
    if (!path_blocks.empty()) {
        std::cout << "blocks_by_path:\n";
        for (const auto& kv : path_blocks) {
            if (!kv.first.empty()) {
                std::cout << "  " << kv.first << ": " << kv.second << "\n";
            }
        }
    }

    return 0;
}

static LogLevel parse_log_level(const std::string& level)
{
    if (level == "debug") return LogLevel::Debug;
    if (level == "info") return LogLevel::Info;
    if (level == "warn" || level == "warning") return LogLevel::Warn;
    if (level == "error") return LogLevel::Error;
    if (level == "fatal") return LogLevel::Fatal;
    return LogLevel::Info;
}

static int usage(const char* prog)
{
    std::cerr << "Usage: " << prog
              << " run [--audit|--enforce] [--seccomp] [--deadman-ttl=<seconds>] [--lsm-hook=file|inode|both] [--ringbuf-bytes=<bytes>] [--event-sample-rate=<n>] [--log=stdout|journald|both] [--log-level=debug|info|warn|error] [--log-format=text|json]"
              << " | block {add|del|list|clear} [path]"
              << " | allow {add|del} <cgroup_path> | allow list"
              << " | survival {list|verify}"
              << " | policy {lint|apply|export} <file> [--reset] [--sha256 <hex>|--sha256-file <path>] [--no-rollback] [--require-signature]"
              << " | policy sign <policy.conf> --key <private.key> --output <policy.signed>"
              << " | policy {show|rollback}"
              << " | keys {list|add <pubkey.pub>}"
              << " | stats"
              << " | metrics [--out <path>]"
              << " | health" << std::endl;
    return 1;
}

}  // namespace aegis

int main(int argc, char** argv)
{
    using namespace aegis;

    // Parse global logging options first
    LogLevel log_level = LogLevel::Info;
    bool json_format = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.rfind("--log-level=", 0) == 0) {
            log_level = parse_log_level(arg.substr(12));
        }
        else if (arg.rfind("--log-format=", 0) == 0) {
            json_format = (arg.substr(13) == "json");
        }
    }

    logger().set_level(log_level);
    logger().set_json_format(json_format);

    if (argc == 1) {
        return run(false, false, 0, LsmHookMode::FileOpen, 0, 1);
    }

    std::string cmd = argv[1];

    if (cmd == "run") {
        bool audit_only = false;
        bool enable_seccomp = false;
        uint32_t deadman_ttl = 0;
        uint32_t ringbuf_bytes = 0;
        uint32_t event_sample_rate = 1;
        LsmHookMode lsm_hook = LsmHookMode::FileOpen;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--audit" || arg == "--mode=audit") {
                audit_only = true;
            }
            else if (arg == "--enforce" || arg == "--mode=enforce") {
                audit_only = false;
            }
            else if (arg == "--seccomp") {
                enable_seccomp = true;
            }
            else if (arg.rfind("--deadman-ttl=", 0) == 0) {
                std::string value = arg.substr(std::strlen("--deadman-ttl="));
                uint64_t ttl = 0;
                if (!parse_uint64(value, ttl) || ttl > UINT32_MAX) {
                    logger().log(SLOG_ERROR("Invalid deadman TTL value").field("value", value));
                    return 1;
                }
                deadman_ttl = static_cast<uint32_t>(ttl);
            }
            else if (arg == "--deadman-ttl") {
                if (i + 1 >= argc) {
                    return usage(argv[0]);
                }
                std::string value = argv[++i];
                uint64_t ttl = 0;
                if (!parse_uint64(value, ttl) || ttl > UINT32_MAX) {
                    logger().log(SLOG_ERROR("Invalid deadman TTL value").field("value", value));
                    return 1;
                }
                deadman_ttl = static_cast<uint32_t>(ttl);
            }
            else if (arg.rfind("--log=", 0) == 0) {
                std::string value = arg.substr(std::strlen("--log="));
                if (!set_event_log_sink(value)) {
                    return usage(argv[0]);
                }
            }
            else if (arg == "--log") {
                if (i + 1 >= argc) {
                    return usage(argv[0]);
                }
                std::string value = argv[++i];
                if (!set_event_log_sink(value)) {
                    return usage(argv[0]);
                }
            }
            else if (arg.rfind("--log-level=", 0) == 0 || arg.rfind("--log-format=", 0) == 0) {
                // Already processed
            }
            else if (arg.rfind("--ringbuf-bytes=", 0) == 0) {
                std::string value = arg.substr(std::strlen("--ringbuf-bytes="));
                uint64_t bytes = 0;
                if (!parse_uint64(value, bytes) || bytes > UINT32_MAX) {
                    logger().log(SLOG_ERROR("Invalid ringbuf size").field("value", value));
                    return 1;
                }
                ringbuf_bytes = static_cast<uint32_t>(bytes);
            }
            else if (arg.rfind("--event-sample-rate=", 0) == 0) {
                std::string value = arg.substr(std::strlen("--event-sample-rate="));
                uint64_t rate = 0;
                if (!parse_uint64(value, rate) || rate == 0 || rate > UINT32_MAX) {
                    logger().log(SLOG_ERROR("Invalid event sample rate").field("value", value));
                    return 1;
                }
                event_sample_rate = static_cast<uint32_t>(rate);
            }
            else if (arg.rfind("--lsm-hook=", 0) == 0) {
                std::string value = arg.substr(std::strlen("--lsm-hook="));
                if (!parse_lsm_hook(value, lsm_hook)) {
                    logger().log(SLOG_ERROR("Invalid lsm hook value").field("value", value));
                    return 1;
                }
            }
            else if (arg == "--ringbuf-bytes") {
                if (i + 1 >= argc) {
                    return usage(argv[0]);
                }
                std::string value = argv[++i];
                uint64_t bytes = 0;
                if (!parse_uint64(value, bytes) || bytes > UINT32_MAX) {
                    logger().log(SLOG_ERROR("Invalid ringbuf size").field("value", value));
                    return 1;
                }
                ringbuf_bytes = static_cast<uint32_t>(bytes);
            }
            else if (arg == "--event-sample-rate") {
                if (i + 1 >= argc) {
                    return usage(argv[0]);
                }
                std::string value = argv[++i];
                uint64_t rate = 0;
                if (!parse_uint64(value, rate) || rate == 0 || rate > UINT32_MAX) {
                    logger().log(SLOG_ERROR("Invalid event sample rate").field("value", value));
                    return 1;
                }
                event_sample_rate = static_cast<uint32_t>(rate);
            }
            else if (arg == "--lsm-hook") {
                if (i + 1 >= argc) {
                    return usage(argv[0]);
                }
                std::string value = argv[++i];
                if (!parse_lsm_hook(value, lsm_hook)) {
                    logger().log(SLOG_ERROR("Invalid lsm hook value").field("value", value));
                    return 1;
                }
            }
            else {
                return usage(argv[0]);
            }
        }
        return run(audit_only, enable_seccomp, deadman_ttl, lsm_hook, ringbuf_bytes, event_sample_rate);
    }

    if (cmd == "block") {
        if (argc < 3) {
            return usage(argv[0]);
        }
        std::string sub = argv[2];
        if (sub == "add") {
            if (argc < 4) {
                return usage(argv[0]);
            }
            return block_add(argv[3]);
        }
        if (sub == "del") {
            if (argc < 4) {
                return usage(argv[0]);
            }
            return block_del(argv[3]);
        }
        if (sub == "list") {
            return block_list();
        }
        if (sub == "clear") {
            return block_clear();
        }
        return usage(argv[0]);
    }

    if (cmd == "allow") {
        if (argc < 3) {
            return usage(argv[0]);
        }
        std::string sub = argv[2];
        if (sub == "add") {
            if (argc < 4) {
                return usage(argv[0]);
            }
            return allow_add(argv[3]);
        }
        if (sub == "del") {
            if (argc < 4) {
                return usage(argv[0]);
            }
            return allow_del(argv[3]);
        }
        if (sub == "list") {
            if (argc > 3) {
                return usage(argv[0]);
            }
            return allow_list();
        }
        return usage(argv[0]);
    }

    if (cmd == "survival") {
        if (argc < 3) {
            return usage(argv[0]);
        }
        std::string sub = argv[2];
        if (sub == "list") {
            return survival_list();
        }
        if (sub == "verify") {
            return survival_verify();
        }
        return usage(argv[0]);
    }

    if (cmd == "policy") {
        if (argc < 3) {
            return usage(argv[0]);
        }
        std::string sub = argv[2];
        if (sub == "lint") {
            if (argc != 4) {
                return usage(argv[0]);
            }
            auto result = policy_lint(argv[3]);
            return result ? 0 : 1;
        }
        if (sub == "apply") {
            if (argc < 4) {
                return usage(argv[0]);
            }
            bool reset = false;
            bool rollback_on_failure = true;
            bool require_signature = false;
            std::string sha256;
            std::string sha256_file;
            for (int i = 4; i < argc; ++i) {
                std::string arg = argv[i];
                if (arg == "--reset") {
                    reset = true;
                }
                else if (arg == "--no-rollback") {
                    rollback_on_failure = false;
                }
                else if (arg == "--require-signature") {
                    require_signature = true;
                }
                else if (arg == "--sha256") {
                    if (i + 1 >= argc) {
                        return usage(argv[0]);
                    }
                    sha256 = argv[++i];
                }
                else if (arg == "--sha256-file") {
                    if (i + 1 >= argc) {
                        return usage(argv[0]);
                    }
                    sha256_file = argv[++i];
                }
                else {
                    return usage(argv[0]);
                }
            }
            // Check if file looks like a signed bundle
            std::ifstream check_file(argv[3]);
            std::string first_line;
            std::getline(check_file, first_line);
            check_file.close();
            if (first_line.find("AEGIS-POLICY-BUNDLE") == 0 || require_signature) {
                return policy_apply_signed(argv[3], require_signature);
            }
            auto result = policy_apply(argv[3], reset, sha256, sha256_file, rollback_on_failure);
            return result ? 0 : 1;
        }
        if (sub == "sign") {
            if (argc < 4) {
                return usage(argv[0]);
            }
            std::string key_path;
            std::string output_path;
            for (int i = 4; i < argc; ++i) {
                std::string arg = argv[i];
                if (arg == "--key") {
                    if (i + 1 >= argc) return usage(argv[0]);
                    key_path = argv[++i];
                }
                else if (arg == "--output") {
                    if (i + 1 >= argc) return usage(argv[0]);
                    output_path = argv[++i];
                }
                else {
                    return usage(argv[0]);
                }
            }
            if (key_path.empty() || output_path.empty()) {
                return usage(argv[0]);
            }
            return policy_sign(argv[3], key_path, output_path);
        }
        if (sub == "export") {
            if (argc != 4) {
                return usage(argv[0]);
            }
            auto result = policy_export(argv[3]);
            return result ? 0 : 1;
        }
        if (sub == "show") {
            if (argc != 3) {
                return usage(argv[0]);
            }
            auto result = policy_show();
            return result ? 0 : 1;
        }
        if (sub == "rollback") {
            if (argc != 3) {
                return usage(argv[0]);
            }
            auto result = policy_rollback();
            return result ? 0 : 1;
        }
        return usage(argv[0]);
    }

    if (cmd == "keys") {
        if (argc < 3) {
            return usage(argv[0]);
        }
        std::string sub = argv[2];
        if (sub == "list") {
            return keys_list();
        }
        if (sub == "add") {
            if (argc != 4) {
                return usage(argv[0]);
            }
            return keys_add(argv[3]);
        }
        return usage(argv[0]);
    }

    if (cmd == "health") {
        if (argc > 2) {
            return usage(argv[0]);
        }
        return health();
    }

    if (cmd == "metrics") {
        std::string out_path;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--out") {
                if (i + 1 >= argc) {
                    return usage(argv[0]);
                }
                out_path = argv[++i];
            }
            else {
                return usage(argv[0]);
            }
        }
        return print_metrics(out_path);
    }

    if (cmd == "stats") {
        if (argc > 2) {
            return usage(argv[0]);
        }
        return print_stats();
    }

    return usage(argv[0]);
}
