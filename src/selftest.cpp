// cppcheck-suppress-file missingIncludeSystem
#include "selftest.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <cstdint>
#include <cstring>

#include "logging.hpp"
#include "types.hpp"

namespace aegis {

Result<SelftestResult> run_startup_selftests(const BpfState& state)
{
    SelftestResult result;

    // Check critical maps exist
    struct MapCheck {
        const char* name;
        const bpf_map* map;
    };
    const MapCheck checks[] = {
        {"events", state.events},
        {"deny_inode", state.deny_inode},
        {"deny_path", state.deny_path},
        {"allow_cgroup", state.allow_cgroup},
        {"block_stats", state.block_stats},
        {"config_map", state.config_map},
        {"survival_allowlist", state.survival_allowlist},
    };

    for (const auto& check : checks) {
        result.maps_checked++;
        if (check.map != nullptr) {
            result.maps_ok++;
        } else {
            logger().log(SLOG_WARN("Selftest: map not found").field("map", check.name));
        }
    }

    result.maps_accessible = (result.maps_ok == result.maps_checked);

    // Test config map readability
    if (state.config_map) {
        uint32_t key = 0;
        AgentConfig cfg{};
        int cfg_fd = bpf_map__fd(state.config_map);
        if (cfg_fd >= 0 && bpf_map_lookup_elem(cfg_fd, &key, &cfg) == 0) {
            result.config_readable = true;
        } else {
            result.failure_detail = "Config map read failed";
            logger().log(SLOG_WARN("Selftest: config map unreadable"));
        }
    }

    // Test ring buffer FD validity
    if (state.events) {
        int events_fd = bpf_map__fd(state.events);
        result.ringbuf_writable = (events_fd >= 0);
        if (!result.ringbuf_writable) {
            result.failure_detail = "Events ring buffer FD invalid";
        }
    }

    // Test process_tree write/read/delete cycle
    if (state.obj) {
        bpf_map* pt = bpf_object__find_map_by_name(state.obj, "process_tree");
        if (pt) {
            int pt_fd = bpf_map__fd(pt);
            if (pt_fd >= 0) {
                // Use PID 0 as sentinel (kernel idle task, never a real userspace PID)
                uint32_t test_pid = 0;
                // Zero-init buffer to match BPF-side layout
                uint8_t zeroed[64] = {};
                int write_rc = bpf_map_update_elem(pt_fd, &test_pid, zeroed, BPF_ANY);
                if (write_rc == 0) {
                    uint8_t readback[64] = {};
                    int read_rc = bpf_map_lookup_elem(pt_fd, &test_pid, readback);
                    bpf_map_delete_elem(pt_fd, &test_pid);
                    result.process_tree_writable = (read_rc == 0);
                } else {
                    result.process_tree_writable = false;
                    result.failure_detail = "process_tree write failed";
                }
            }
        }
    }

    if (result.maps_accessible && result.config_readable && result.ringbuf_writable && result.process_tree_writable) {
        logger().log(SLOG_INFO("Startup self-tests passed")
                         .field("maps_checked", static_cast<int64_t>(result.maps_checked))
                         .field("maps_ok", static_cast<int64_t>(result.maps_ok)));
    } else {
        logger().log(SLOG_WARN("Startup self-tests detected issues")
                         .field("maps_accessible", result.maps_accessible)
                         .field("config_readable", result.config_readable)
                         .field("ringbuf_writable", result.ringbuf_writable)
                         .field("process_tree_writable", result.process_tree_writable)
                         .field("detail", result.failure_detail));
    }

    return result;
}

} // namespace aegis
