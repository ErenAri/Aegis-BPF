// cppcheck-suppress-file missingIncludeSystem
#include "proc_scan.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <dirent.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>

#include "logging.hpp"

namespace aegis {

namespace {

struct ProcInfo {
    uint32_t pid = 0;
    uint32_t ppid = 0;
    uint64_t start_time = 0;
    char comm[16] = {};
};

bool parse_proc_stat(uint32_t pid, ProcInfo& out)
{
    std::string path = "/proc/" + std::to_string(pid) + "/stat";
    std::ifstream f(path);
    if (!f.is_open())
        return false;

    std::string line;
    if (!std::getline(f, line))
        return false;

    // Format: pid (comm) state ppid ... field22=starttime
    // Find the closing paren to skip comm (which can contain spaces/parens)
    auto close_paren = line.rfind(')');
    if (close_paren == std::string::npos)
        return false;

    out.pid = pid;

    // Parse fields after ") "
    // Fields: state ppid pgrp session tty_nr tpgid flags
    //         minflt cminflt majflt cmajflt utime stime cutime cstime
    //         priority nice num_threads itrealvalue starttime ...
    const char* rest = line.c_str() + close_paren + 2; // skip ") "
    char state = 0;
    uint32_t ppid = 0;
    unsigned long long starttime = 0;

    // cppcheck-suppress invalidscanf
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
    int matched = sscanf(rest,
                         "%c %u %*d %*d %*d %*d %*u " // state ppid pgrp session tty tpgid flags
                         "%*lu %*lu %*lu %*lu "       // minflt cminflt majflt cmajflt
                         "%*lu %*lu %*ld %*ld "       // utime stime cutime cstime
                         "%*ld %*ld %*ld %*ld "       // priority nice num_threads itrealvalue
                         "%llu",                      // starttime
                         &state, &ppid, &starttime);
#pragma GCC diagnostic pop

    (void)state; // only used for sscanf positional parsing
    if (matched < 2)
        return false;

    out.ppid = ppid;
    out.start_time = starttime;

    // Read comm from /proc/[pid]/comm (newline-terminated)
    std::string comm_path = "/proc/" + std::to_string(pid) + "/comm";
    std::ifstream cf(comm_path);
    if (cf.is_open()) {
        std::string comm;
        if (std::getline(cf, comm)) {
            size_t len = comm.size();
            if (len > 15)
                len = 15;
            std::memcpy(out.comm, comm.c_str(), len);
            out.comm[len] = '\0';
        }
    }

    return true;
}

} // namespace

Result<ProcScanResult> reconcile_proc_tree(const BpfState& state)
{
    ProcScanResult result;

    bpf_map* pt = state.obj ? bpf_object__find_map_by_name(state.obj, "process_tree") : nullptr;
    if (!pt) {
        return Error(ErrorCode::BpfLoadFailed, "process_tree map not found");
    }

    int pt_fd = bpf_map__fd(pt);
    if (pt_fd < 0) {
        return Error(ErrorCode::BpfLoadFailed, "process_tree fd invalid");
    }

    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        return Error::system(errno, "Failed to open /proc");
    }

    struct dirent* entry = nullptr;
    while ((entry = readdir(proc_dir)) != nullptr) {
        // Only process numeric directories (PIDs)
        if (entry->d_type != DT_DIR)
            continue;

        char* endptr = nullptr;
        unsigned long pid_ul = std::strtoul(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid_ul == 0)
            continue;

        auto pid = static_cast<uint32_t>(pid_ul);
        result.processes_scanned++;

        // Check if already in process_tree
        uint8_t existing[128] = {};
        if (bpf_map_lookup_elem(pt_fd, &pid, existing) == 0) {
            result.processes_skipped++;
            continue;
        }

        // Parse /proc/[pid]/stat
        ProcInfo info;
        if (!parse_proc_stat(pid, info)) {
            result.errors++;
            continue;
        }

        // Build process_info-compatible struct (zeroed padding).
        // Layout: pid(4) ppid(4) start_time(8) then remaining zeroed.
        uint8_t value[128] = {};
        std::memcpy(value, &info.pid, 4);            // offset 0: pid
        std::memcpy(value + 4, &info.ppid, 4);       // offset 4: ppid
        std::memcpy(value + 8, &info.start_time, 8); // offset 8: start_time

        int rc = bpf_map_update_elem(pt_fd, &pid, value, BPF_NOEXIST);
        if (rc == 0) {
            result.processes_added++;
        } else if (rc == -EEXIST) {
            result.processes_skipped++;
        } else {
            result.errors++;
        }
    }

    closedir(proc_dir);

    logger().log(SLOG_INFO("Process tree reconciliation complete")
                     .field("scanned", static_cast<int64_t>(result.processes_scanned))
                     .field("added", static_cast<int64_t>(result.processes_added))
                     .field("skipped", static_cast<int64_t>(result.processes_skipped))
                     .field("errors", static_cast<int64_t>(result.errors)));

    return result;
}

} // namespace aegis
