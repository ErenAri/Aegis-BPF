// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Footprint command implementation
 */

#include "commands_monitoring.hpp"

#include <iomanip>
#include <iostream>
#include <sstream>

#include "types.hpp"

namespace aegis {

namespace {

constexpr uint64_t MAX_DENY_INODE_ENTRIES = 65536;
constexpr uint64_t MAX_DENY_PATH_ENTRIES = 16384;
constexpr uint64_t MAX_ALLOW_CGROUP_ENTRIES = 1024;
constexpr uint64_t MAX_ALLOW_EXEC_INODE_ENTRIES = 65536;
constexpr uint64_t MAX_DENY_IPV4_ENTRIES = 65536;
constexpr uint64_t MAX_DENY_IPV6_ENTRIES = 65536;
constexpr uint64_t MAX_DENY_PORT_ENTRIES = 4096;
constexpr uint64_t MAX_DENY_CIDR_V4_ENTRIES = 16384;
constexpr uint64_t MAX_DENY_CIDR_V6_ENTRIES = 16384;

} // namespace

int cmd_footprint(uint64_t deny_inodes, uint64_t deny_paths, uint64_t deny_ips, uint64_t deny_cidrs,
                  uint64_t deny_ports, uint64_t ringbuf_bytes)
{
    // Use max capacity when specific counts are not provided.
    if (deny_inodes == 0) {
        deny_inodes = MAX_DENY_INODE_ENTRIES;
    }
    if (deny_paths == 0) {
        deny_paths = MAX_DENY_PATH_ENTRIES;
    }
    if (deny_ips == 0) {
        deny_ips = MAX_DENY_IPV4_ENTRIES + MAX_DENY_IPV6_ENTRIES;
    }
    if (deny_cidrs == 0) {
        deny_cidrs = MAX_DENY_CIDR_V4_ENTRIES + MAX_DENY_CIDR_V6_ENTRIES;
    }
    if (deny_ports == 0) {
        deny_ports = MAX_DENY_PORT_ENTRIES;
    }
    if (ringbuf_bytes == 0) {
        ringbuf_bytes = uint64_t{256} * 1024; // default 256 KiB
    }

    // BPF map overhead per entry (hash map: ~64 bytes metadata per entry).
    constexpr uint64_t kBpfHashOverhead = 64;

    // Compute per-map memory estimates.
    // deny_inode: key=InodeId(16), value=uint8_t(1)
    uint64_t deny_inode_mem = deny_inodes * (sizeof(InodeId) + 1 + kBpfHashOverhead);
    // deny_path: key=PathKey(256), value=uint8_t(1)
    uint64_t deny_path_mem = deny_paths * (sizeof(PathKey) + 1 + kBpfHashOverhead);
    // allow_cgroup: key=uint64_t(8), value=uint8_t(1)
    uint64_t allow_cgroup_mem = MAX_ALLOW_CGROUP_ENTRIES * (8 + 1 + kBpfHashOverhead);
    // allow_exec_inode: key=InodeId(16), value=uint8_t(1)
    uint64_t allow_exec_inode_mem = MAX_ALLOW_EXEC_INODE_ENTRIES * (sizeof(InodeId) + 1 + kBpfHashOverhead);
    // deny_ipv4: key=uint32_t(4), value=uint8_t(1)
    uint64_t deny_ip_mem = deny_ips * (16 + 1 + kBpfHashOverhead); // conservative: IPv6 key size
    // deny_cidr: LPM trie, key includes prefix
    uint64_t deny_cidr_mem = deny_cidrs * (20 + 1 + kBpfHashOverhead); // Ipv6LpmKey(20) + value
    // deny_port: key=PortKey(4), value=uint8_t(1)
    uint64_t deny_port_mem = deny_ports * (sizeof(PortKey) + 1 + kBpfHashOverhead);
    // Stats maps: per-cpu arrays, small fixed size
    uint64_t stats_mem = 4096; // conservative estimate for all stats maps

    uint64_t total_maps = deny_inode_mem + deny_path_mem + allow_cgroup_mem + allow_exec_inode_mem + deny_ip_mem +
                          deny_cidr_mem + deny_port_mem + stats_mem;
    uint64_t total = total_maps + ringbuf_bytes;

    auto fmt_kb = [](uint64_t bytes) -> std::string {
        std::ostringstream oss;
        if (bytes >= uint64_t{1024} * 1024) {
            oss << std::fixed << std::setprecision(1) << (static_cast<double>(bytes) / (1024.0 * 1024.0)) << " MiB";
        } else {
            oss << std::fixed << std::setprecision(1) << (static_cast<double>(bytes) / 1024.0) << " KiB";
        }
        return oss.str();
    };

    std::cout << "AegisBPF Memory Footprint Estimate\n";
    std::cout << "===================================\n";
    std::cout << "  deny_inode  (" << deny_inodes << " entries): " << fmt_kb(deny_inode_mem) << "\n";
    std::cout << "  deny_path   (" << deny_paths << " entries): " << fmt_kb(deny_path_mem) << "\n";
    std::cout << "  allow_cgroup(" << MAX_ALLOW_CGROUP_ENTRIES << " entries): " << fmt_kb(allow_cgroup_mem) << "\n";
    std::cout << "  allow_exec_inode(" << MAX_ALLOW_EXEC_INODE_ENTRIES << " entries): " << fmt_kb(allow_exec_inode_mem)
              << "\n";
    std::cout << "  deny_ip     (" << deny_ips << " entries): " << fmt_kb(deny_ip_mem) << "\n";
    std::cout << "  deny_cidr   (" << deny_cidrs << " entries): " << fmt_kb(deny_cidr_mem) << "\n";
    std::cout << "  deny_port   (" << deny_ports << " entries): " << fmt_kb(deny_port_mem) << "\n";
    std::cout << "  stats maps  (fixed):               " << fmt_kb(stats_mem) << "\n";
    std::cout << "  ring buffer:                       " << fmt_kb(ringbuf_bytes) << "\n";
    std::cout << "  -----------------------------------\n";
    std::cout << "  Total (maps):                      " << fmt_kb(total_maps) << "\n";
    std::cout << "  Total (maps + ringbuf):             " << fmt_kb(total) << "\n";
    std::cout << "\n";
    std::cout << "  Recommended RLIMIT_MEMLOCK:         " << fmt_kb(total * 2) << " (2x headroom)\n";

    return 0;
}

} // namespace aegis
