// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>

namespace aegis {

// Monitoring and sizing commands
int cmd_footprint(uint64_t deny_inodes = 0, uint64_t deny_paths = 0, uint64_t deny_ips = 0, uint64_t deny_cidrs = 0,
                  uint64_t deny_ports = 0, uint64_t ringbuf_bytes = 0);

} // namespace aegis
