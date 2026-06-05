// cppcheck-suppress-file missingIncludeSystem
/*
 * Reconstruct a structured C++ Policy from the memory-safe Rust parser, via the
 * `aegis_policy_build` FFI seam. This is the *content* transport for the eventual
 * swap (vs the consensus/shadow, which only compares canonical dumps). The Rust
 * parser walks its parsed policy and calls back per field; here we reassemble a
 * `Policy`, including parsing the canonical string forms of the compound fields
 * (inodes / ip:ports / cgroup keys) back into structs.
 *
 * NOT wired into the apply path — exercised only by the in-process equivalence
 * test (tests/test_rust_ffi_parity.cpp). Compiled to a no-op unless built with
 * -DENABLE_RUST_PARSER_LINK=ON (which defines AEGIS_RUST_SHADOW).
 */
#include "rust_policy_build.hpp"

#ifdef AEGIS_RUST_SHADOW
#    include "aegis_parser_ffi.h"

#    include <cstdint>
#    include <cstdlib>
#    include <string>
#endif

namespace aegis {

#ifdef AEGIS_RUST_SHADOW

namespace {

// "dev:ino" -> InodeId (matches the Rust `format!("{dev}:{ino}")` / C++
// inode_to_string canonical form).
InodeId parse_inode(const std::string& s)
{
    InodeId id{};
    const auto colon = s.find(':');
    if (colon != std::string::npos) {
        id.dev = static_cast<uint32_t>(std::strtoul(s.substr(0, colon).c_str(), nullptr, 10));
        id.ino = std::strtoull(s.substr(colon + 1).c_str(), nullptr, 10);
    }
    return id;
}

extern "C" void b_set_version(void* ctx, uint64_t v)
{
    static_cast<Policy*>(ctx)->version = static_cast<int>(v);
}

extern "C" void b_set_flag(void* ctx, uint32_t id)
{
    auto* p = static_cast<Policy*>(ctx);
    switch (id) {
        case AEGIS_PFLAG_PROTECT_CONNECT:
            p->protect_connect = true;
            break;
        case AEGIS_PFLAG_PROTECT_RUNTIME_DEPS:
            p->protect_runtime_deps = true;
            break;
        case AEGIS_PFLAG_REQUIRE_IMA_APPRAISAL:
            p->require_ima_appraisal = true;
            break;
        case AEGIS_PFLAG_IMA_FAIL_CLOSED:
            p->ima_fail_closed = true;
            break;
        case AEGIS_PFLAG_DENY_PTRACE:
            p->deny_ptrace = true;
            break;
        case AEGIS_PFLAG_DENY_MODULE_LOAD:
            p->deny_module_load = true;
            break;
        case AEGIS_PFLAG_DENY_BPF:
            p->deny_bpf = true;
            break;
        case AEGIS_PFLAG_NETWORK_ENABLED:
            p->network.enabled = true;
            break;
        case AEGIS_PFLAG_CGROUP_ENABLED:
            p->cgroup.enabled = true;
            break;
        default:
            break;
    }
}

extern "C" void b_add_string(void* ctx, uint32_t category, const char* s, size_t len)
{
    auto* p = static_cast<Policy*>(ctx);
    std::string v(s, len);
    switch (category) {
        case AEGIS_PCAT_DENY_PATH:
            p->deny_paths.push_back(std::move(v));
            break;
        case AEGIS_PCAT_PROTECT_PATH:
            p->protect_paths.push_back(std::move(v));
            break;
        case AEGIS_PCAT_DENY_INODE:
            p->deny_inodes.push_back(parse_inode(v));
            break;
        case AEGIS_PCAT_ALLOW_CGROUP_PATH:
            p->allow_cgroup_paths.push_back(std::move(v));
            break;
        case AEGIS_PCAT_DENY_IP:
            p->network.deny_ips.push_back(std::move(v));
            break;
        case AEGIS_PCAT_DENY_CIDR:
            p->network.deny_cidrs.push_back(std::move(v));
            break;
        case AEGIS_PCAT_DENY_IP_PORT: {
            // "ip|port|proto"
            const auto p1 = v.find('|');
            const auto p2 = v.rfind('|');
            if (p1 != std::string::npos && p2 != std::string::npos && p2 > p1) {
                IpPortRule r;
                r.ip = v.substr(0, p1);
                r.port = static_cast<uint16_t>(std::strtoul(v.substr(p1 + 1, p2 - p1 - 1).c_str(), nullptr, 10));
                r.protocol = static_cast<uint8_t>(std::strtoul(v.substr(p2 + 1).c_str(), nullptr, 10));
                p->network.deny_ip_ports.push_back(std::move(r));
            }
            break;
        }
        case AEGIS_PCAT_DENY_BINARY_HASH:
            p->deny_binary_hashes.push_back(std::move(v));
            break;
        case AEGIS_PCAT_ALLOW_BINARY_HASH:
            p->allow_binary_hashes.push_back(std::move(v));
            break;
        case AEGIS_PCAT_TRUSTED_EXEC_HASH:
            p->trusted_exec_hashes.push_back(std::move(v));
            break;
        case AEGIS_PCAT_DENY_COMM:
            p->deny_comm.push_back(std::move(v));
            break;
        case AEGIS_PCAT_SCAN_PATH:
            p->scan_paths.push_back(std::move(v));
            break;
        case AEGIS_PCAT_CGROUP_DENY_INODE: {
            // "cgroup|dev:ino" (split on the FIRST '|')
            const auto bar = v.find('|');
            if (bar != std::string::npos) {
                CgroupDenyInodeRule r;
                r.cgroup = v.substr(0, bar);
                r.inode = parse_inode(v.substr(bar + 1));
                p->cgroup.deny_inodes.push_back(std::move(r));
            }
            break;
        }
        case AEGIS_PCAT_CGROUP_DENY_IP: {
            // "cgroup|ip"
            const auto bar = v.find('|');
            if (bar != std::string::npos) {
                CgroupDenyIpRule r;
                r.cgroup = v.substr(0, bar);
                r.ip = v.substr(bar + 1);
                p->cgroup.deny_ips.push_back(std::move(r));
            }
            break;
        }
        default:
            break;
    }
}

extern "C" void b_add_cgroup_id(void* ctx, uint64_t id)
{
    static_cast<Policy*>(ctx)->allow_cgroup_ids.push_back(id);
}

extern "C" void b_add_deny_port(void* ctx, uint16_t port, uint8_t proto, uint8_t dir)
{
    PortRule r;
    r.port = port;
    r.protocol = proto;
    r.direction = dir;
    static_cast<Policy*>(ctx)->network.deny_ports.push_back(r);
}

extern "C" void b_add_cgroup_deny_port(void* ctx, const char* cg, size_t cglen, uint16_t port, uint8_t proto,
                                       uint8_t dir)
{
    CgroupDenyPortRule r;
    r.cgroup = std::string(cg, cglen);
    r.port.port = port;
    r.port.protocol = proto;
    r.port.direction = dir;
    static_cast<Policy*>(ctx)->cgroup.deny_ports.push_back(std::move(r));
}

} // namespace

bool rust_build_policy(const std::string& policy_bytes, Policy& out)
{
    out = Policy{};
    AegisPolicyBuilder b{};
    b.ctx = &out;
    b.set_version = b_set_version;
    b.set_flag = b_set_flag;
    b.add_string = b_add_string;
    b.add_cgroup_id = b_add_cgroup_id;
    b.add_deny_port = b_add_deny_port;
    b.add_cgroup_deny_port = b_add_cgroup_deny_port;
    // 0 == clean policy built; >0 == parse error (nothing built); <0 == bad call.
    return aegis_policy_build(policy_bytes.data(), policy_bytes.size(), &b) == 0;
}

#else // !AEGIS_RUST_SHADOW

bool rust_build_policy(const std::string& /*policy_bytes*/, Policy& /*out*/)
{
    return false;
}

#endif

} // namespace aegis
