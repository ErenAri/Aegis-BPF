// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Policy command implementations
 */

#include "commands_policy.hpp"

#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

#include "bpf_ops.hpp"
#include "crypto.hpp"
#include "logging.hpp"
#include "network_ops.hpp"
#include "policy.hpp"
#include "sha256.hpp"
#include "tracing.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace aegis {

int cmd_policy_lint(const std::string& path)
{
    const std::string trace_id = make_span_id("trace-policy-lint");
    ScopedSpan span("cli.policy_lint", trace_id);
    auto result = policy_lint(path);
    if (!result) {
        span.fail(result.error().to_string());
    }
    return result ? 0 : 1;
}

int cmd_policy_lint_fix(const std::string& path, const std::string& out_path)
{
    const std::string trace_id = make_span_id("trace-policy-lint-fix");
    ScopedSpan span("cli.policy_lint_fix", trace_id);

    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);
    report_policy_issues(issues);
    if (!result) {
        span.fail(result.error().to_string());
        return 1;
    }
    if (issues.has_errors()) {
        span.fail("Policy contains errors");
        return 1;
    }

    const Policy& policy = *result;
    std::vector<std::string> deny_inodes;
    deny_inodes.reserve(policy.deny_inodes.size());
    for (const auto& id : policy.deny_inodes) {
        deny_inodes.push_back(inode_to_string(id));
    }

    std::vector<std::string> allow_entries = policy.allow_cgroup_paths;
    allow_entries.reserve(policy.allow_cgroup_paths.size() + policy.allow_cgroup_ids.size());
    for (uint64_t id : policy.allow_cgroup_ids) {
        allow_entries.push_back("cgid:" + std::to_string(id));
    }

    std::string target = out_path.empty() ? (path + ".fixed") : out_path;
    auto write_result = write_policy_file(target, policy.deny_paths, deny_inodes, allow_entries);
    if (!write_result) {
        logger().log(SLOG_ERROR("Failed to write normalized policy")
                         .field("path", target)
                         .field("error", write_result.error().to_string()));
        span.fail(write_result.error().to_string());
        return 1;
    }

    std::cout << "Wrote normalized policy to " << target << "\n";
    return 0;
}

int cmd_policy_validate(const std::string& path, bool verbose)
{
    const std::string trace_id = make_span_id("trace-policy-validate");
    ScopedSpan span("cli.policy_validate", trace_id);
    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);
    report_policy_issues(issues);
    if (!result) {
        logger().log(SLOG_ERROR("Policy validation failed").field("error", result.error().to_string()));
        span.fail(result.error().to_string());
        return 1;
    }
    const Policy& policy = *result;

    std::cout << "Policy validation successful.\n\n";
    std::cout << "Summary:\n";
    std::cout << "  Deny paths: " << policy.deny_paths.size() << "\n";
    std::cout << "  Deny inodes: " << policy.deny_inodes.size() << "\n";
    std::cout << "  Allow cgroup IDs: " << policy.allow_cgroup_ids.size() << "\n";
    std::cout << "  Allow cgroup paths: " << policy.allow_cgroup_paths.size() << "\n";

    if (policy.network.enabled) {
        std::cout << "  Network deny IPs: " << policy.network.deny_ips.size() << "\n";
        std::cout << "  Network deny CIDRs: " << policy.network.deny_cidrs.size() << "\n";
        std::cout << "  Network deny ports: " << policy.network.deny_ports.size() << "\n";
        std::cout << "  Network deny IP:ports: " << policy.network.deny_ip_ports.size() << "\n";
    }

    if (verbose) {
        if (!policy.deny_paths.empty()) {
            std::cout << "\nDeny paths:\n";
            for (const auto& p : policy.deny_paths) {
                std::cout << "  - " << p << "\n";
            }
        }
        if (!policy.deny_inodes.empty()) {
            std::cout << "\nDeny inodes:\n";
            for (const auto& id : policy.deny_inodes) {
                std::cout << "  - " << id.dev << ":" << id.ino << "\n";
            }
        }
        if (!policy.allow_cgroup_paths.empty()) {
            std::cout << "\nAllow cgroup paths:\n";
            for (const auto& p : policy.allow_cgroup_paths) {
                std::cout << "  - " << p << "\n";
            }
        }
        if (policy.network.enabled) {
            if (!policy.network.deny_ips.empty()) {
                std::cout << "\nNetwork deny IPs:\n";
                for (const auto& ip : policy.network.deny_ips) {
                    std::cout << "  - " << ip << "\n";
                }
            }
            if (!policy.network.deny_cidrs.empty()) {
                std::cout << "\nNetwork deny CIDRs:\n";
                for (const auto& cidr : policy.network.deny_cidrs) {
                    std::cout << "  - " << cidr << "\n";
                }
            }
            if (!policy.network.deny_ports.empty()) {
                std::cout << "\nNetwork deny ports:\n";
                for (const auto& pr : policy.network.deny_ports) {
                    std::string proto = (pr.protocol == kProtoTCP) ? "tcp" : (pr.protocol == kProtoUDP) ? "udp" : "any";
                    std::string dir = (pr.direction == 0) ? "egress" : (pr.direction == 1) ? "bind" : "both";
                    std::cout << "  - port " << pr.port << " (" << proto << ", " << dir << ")\n";
                }
            }
            if (!policy.network.deny_ip_ports.empty()) {
                std::cout << "\nNetwork deny IP:ports:\n";
                for (const auto& rule : policy.network.deny_ip_ports) {
                    std::cout << "  - " << format_ip_port_rule(rule) << "\n";
                }
            }
        }
    }

    if (!issues.warnings.empty()) {
        std::cout << "\nWarnings: " << issues.warnings.size() << "\n";
    }

    return 0;
}

// Emit a complete, canonical, machine-comparable dump of the parsed policy for
// the Rust differential-parity harness (scripts/rust_policy_parity.sh). This is
// a hidden diagnostic/test seam, not part of the public CLI: it mirrors, byte
// for byte over the UTF-8 input domain, what rust/aegis-parser's
// canonical_report() produces, so the two parsers can be proven *structurally*
// equivalent (every stored entry, not just counts and issues).
//
// Layout (fixed section order; entries in stored insertion order):
//   * no errors: `version`, `flag` lines, then every entry in every category,
//     then sorted `WARN` lines.
//   * >=1 error: the parser discards the partial policy on error, so only sorted
//     `ERROR` then sorted `WARN` lines are emitted.
// Ports render as the parsed numeric tuple `port:proto:dir`; deny_ip_port and
// cgroup_deny_inode/ip render as their canonical dedup keys. Only the canonical
// dump goes to stdout (the harness reads stdout; logs go to stderr).
int cmd_policy_canonical(const std::string& path)
{
    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);
    if (result) {
        detect_policy_conflicts(*result, issues);
    }

    auto port_tuple = [](const PortRule& pr) {
        return std::to_string(pr.port) + ":" + std::to_string(static_cast<unsigned>(pr.protocol)) + ":" +
               std::to_string(static_cast<unsigned>(pr.direction));
    };

    std::string out;
    if (!issues.has_errors()) {
        const Policy& policy = *result;
        out += "version " + std::to_string(policy.version) + "\n";
        // Flag order MUST match the rust/aegis-parser `Flag` enum declaration
        // order (its BTreeSet<Flag> iterates in that order), NOT alphabetical.
        if (policy.protect_connect)
            out += "flag protect_connect\n";
        if (policy.protect_runtime_deps)
            out += "flag protect_runtime_deps\n";
        if (policy.require_ima_appraisal)
            out += "flag require_ima_appraisal\n";
        if (policy.ima_fail_closed)
            out += "flag ima_fail_closed\n";
        if (policy.deny_ptrace)
            out += "flag deny_ptrace\n";
        if (policy.deny_module_load)
            out += "flag deny_module_load\n";
        if (policy.deny_bpf)
            out += "flag deny_bpf\n";

        for (const auto& v : policy.deny_paths)
            out += "deny_path " + v + "\n";
        for (const auto& v : policy.protect_paths)
            out += "protect_path " + v + "\n";
        for (const auto& id : policy.deny_inodes)
            out += "deny_inode " + inode_to_string(id) + "\n";
        for (uint64_t id : policy.allow_cgroup_ids)
            out += "allow_cgroup_id " + std::to_string(id) + "\n";
        for (const auto& v : policy.allow_cgroup_paths)
            out += "allow_cgroup_path " + v + "\n";
        for (const auto& v : policy.network.deny_ips)
            out += "deny_ip " + v + "\n";
        for (const auto& v : policy.network.deny_cidrs)
            out += "deny_cidr " + v + "\n";
        for (const auto& pr : policy.network.deny_ports)
            out += "deny_port " + port_tuple(pr) + "\n";
        for (const auto& r : policy.network.deny_ip_ports)
            out += "deny_ip_port " + r.ip + "|" + std::to_string(r.port) + "|" +
                   std::to_string(static_cast<unsigned>(r.protocol)) + "\n";
        for (const auto& v : policy.deny_binary_hashes)
            out += "deny_binary_hash " + v + "\n";
        for (const auto& v : policy.allow_binary_hashes)
            out += "allow_binary_hash " + v + "\n";
        for (const auto& v : policy.trusted_exec_hashes)
            out += "trusted_exec_hash " + v + "\n";
        for (const auto& v : policy.deny_comm)
            out += "deny_comm " + v + "\n";
        for (const auto& v : policy.scan_paths)
            out += "scan_paths " + v + "\n";
        for (const auto& r : policy.cgroup.deny_inodes)
            out += "cgroup_deny_inode " + r.cgroup + "|" + inode_to_string(r.inode) + "\n";
        for (const auto& r : policy.cgroup.deny_ips)
            out += "cgroup_deny_ip " + r.cgroup + "|" + r.ip + "\n";
        for (const auto& r : policy.cgroup.deny_ports)
            out += "cgroup_deny_port " + r.cgroup + "|" + port_tuple(r.port) + "\n";
    }

    std::vector<std::string> errs = issues.errors;
    std::vector<std::string> warns = issues.warnings;
    std::sort(errs.begin(), errs.end());
    std::sort(warns.begin(), warns.end());
    for (const auto& e : errs)
        out += "ERROR " + e + "\n";
    for (const auto& w : warns)
        out += "WARN " + w + "\n";

    std::cout << out;
    return issues.has_errors() ? 1 : 0;
}

// Emit a canonical, machine-comparable dump of a parsed signed-policy-bundle for
// the Rust differential-parity harness (scripts/rust_bundle_parity.sh). Hidden
// diagnostic/test seam mirroring rust/aegis-parser's bundle::canonical_report
// byte-for-byte over the UTF-8 input domain, so the two bundle decoders can be
// proven structurally equivalent. On success: `ok` + every parsed field (byte
// arrays as lowercase hex, policy body as length + FNV-1a). On failure:
// `err <primary message>` (Error::message(), matching the Rust error strings).
int cmd_policy_bundle_canonical(const std::string& path)
{
    std::ifstream in(path);
    if (!in.is_open()) {
        // The harness only feeds existing files; this mirrors the Rust bin's
        // read-failure path (exit 2, nothing on stdout) and is just defensive.
        std::cerr << "error: cannot read " << path << "\n";
        return 2;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string content = ss.str();

    auto result = parse_signed_bundle(content);
    std::string out;
    if (!result) {
        out += "err " + result.error().message() + "\n";
        std::cout << out;
        return 1;
    }

    auto to_hex = [](const uint8_t* data, size_t len) {
        static const char* digits = "0123456789abcdef";
        std::string s;
        s.reserve(len * 2);
        for (size_t i = 0; i < len; ++i) {
            s += digits[(data[i] >> 4) & 0xf];
            s += digits[data[i] & 0xf];
        }
        return s;
    };
    auto fnv1a64 = [](const std::string& data) {
        uint64_t hash = 0xcbf29ce484222325ULL;
        for (unsigned char c : data) {
            hash ^= static_cast<uint64_t>(c);
            hash *= 0x100000001b3ULL;
        }
        return hash;
    };

    const SignedPolicyBundle& b = *result;
    char fnvbuf[24];
    std::snprintf(fnvbuf, sizeof(fnvbuf), "%016llx", static_cast<unsigned long long>(fnv1a64(b.policy_content)));

    out += "ok\n";
    out += "format_version " + std::to_string(b.format_version) + "\n";
    out += "policy_version " + std::to_string(b.policy_version) + "\n";
    out += "timestamp " + std::to_string(b.timestamp) + "\n";
    out += "expires " + std::to_string(b.expires) + "\n";
    out += "signer_key " + to_hex(b.signer_key.data(), b.signer_key.size()) + "\n";
    out += "signature " + to_hex(b.signature.data(), b.signature.size()) + "\n";
    out += "policy_sha256 " + b.policy_sha256 + "\n";
    out += "policy_content_len " + std::to_string(b.policy_content.size()) + "\n";
    out += "policy_content_fnv1a64 " + std::string(fnvbuf) + "\n";

    std::cout << out;
    return 0;
}

// Emit a canonical, machine-comparable dump of a decoded BPF ring-buffer event
// record for the Rust differential-parity harness (scripts/rust_event_parity.sh).
// Hidden diagnostic/test seam mirroring rust/aegis-parser's event::canonical_report
// byte-for-byte. The decode walks the record through the SAME `Event` union access
// that the production consumer `handle_event` uses (src/events.cpp), so the
// compiler's own struct layout is the ground truth the Rust port's fixed offsets
// are proven against. The dump pins the memory-unsafe decode surface (field
// offsets, integer endianness, NUL-terminated char[] extraction, direction/
// rule_type -> label derivation): ints as decimal, char[]/address bytes as
// length-exact lowercase hex. A short record -> `err short_buffer <len>` (the
// bounds check handle_event lacks); an unrecognized type -> `unknown_type <n>`
// (handle_event prints nothing). Address text formatting (inet_ntop) is
// presentation, not decode, and is intentionally out of scope.
// Wire-layout contract for the event decoder. The Rust port
// (rust/aegis-parser/src/event.rs) mirrors these exact offsets as hard-coded
// `PAYLOAD + k` reads; the differential-parity harness proves the two agree at
// runtime, and these compile-time guards make a future struct-layout change a
// hard *build* failure here (a loud signal that the Rust offsets must be updated
// in lockstep) rather than a silent parity-gate red.
static_assert(sizeof(Event) == 344, "Event size changed — update rust event decoder offsets");
static_assert(offsetof(Event, exec) == 8, "Event union payload offset changed");
static_assert(offsetof(Event, exec_argv) == 8 && offsetof(Event, block) == 8 && offsetof(Event, net_block) == 8 &&
                  offsetof(Event, forensic) == 8 && offsetof(Event, kernel_block) == 8 &&
                  offsetof(Event, overlay_copy_up) == 8,
              "Event union payload offset changed");
static_assert(offsetof(ExecEvent, comm) == 24 && offsetof(ExecEvent, ancestor_pids) == 40 &&
                  offsetof(ExecEvent, ancestor_count) == 72,
              "ExecEvent layout changed — update rust event decoder");
static_assert(offsetof(ExecArgvEvent, argc) == 16 && offsetof(ExecArgvEvent, total_len) == 18 &&
                  offsetof(ExecArgvEvent, argv) == 24,
              "ExecArgvEvent layout changed — update rust event decoder");
static_assert(offsetof(BlockEvent, pid) == 24 && offsetof(BlockEvent, comm) == 40 && offsetof(BlockEvent, ino) == 56 &&
                  offsetof(BlockEvent, dev) == 64 && offsetof(BlockEvent, path) == 68 &&
                  offsetof(BlockEvent, action) == 324,
              "BlockEvent layout changed — update rust event decoder");
static_assert(offsetof(NetBlockEvent, comm) == 32 && offsetof(NetBlockEvent, family) == 48 &&
                  offsetof(NetBlockEvent, protocol) == 49 && offsetof(NetBlockEvent, local_port) == 50 &&
                  offsetof(NetBlockEvent, remote_port) == 52 && offsetof(NetBlockEvent, direction) == 54 &&
                  offsetof(NetBlockEvent, remote_ipv4) == 56 && offsetof(NetBlockEvent, remote_ipv6) == 60 &&
                  offsetof(NetBlockEvent, action) == 76 && offsetof(NetBlockEvent, rule_type) == 84,
              "NetBlockEvent layout changed — update rust event decoder");
static_assert(offsetof(ForensicEvent, pid) == 4 && offsetof(ForensicEvent, ppid) == 8 &&
                  offsetof(ForensicEvent, comm) == 40 && offsetof(ForensicEvent, uid) == 68 &&
                  offsetof(ForensicEvent, gid) == 72 && offsetof(ForensicEvent, exec_ino) == 80 &&
                  offsetof(ForensicEvent, exec_dev) == 88 && offsetof(ForensicEvent, exec_stage) == 92 &&
                  offsetof(ForensicEvent, action) == 96,
              "ForensicEvent layout changed — update rust event decoder");
static_assert(offsetof(KernelBlockEvent, comm) == 32 && offsetof(KernelBlockEvent, target_pid) == 48 &&
                  offsetof(KernelBlockEvent, action) == 56 && offsetof(KernelBlockEvent, rule_type) == 64,
              "KernelBlockEvent layout changed — update rust event decoder");
static_assert(offsetof(OverlayCopyUpEvent, cgid) == 8 && offsetof(OverlayCopyUpEvent, src_ino) == 16 &&
                  offsetof(OverlayCopyUpEvent, src_dev) == 24 && offsetof(OverlayCopyUpEvent, deny_flags) == 32,
              "OverlayCopyUpEvent layout changed — update rust event decoder");

int cmd_policy_event_canonical(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        std::cerr << "error: cannot read " << path << "\n";
        return 2;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string content = ss.str();

    if (content.size() < sizeof(Event)) {
        std::cout << "err short_buffer " << content.size() << "\n";
        return 0;
    }

    // Copy into a properly-aligned Event (handle_event reinterpret_casts an
    // already-aligned ringbuf record; an aligned local makes the field reads
    // well-defined here too). Trailing bytes beyond sizeof(Event) are ignored,
    // exactly as handle_event ignores its size argument.
    Event ev{};
    std::memcpy(&ev, content.data(), sizeof(Event));

    auto hex = [](const uint8_t* data, size_t len) {
        static const char* digits = "0123456789abcdef";
        std::string s;
        s.reserve(len * 2);
        for (size_t i = 0; i < len; ++i) {
            s += digits[(data[i] >> 4) & 0xf];
            s += digits[data[i] & 0xf];
        }
        return s;
    };
    // Hex of to_string(buf, n) == string(buf, strnlen(buf, n)): the bytes up to
    // the first NUL within the fixed width.
    auto cstr_hex = [&hex](const char* buf, size_t n) {
        std::string s = to_string(buf, n);
        return hex(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    };

    std::string out;
    auto kv = [&out](const char* k, const std::string& v) {
        out += k;
        out += ' ';
        out += v;
        out += '\n';
    };
    auto kvu = [&out](const char* k, unsigned long long v) {
        out += k;
        out += ' ';
        out += std::to_string(v);
        out += '\n';
    };

    const uint32_t type = ev.type;
    if (type == EVENT_EXEC) {
        const ExecEvent& e = ev.exec;
        kv("type", "exec");
        kvu("pid", e.pid);
        kvu("ppid", e.ppid);
        kvu("start_time", e.start_time);
        kvu("cgid", e.cgid);
        kv("comm_hex", cstr_hex(e.comm, sizeof(e.comm)));
        kvu("ancestor_count", e.ancestor_count);
        std::string ancestors;
        for (uint8_t i = 0; i < e.ancestor_count && i < kAncestorMaxDepth; ++i) {
            if (i > 0)
                ancestors += ',';
            ancestors += std::to_string(e.ancestor_pids[i]);
        }
        kv("ancestors", ancestors);
    } else if (type == EVENT_BLOCK) {
        const BlockEvent& e = ev.block;
        kv("type", "block");
        kvu("pid", e.pid);
        kvu("ppid", e.ppid);
        kvu("start_time", e.start_time);
        kvu("parent_start_time", e.parent_start_time);
        kvu("cgid", e.cgid);
        kv("comm_hex", cstr_hex(e.comm, sizeof(e.comm)));
        kvu("ino", e.ino);
        kvu("dev", e.dev);
        kv("path_hex", cstr_hex(e.path, sizeof(e.path)));
        kv("action_hex", cstr_hex(e.action, sizeof(e.action)));
    } else if (type == EVENT_EXEC_ARGV) {
        const ExecArgvEvent& e = ev.exec_argv;
        kv("type", "exec_argv");
        kvu("pid", e.pid);
        kvu("start_time", e.start_time);
        kvu("argc", e.argc);
        kvu("total_len", e.total_len);
        const size_t used = (e.argc < kMaxArgvEntries) ? e.argc : kMaxArgvEntries;
        kvu("argv_count", used);
        for (size_t i = 0; i < used; ++i) {
            kv(("arg" + std::to_string(i) + "_hex").c_str(), cstr_hex(&e.argv[i * kArgvSlot], kArgvSlot));
        }
    } else if (type == EVENT_FORENSIC_BLOCK) {
        const ForensicEvent& e = ev.forensic;
        kv("type", "forensic_block");
        kvu("pid", e.pid);
        kvu("ppid", e.ppid);
        kvu("start_time", e.start_time);
        kvu("parent_start_time", e.parent_start_time);
        kvu("cgid", e.cgid);
        kv("comm_hex", cstr_hex(e.comm, sizeof(e.comm)));
        kvu("ino", e.ino);
        kvu("dev", e.dev);
        kvu("uid", e.uid);
        kvu("gid", e.gid);
        kvu("exec_ino", e.exec_ino);
        kvu("exec_dev", e.exec_dev);
        kvu("exec_stage", e.exec_stage);
        kvu("verified_exec", e.verified_exec);
        kvu("exec_identity_known", e.exec_identity_known);
        kv("action_hex", cstr_hex(e.action, sizeof(e.action)));
    } else if (type == EVENT_NET_CONNECT_BLOCK || type == EVENT_NET_BIND_BLOCK || type == EVENT_NET_LISTEN_BLOCK ||
               type == EVENT_NET_ACCEPT_BLOCK || type == EVENT_NET_SENDMSG_BLOCK || type == EVENT_NET_RECVMSG_BLOCK) {
        const NetBlockEvent& e = ev.net_block;
        const char* label = (e.direction == 0)   ? "net_connect_block"
                            : (e.direction == 1) ? "net_bind_block"
                            : (e.direction == 2) ? "net_listen_block"
                            : (e.direction == 3) ? "net_accept_block"
                            : (e.direction == 4) ? "net_sendmsg_block"
                                                 : "net_recvmsg_block";
        kv("type", label);
        kvu("pid", e.pid);
        kvu("ppid", e.ppid);
        kvu("start_time", e.start_time);
        kvu("parent_start_time", e.parent_start_time);
        kvu("cgid", e.cgid);
        kv("comm_hex", cstr_hex(e.comm, sizeof(e.comm)));
        kv("family", e.family == kFamilyIPv4 ? "ipv4" : "ipv6");
        kvu("family_raw", e.family);
        std::string proto = (e.protocol == kProtoTCP)   ? "tcp"
                            : (e.protocol == kProtoUDP) ? "udp"
                                                        : std::to_string(e.protocol);
        kv("protocol", proto);
        kvu("local_port", e.local_port);
        kvu("remote_port", e.remote_port);
        kvu("direction", e.direction);
        kv("remote_ipv4_hex", hex(reinterpret_cast<const uint8_t*>(&e.remote_ipv4), sizeof(e.remote_ipv4)));
        kv("remote_ipv6_hex", hex(e.remote_ipv6, sizeof(e.remote_ipv6)));
        kv("action_hex", cstr_hex(e.action, sizeof(e.action)));
        kv("rule_type_hex", cstr_hex(e.rule_type, sizeof(e.rule_type)));
    } else if (type == EVENT_KERNEL_PTRACE_BLOCK || type == EVENT_KERNEL_MODULE_BLOCK ||
               type == EVENT_KERNEL_BPF_BLOCK) {
        const KernelBlockEvent& e = ev.kernel_block;
        kv("type", "kernel_block");
        kvu("pid", e.pid);
        kvu("ppid", e.ppid);
        kvu("start_time", e.start_time);
        kvu("parent_start_time", e.parent_start_time);
        kvu("cgid", e.cgid);
        kv("comm_hex", cstr_hex(e.comm, sizeof(e.comm)));
        kvu("target_pid", e.target_pid);
        kv("action_hex", cstr_hex(e.action, sizeof(e.action)));
        kv("rule_type_hex", cstr_hex(e.rule_type, sizeof(e.rule_type)));
        // print_kernel_block_event derives event_type = "kernel_" + rule_type +
        // "_block"; emit the derived label as hex so the derivation is pinned.
        const std::string derived = "kernel_" + to_string(e.rule_type, sizeof(e.rule_type)) + "_block";
        kv("event_type_hex", hex(reinterpret_cast<const uint8_t*>(derived.data()), derived.size()));
    } else if (type == EVENT_OVERLAY_COPY_UP) {
        const OverlayCopyUpEvent& e = ev.overlay_copy_up;
        kv("type", "overlay_copy_up");
        kvu("pid", e.pid);
        kvu("cgid", e.cgid);
        kvu("src_ino", e.src_ino);
        kvu("src_dev", e.src_dev);
        kvu("deny_flags", e.deny_flags);
    } else {
        out = "unknown_type " + std::to_string(type) + "\n";
    }

    std::cout << out;
    return 0;
}

int cmd_policy_apply(const std::string& path, bool reset, const std::string& sha256, const std::string& sha256_file,
                     bool rollback_on_failure)
{
    const std::string trace_id = make_span_id("trace-policy-cli");
    ScopedSpan span("cli.policy_apply", trace_id);
    auto result = policy_apply(path, reset, sha256, sha256_file, rollback_on_failure, trace_id);
    if (!result) {
        span.fail(result.error().to_string());
    }
    return result ? 0 : 1;
}

int cmd_policy_apply_signed(const std::string& bundle_path, bool require_signature)
{
    const std::string trace_id = make_span_id("trace-policy-signed");
    ScopedSpan root_span("cli.policy_apply_signed", trace_id);
    auto fail = [&](const std::string& message) -> int {
        root_span.fail(message);
        return 1;
    };

    auto perms_result = validate_file_permissions(bundle_path, false);
    if (!perms_result) {
        logger().log(SLOG_ERROR("Policy file permission check failed")
                         .field("path", bundle_path)
                         .field("error", perms_result.error().to_string()));
        return fail(perms_result.error().to_string());
    }

    std::ifstream in(bundle_path);
    if (!in.is_open()) {
        logger().log(SLOG_ERROR("Failed to open bundle file").field("path", bundle_path));
        return fail("Failed to open bundle file");
    }

    std::stringstream ss;
    ss << in.rdbuf();
    std::string content = ss.str();

    if (content.starts_with("AEGIS-POLICY-BUNDLE")) {
        auto bundle_result = parse_signed_bundle(content);
        if (!bundle_result) {
            logger().log(SLOG_ERROR("Failed to parse signed bundle").field("error", bundle_result.error().to_string()));
            return fail(bundle_result.error().to_string());
        }
        SignedPolicyBundle bundle = *bundle_result;

        auto keys_result = load_trusted_keys();
        if (!keys_result) {
            logger().log(SLOG_ERROR("Failed to load trusted keys").field("error", keys_result.error().to_string()));
            return fail(keys_result.error().to_string());
        }
        const auto& trusted_keys = *keys_result;
        if (trusted_keys.empty()) {
            logger().log(SLOG_ERROR("No trusted keys configured - cannot verify signed policy"));
            return fail("No trusted keys configured - cannot verify signed policy");
        }

        auto verify_result = verify_bundle(bundle, trusted_keys);
        if (!verify_result) {
            logger().log(SLOG_ERROR("Bundle verification failed").field("error", verify_result.error().to_string()));
            return fail(verify_result.error().to_string());
        }

        if (!check_version_acceptable(bundle)) {
            logger().log(SLOG_ERROR("Policy version rollback rejected")
                             .field("bundle_version", static_cast<int64_t>(bundle.policy_version))
                             .field("current_version", static_cast<int64_t>(read_version_counter())));
            return fail("Policy version rollback rejected");
        }

        char temp_path[] = "/tmp/aegisbpf_policy_XXXXXX";
        int temp_fd = mkstemp(temp_path);
        if (temp_fd < 0) {
            logger().log(SLOG_ERROR("Failed to create temp policy file").error_code(errno));
            return fail("Failed to create temp policy file");
        }

        /* RAII guard: unlink the temp file on every exit path below,
         * including future early-returns that a reader might add between
         * here and the apply call. The fd is closed separately because
         * we need it open only for the write loop. */
        struct TempPathGuard {
            const char* path;
            ~TempPathGuard()
            {
                if (path) {
                    std::remove(path);
                }
            }
        } temp_guard{temp_path};

        {
            const auto& content_ref = bundle.policy_content;
            ssize_t written = 0;
            size_t total = content_ref.size();
            while (static_cast<size_t>(written) < total) {
                ssize_t n = ::write(temp_fd, content_ref.data() + written, total - static_cast<size_t>(written));
                if (n < 0) {
                    ::close(temp_fd);
                    logger().log(SLOG_ERROR("Failed to write temp policy file").error_code(errno));
                    return fail("Failed to write temp policy file");
                }
                written += n;
            }
            ::close(temp_fd);
        }

        auto apply_result = policy_apply(temp_path, false, bundle.policy_sha256, "", true, trace_id);
        if (!apply_result) {
            return fail(apply_result.error().to_string());
        }

        auto write_result = write_version_counter(bundle.policy_version);
        if (!write_result) {
            logger().log(
                SLOG_WARN("Failed to update version counter").field("error", write_result.error().to_string()));
        }

        return 0;
    }

    if (require_signature) {
        logger().log(SLOG_ERROR("Unsigned policy rejected (--require-signature specified)"));
        return fail("Unsigned policy rejected (--require-signature specified)");
    }

    auto apply_result = policy_apply(bundle_path, false, "", "", true, trace_id);
    if (!apply_result) {
        return fail(apply_result.error().to_string());
    }
    return 0;
}

int cmd_policy_sign(const std::string& policy_path, const std::string& key_path, const std::string& output_path)
{
    const std::string trace_id = make_span_id("trace-policy-sign");
    ScopedSpan span("cli.policy_sign", trace_id);
    auto fail = [&](const std::string& message) -> int {
        span.fail(message);
        return 1;
    };

    auto policy_perms = validate_file_permissions(policy_path, false);
    if (!policy_perms) {
        logger().log(SLOG_ERROR("Policy file permission check failed")
                         .field("path", policy_path)
                         .field("error", policy_perms.error().to_string()));
        return fail(policy_perms.error().to_string());
    }
    auto key_perms = validate_file_permissions(key_path, false);
    if (!key_perms) {
        logger().log(SLOG_ERROR("Signing key permission check failed")
                         .field("path", key_path)
                         .field("error", key_perms.error().to_string()));
        return fail(key_perms.error().to_string());
    }

    std::ifstream policy_in(policy_path);
    if (!policy_in.is_open()) {
        logger().log(SLOG_ERROR("Failed to open policy file").field("path", policy_path));
        return fail("Failed to open policy file");
    }
    std::stringstream policy_ss;
    policy_ss << policy_in.rdbuf();
    std::string policy_content = policy_ss.str();

    std::ifstream key_in(key_path);
    if (!key_in.is_open()) {
        logger().log(SLOG_ERROR("Failed to open private key file").field("path", key_path));
        return fail("Failed to open private key file");
    }
    std::string key_hex;
    std::getline(key_in, key_hex);

    if (key_hex.size() != 128) {
        logger().log(SLOG_ERROR("Invalid private key format (expected 128 hex chars)"));
        return fail("Invalid private key format");
    }

    auto hex_value = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F')
            return 10 + (c - 'A');
        return -1;
    };

    SecretKey secret_key{};
    for (size_t i = 0; i < secret_key.size(); ++i) {
        int hi = hex_value(key_hex[2 * i]);
        int lo = hex_value(key_hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            logger().log(SLOG_ERROR("Invalid private key format (non-hex character)"));
            return fail("Invalid private key format");
        }
        secret_key[i] = static_cast<uint8_t>((hi << 4) | lo);
    }

    uint64_t version = read_version_counter() + 1;
    auto bundle_result = create_signed_bundle(policy_content, secret_key, version, 0);
    if (!bundle_result) {
        logger().log(SLOG_ERROR("Failed to create signed bundle").field("error", bundle_result.error().to_string()));
        return fail(bundle_result.error().to_string());
    }

    auto write_result = atomic_write_file(output_path, *bundle_result);
    if (!write_result) {
        logger().log(SLOG_ERROR("Failed to write output file")
                         .field("path", output_path)
                         .field("error", write_result.error().to_string()));
        return fail(write_result.error().to_string());
    }
    logger().log(SLOG_INFO("Policy signed successfully")
                     .field("output", output_path)
                     .field("version", static_cast<int64_t>(version)));
    return 0;
}

int cmd_policy_dry_run(const std::string& path, const std::string& sha256, const std::string& sha256_file)
{
    const std::string trace_id = make_span_id("trace-policy-dry-run");
    ScopedSpan span("cli.policy_dry_run", trace_id);
    auto fail = [&](const std::string& message) -> int {
        span.fail(message);
        return 1;
    };

    // Validate file permissions
    auto perms_result = validate_file_permissions(path, false);
    if (!perms_result) {
        logger().log(SLOG_ERROR("Policy file permission check failed")
                         .field("path", path)
                         .field("error", perms_result.error().to_string()));
        return fail(perms_result.error().to_string());
    }

    // Verify hash if provided
    std::string expected_hash = sha256;
    if (expected_hash.empty() && !sha256_file.empty()) {
        auto hash_perms = validate_file_permissions(sha256_file, false);
        if (!hash_perms) {
            return fail(hash_perms.error().to_string());
        }
        std::string hash_content;
        if (!read_sha256_file(sha256_file, hash_content)) {
            return fail("Failed to read sha256 file");
        }
        expected_hash = hash_content;
    }
    if (!expected_hash.empty()) {
        std::string computed;
        if (!verify_policy_hash(path, expected_hash, computed)) {
            logger().log(SLOG_ERROR("Policy sha256 mismatch (dry-run)"));
            return fail("Policy sha256 mismatch");
        }
        std::cout << "SHA-256: " << computed << " (verified)\n";
    } else {
        std::string computed;
        if (sha256_file_hex(path, computed)) {
            std::cout << "SHA-256: " << computed << "\n";
        }
    }

    // Parse and validate
    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);
    report_policy_issues(issues);
    if (!result) {
        return fail(result.error().to_string());
    }

    const Policy& policy = *result;

    std::cout << "\n[dry-run] Policy summary:\n";
    std::cout << "  Version: " << policy.version << "\n";
    std::cout << "  Deny paths: " << policy.deny_paths.size() << "\n";
    std::cout << "  Deny inodes: " << policy.deny_inodes.size() << "\n";
    std::cout << "  Allow cgroup IDs: " << policy.allow_cgroup_ids.size() << "\n";
    std::cout << "  Allow cgroup paths: " << policy.allow_cgroup_paths.size() << "\n";

    if (policy.network.enabled) {
        std::cout << "  Network deny IPs: " << policy.network.deny_ips.size() << "\n";
        std::cout << "  Network deny CIDRs: " << policy.network.deny_cidrs.size() << "\n";
        std::cout << "  Network deny ports: " << policy.network.deny_ports.size() << "\n";
        std::cout << "  Network deny IP:ports: " << policy.network.deny_ip_ports.size() << "\n";
    }

    if (!issues.warnings.empty()) {
        std::cout << "  Warnings: " << issues.warnings.size() << "\n";
    }

    std::cout << "\n[dry-run] No maps were modified.\n";
    return 0;
}

int cmd_policy_canary(const std::string& path, bool reset, const std::string& sha256, const std::string& sha256_file,
                      bool rollback_on_failure, uint32_t canary_seconds, uint32_t canary_threshold)
{
    const std::string trace_id = make_span_id("trace-policy-canary");
    ScopedSpan span("cli.policy_canary", trace_id);
    auto fail = [&](const std::string& message) -> int {
        span.fail(message);
        return 1;
    };

    std::cout << "[canary] Applying policy in canary mode (" << canary_seconds << "s observation window)\n";
    std::cout << "[canary] Deny rate threshold: " << canary_threshold << " denies/second\n";

    // Apply the policy
    auto apply_result = policy_apply(path, reset, sha256, sha256_file, rollback_on_failure, trace_id);
    if (!apply_result) {
        logger().log(SLOG_ERROR("Canary: policy apply failed").field("error", apply_result.error().to_string()));
        return fail(apply_result.error().to_string());
    }
    std::cout << "[canary] Policy applied successfully. Starting observation...\n";

    // Read initial block stats
    auto rlimit = bump_memlock_rlimit();
    if (!rlimit) {
        return fail("Failed to raise memlock rlimit");
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        std::cout << "[canary] Warning: Cannot read block stats (daemon may not be running)\n";
        std::cout << "[canary] Policy is applied. Monitor deny rate manually.\n";
        return 0;
    }

    auto initial_stats = read_block_stats_map(state.block_stats);
    uint64_t initial_blocks = initial_stats ? initial_stats->blocks : 0;

    // Observation loop: check every 5 seconds
    uint32_t elapsed = 0;
    uint32_t check_interval = (canary_seconds > 30) ? 5 : 1;
    bool threshold_breached = false;
    uint64_t prev_blocks = initial_blocks;

    while (elapsed < canary_seconds) {
        uint32_t sleep_time = std::min(check_interval, canary_seconds - elapsed);
        std::this_thread::sleep_for(std::chrono::seconds(sleep_time));
        elapsed += sleep_time;

        auto stats = read_block_stats_map(state.block_stats);
        if (!stats) {
            continue;
        }

        uint64_t current_blocks = stats->blocks;
        uint64_t delta = current_blocks - prev_blocks;
        double rate = static_cast<double>(delta) / static_cast<double>(sleep_time);

        std::cout << "[canary] t=" << elapsed << "s: " << delta << " denies in " << sleep_time << "s (rate=" << rate
                  << "/s)\n";

        if (rate > static_cast<double>(canary_threshold)) {
            threshold_breached = true;
            std::cout << "[canary] THRESHOLD BREACHED: deny rate " << rate << "/s > " << canary_threshold << "/s\n";
            break;
        }
        prev_blocks = current_blocks;
    }

    auto final_stats = read_block_stats_map(state.block_stats);
    uint64_t total_blocks = final_stats ? (final_stats->blocks - initial_blocks) : 0;

    if (threshold_breached) {
        std::cout << "[canary] FAIL: deny rate exceeded threshold during canary window\n";
        std::cout << "[canary] Total denies during canary: " << total_blocks << "\n";

        if (rollback_on_failure) {
            std::cout << "[canary] Rolling back policy...\n";
            auto rollback_result = policy_rollback();
            if (rollback_result) {
                std::cout << "[canary] Policy rolled back successfully\n";
            } else {
                logger().log(SLOG_ERROR("Canary: rollback failed").field("error", rollback_result.error().to_string()));
                std::cout << "[canary] WARNING: Rollback failed. Manual intervention required.\n";
            }
        }
        return 1;
    }

    std::cout << "[canary] PASS: canary observation completed\n";
    std::cout << "[canary] Total denies during canary: " << total_blocks << "\n";
    std::cout << "[canary] Policy is active.\n";
    return 0;
}

int cmd_policy_export(const std::string& path)
{
    const std::string trace_id = make_span_id("trace-policy-export");
    ScopedSpan span("cli.policy_export", trace_id);
    auto result = policy_export(path);
    if (!result) {
        span.fail(result.error().to_string());
    }
    return result ? 0 : 1;
}

int cmd_policy_show()
{
    const std::string trace_id = make_span_id("trace-policy-show");
    ScopedSpan span("cli.policy_show", trace_id);
    auto result = policy_show();
    if (!result) {
        span.fail(result.error().to_string());
    }
    return result ? 0 : 1;
}

int cmd_policy_rollback()
{
    const std::string trace_id = make_span_id("trace-policy-rollback");
    ScopedSpan span("cli.policy_rollback", trace_id);
    auto result = policy_rollback();
    if (!result) {
        span.fail(result.error().to_string());
    }
    return result ? 0 : 1;
}

} // namespace aegis
