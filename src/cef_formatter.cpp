// cppcheck-suppress-file missingIncludeSystem
#include "cef_formatter.hpp"

#include <chrono>
#include <cstring>
#include <sstream>
#include <string>

#ifndef AEGIS_VERSION_STRING
#    define AEGIS_VERSION_STRING "0.0.0"
#endif

namespace aegis {

namespace {

// CEF severity scale per ArcSight Implementation Standard:
// 0-3 Low, 4-6 Medium, 7-8 High, 9-10 Very-High. Audit-only is
// surfaced at Medium (4) — operator told us they want a record but
// did not opt to enforce. An enforced block (BLOCK / TERM / KILL)
// is High (8) — same severity-tier the OCSF formatter uses for the
// `kSeverityHigh` (4) bucket, just remapped to CEF's 0-10 scale.
constexpr int kSeverityAudit = 4;
constexpr int kSeverityEnforce = 8;

bool is_audit_action(const std::string& action) noexcept
{
    return action == "AUDIT" || action == "audit";
}

uint64_t epoch_ms_now() noexcept
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::string parent_folder_of(const std::string& path)
{
    if (path.empty()) {
        return {};
    }
    auto pos = path.find_last_of('/');
    if (pos == std::string::npos) {
        return {};
    }
    if (pos == 0) {
        return "/";
    }
    return path.substr(0, pos);
}

std::string basename_of(const std::string& path)
{
    if (path.empty()) {
        return {};
    }
    auto pos = path.find_last_of('/');
    if (pos == std::string::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

// Per CEF Implementation Standard: header fields must escape `\` and
// `|`. Newlines and carriage returns must be escaped because the CEF
// record is by definition single-line.
std::string cef_escape_header(const std::string& in)
{
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        switch (c) {
            case '\\':
                out += "\\\\";
                break;
            case '|':
                out += "\\|";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            default:
                out += c;
                break;
        }
    }
    return out;
}

// Per CEF Implementation Standard: extension *values* must escape `\`
// and `=`. Newlines/CR are also escaped (single-line invariant). The
// `|` character is permitted unescaped inside extension values per
// the spec — only the header forbids it. Keys are alphanumeric by
// design (no escaping needed).
std::string cef_escape_extension(const std::string& in)
{
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        switch (c) {
            case '\\':
                out += "\\\\";
                break;
            case '=':
                out += "\\=";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            default:
                out += c;
                break;
        }
    }
    return out;
}

void write_header(std::ostringstream& oss, const std::string& signature_id, const std::string& name, int severity)
{
    oss << "CEF:0" << "|" << cef_escape_header("AegisBPF Project") << "|" << cef_escape_header("AegisBPF") << "|"
        << cef_escape_header(AEGIS_VERSION_STRING) << "|" << cef_escape_header(signature_id) << "|"
        << cef_escape_header(name) << "|" << severity << "|";
}

class ExtensionWriter {
  public:
    explicit ExtensionWriter(std::ostringstream& oss) : oss_(oss) {}

    // Emit a `key=value` pair only when value is non-empty. CEF
    // permits omitting unknown fields entirely; an empty `key=` would
    // be ambiguous on parse, so we skip rather than emit it.
    void write_str(const char* key, const std::string& value)
    {
        if (value.empty()) {
            return;
        }
        if (!first_) {
            oss_ << ' ';
        }
        oss_ << key << '=' << cef_escape_extension(value);
        first_ = false;
    }

    void write_int(const char* key, long long value)
    {
        if (!first_) {
            oss_ << ' ';
        }
        oss_ << key << '=' << value;
        first_ = false;
    }

    void write_uint(const char* key, unsigned long long value)
    {
        if (!first_) {
            oss_ << ' ';
        }
        oss_ << key << '=' << value;
        first_ = false;
    }

  private:
    std::ostringstream& oss_;
    bool first_ = true;
};

const char* direction_signature(uint8_t direction) noexcept
{
    switch (direction) {
        case 0:
            return "aegis:net:connect";
        case 1:
            return "aegis:net:bind";
        case 2:
            return "aegis:net:listen";
        case 3:
            return "aegis:net:accept";
        case 4:
            return "aegis:net:send";
        case 5:
            return "aegis:net:recv";
        default:
            return "aegis:net:unknown";
    }
}

const char* direction_name(uint8_t direction) noexcept
{
    switch (direction) {
        case 0:
            return "Connect";
        case 1:
            return "Bind";
        case 2:
            return "Listen";
        case 3:
            return "Accept";
        case 4:
            return "Send";
        case 5:
            return "Receive";
        default:
            return "Unknown";
    }
}

} // namespace

bool is_cef_format_keyword(const std::string& value)
{
    return value == "cef" || value == "CEF" || value == "cef-1.0";
}

std::string format_block_event_cef(const BlockEvent& ev, const std::string& cgpath, const std::string& path,
                                   const std::string& resolved_path, const std::string& action, const std::string& comm,
                                   const std::string& exec_id, const std::string& parent_exec_id,
                                   const std::string& hostname)
{
    const bool audit = is_audit_action(action);
    const int severity = audit ? kSeverityAudit : kSeverityEnforce;
    const std::string& effective_path = !resolved_path.empty() ? resolved_path : path;
    const std::string parent = parent_folder_of(effective_path);
    const std::string basename = basename_of(effective_path);
    const std::string name = audit ? "AegisBPF File Open Audit Observed" : "AegisBPF File Open Denied";

    std::ostringstream oss;
    write_header(oss, "aegis:file:open", name, severity);

    ExtensionWriter ext(oss);
    ext.write_uint("rt", epoch_ms_now());
    ext.write_str("act", action);
    ext.write_str("outcome", "success");
    ext.write_str("msg", audit ? "AegisBPF audit: file open observed" : "AegisBPF: file open denied");
    ext.write_str("dvchost", hostname);
    ext.write_uint("spid", ev.pid);
    ext.write_str("sproc", comm);
    ext.write_str("fname", basename);
    ext.write_str("filePath", effective_path);
    // CEF has no standard "parent folder" key (`filePermission` is
    // permission bits, not a parent-folder pivot). Operators that need
    // it can derive it from `filePath`; we keep the record concise
    // rather than coining a non-standard key.
    (void)parent;
    ext.write_str("externalId", exec_id);
    if (!cgpath.empty()) {
        ext.write_str("cs1", cgpath);
        ext.write_str("cs1Label", "AegisCgroupPath");
    }
    if (!parent_exec_id.empty()) {
        ext.write_str("cs2", parent_exec_id);
        ext.write_str("cs2Label", "AegisParentExecId");
    }
    ext.write_uint("cn1", ev.cgid);
    ext.write_str("cn1Label", "AegisCgroupId");
    ext.write_uint("cn2", ev.ino);
    ext.write_str("cn2Label", "AegisInode");
    ext.write_uint("cn3", ev.dev);
    ext.write_str("cn3Label", "AegisDevice");

    return oss.str();
}

std::string format_net_block_event_cef(const NetBlockEvent& ev, const std::string& cgpath, const std::string& comm,
                                       const std::string& exec_id, const std::string& parent_exec_id,
                                       const std::string& event_type, const std::string& remote_ip,
                                       const std::string& hostname)
{
    const std::string action(ev.action, strnlen(ev.action, sizeof(ev.action)));
    const std::string rule_type(ev.rule_type, strnlen(ev.rule_type, sizeof(ev.rule_type)));
    const bool audit = is_audit_action(action);
    const int severity = audit ? kSeverityAudit : kSeverityEnforce;

    const char* sig = direction_signature(ev.direction);
    const char* dir_name = direction_name(ev.direction);
    std::string name;
    {
        std::ostringstream tmp;
        tmp << "AegisBPF Network " << dir_name << (audit ? " Audit Observed" : " Denied");
        name = tmp.str();
    }

    // Endpoint orientation matches the OCSF formatter:
    // egress(0)/send(4): peer is destination, local is source.
    // accept(3)/recv(5): peer is source, local is destination.
    // bind(1)/listen(2): no remote peer yet — local port becomes dpt.
    const bool peer_is_destination = (ev.direction == 0 || ev.direction == 4);
    const bool peer_is_source = (ev.direction == 3 || ev.direction == 5);

    std::ostringstream oss;
    write_header(oss, sig, name, severity);

    ExtensionWriter ext(oss);
    ext.write_uint("rt", epoch_ms_now());
    ext.write_str("act", action);
    ext.write_str("outcome", "success");
    {
        std::string m = audit ? "AegisBPF audit: network operation observed (" : "AegisBPF: network operation denied (";
        m += event_type;
        m += ')';
        ext.write_str("msg", m);
    }
    ext.write_str("dvchost", hostname);
    ext.write_uint("spid", ev.pid);
    ext.write_str("sproc", comm);

    // Protocol — `proto` per CEF dictionary takes the protocol name.
    if (ev.protocol == kProtoTCP) {
        ext.write_str("proto", "tcp");
    } else if (ev.protocol == kProtoUDP) {
        ext.write_str("proto", "udp");
    }

    if (peer_is_destination) {
        if (!remote_ip.empty() && remote_ip != "0.0.0.0" && remote_ip != "::") {
            ext.write_str("dst", remote_ip);
        }
        if (ev.remote_port != 0) {
            ext.write_uint("dpt", ev.remote_port);
        }
        if (ev.local_port != 0) {
            ext.write_uint("spt", ev.local_port);
        }
    } else if (peer_is_source) {
        if (!remote_ip.empty() && remote_ip != "0.0.0.0" && remote_ip != "::") {
            ext.write_str("src", remote_ip);
        }
        if (ev.remote_port != 0) {
            ext.write_uint("spt", ev.remote_port);
        }
        if (ev.local_port != 0) {
            ext.write_uint("dpt", ev.local_port);
        }
    } else {
        // bind / listen — no remote peer yet; surface the local port
        // under dpt because that's the port a future connection would
        // target. CEF has no schema-level concept of a half-open
        // socket so we lean on event_type to disambiguate.
        if (ev.local_port != 0) {
            ext.write_uint("dpt", ev.local_port);
        } else if (ev.remote_port != 0) {
            ext.write_uint("dpt", ev.remote_port);
        }
    }

    ext.write_str("externalId", exec_id);
    if (!cgpath.empty()) {
        ext.write_str("cs1", cgpath);
        ext.write_str("cs1Label", "AegisCgroupPath");
    }
    if (!parent_exec_id.empty()) {
        ext.write_str("cs2", parent_exec_id);
        ext.write_str("cs2Label", "AegisParentExecId");
    }
    if (!rule_type.empty()) {
        ext.write_str("cs3", rule_type);
        ext.write_str("cs3Label", "AegisRuleType");
    }
    ext.write_str("cs4", event_type);
    ext.write_str("cs4Label", "AegisEventType");
    ext.write_uint("cn1", ev.cgid);
    ext.write_str("cn1Label", "AegisCgroupId");
    ext.write_uint("cn2", static_cast<unsigned long long>(ev.direction));
    ext.write_str("cn2Label", "AegisDirection");

    return oss.str();
}

} // namespace aegis
