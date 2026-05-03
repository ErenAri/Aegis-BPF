// cppcheck-suppress-file missingIncludeSystem
#include "ocsf_formatter.hpp"

#include <chrono>
#include <cstring>
#include <sstream>
#include <string>

#include "utils.hpp"

#ifndef AEGIS_VERSION_STRING
#    define AEGIS_VERSION_STRING "0.0.0"
#endif

namespace aegis {

namespace {

constexpr int kClassFileActivity = 1001;
constexpr int kClassNetworkActivity = 4001;

constexpr int kCategorySystemActivity = 1;
constexpr int kCategoryNetworkActivity = 4;

// File Activity activity_id values (subset relevant to AegisBPF).
constexpr int kFileActivityOpen = 14;

// Network Activity activity_id values.
constexpr int kNetActivityOpen = 1;
constexpr int kNetActivityTraffic = 6;

// action_id values are framework-wide.
constexpr int kActionAllowed = 1;
constexpr int kActionDenied = 2;

// disposition_id is dispatched per Security Control / control plane;
// 2 = "Blocked" is the canonical value for an in-kernel deny.
constexpr int kDispositionBlocked = 2;

// status_id values: 1 Success means the policy decision was successfully
// applied (whether that decision was allow or deny).
constexpr int kStatusSuccess = 1;

// severity_id values per OCSF: 1 Informational, 2 Low, 3 Medium,
// 4 High, 5 Critical, 6 Fatal. Audit-only is Low; an enforced block
// is High.
constexpr int kSeverityLow = 2;
constexpr int kSeverityHigh = 4;

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
        return "/"; // file at root
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

void write_metadata_block(std::ostringstream& oss, const std::string& uid)
{
    oss << "\"metadata\":{" << "\"version\":\"1.1.0\"," << "\"product\":{" << "\"name\":\"AegisBPF\","
        << "\"vendor_name\":\"AegisBPF Project\"," << "\"version\":\"" << AEGIS_VERSION_STRING << "\"" << "}";
    if (!uid.empty()) {
        oss << ",\"uid\":\"" << json_escape(uid) << "\"";
    }
    oss << "}";
}

void write_actor_block(std::ostringstream& oss, uint32_t pid, uint32_t ppid, const std::string& comm,
                       uint64_t start_time)
{
    oss << "\"actor\":{" << "\"process\":{" << "\"pid\":" << pid;
    if (!comm.empty()) {
        oss << ",\"name\":\"" << json_escape(comm) << "\"";
    }
    oss << ",\"created_time\":" << (start_time / 1000000ULL); // ns -> ms
    if (ppid > 0) {
        oss << ",\"parent_process\":{" << "\"pid\":" << ppid << "}";
    }
    oss << "}}";
}

void write_device_block(std::ostringstream& oss, const std::string& hostname)
{
    oss << "\"device\":{" << "\"type_id\":1" // 1 = Server (closest match for a Linux host)
        << ",\"type\":\"Server\"";
    if (!hostname.empty()) {
        oss << ",\"hostname\":\"" << json_escape(hostname) << "\"";
    }
    oss << "}";
}

} // namespace

bool is_ocsf_format_keyword(const std::string& value)
{
    return value == "ocsf" || value == "OCSF" || value == "ocsf-1.1" || value == "ocsf-1.1.0";
}

std::string format_block_event_ocsf(const BlockEvent& ev, const std::string& cgpath, const std::string& path,
                                    const std::string& resolved_path, const std::string& action,
                                    const std::string& comm, const std::string& exec_id,
                                    const std::string& parent_exec_id, const std::string& hostname)
{
    const bool audit = is_audit_action(action);
    const int activity_id = kFileActivityOpen;
    const int action_id = audit ? kActionAllowed : kActionDenied;
    const int severity_id = audit ? kSeverityLow : kSeverityHigh;
    const int type_uid = kClassFileActivity * 100 + activity_id;

    // Pick the most fully-resolved path we have.
    const std::string& effective_path = !resolved_path.empty() ? resolved_path : path;
    const std::string parent = parent_folder_of(effective_path);
    const std::string basename = basename_of(effective_path);

    std::ostringstream oss;
    oss << "{" << "\"class_uid\":" << kClassFileActivity << ",\"class_name\":\"File Activity\""
        << ",\"category_uid\":" << kCategorySystemActivity << ",\"category_name\":\"System Activity\""
        << ",\"activity_id\":" << activity_id << ",\"activity_name\":\"Open\"" << ",\"type_uid\":" << type_uid
        << ",\"type_name\":\"File Activity: Open\"" << ",\"action_id\":" << action_id << ",\"action\":\""
        << (audit ? "Allowed" : "Denied") << "\"";
    if (!audit) {
        oss << ",\"disposition_id\":" << kDispositionBlocked << ",\"disposition\":\"Blocked\"";
    }
    oss << ",\"status_id\":" << kStatusSuccess << ",\"status\":\"Success\"" << ",\"severity_id\":" << severity_id
        << ",\"severity\":\"" << (audit ? "Low" : "High") << "\"" << ",\"time\":" << epoch_ms_now() << ",\"message\":\""
        << (audit ? "AegisBPF audit: file open observed" : "AegisBPF: file open denied") << "\",";

    write_metadata_block(oss, exec_id);
    oss << ",";
    write_actor_block(oss, ev.pid, ev.ppid, comm, ev.start_time);
    oss << ",";
    write_device_block(oss, hostname);

    // file object
    oss << ",\"file\":{" << "\"type_id\":1" // 1 = Regular File
        << ",\"type\":\"Regular File\"";
    if (!basename.empty()) {
        oss << ",\"name\":\"" << json_escape(basename) << "\"";
    }
    if (!effective_path.empty()) {
        oss << ",\"path\":\"" << json_escape(effective_path) << "\"";
    }
    if (!parent.empty()) {
        oss << ",\"parent_folder\":\"" << json_escape(parent) << "\"";
    }
    oss << "}";

    // unmapped attributes go under the OCSF `unmapped` extension to
    // preserve forensic-grade evidence without polluting the schema.
    oss << ",\"unmapped\":{" << "\"aegis_inode\":" << ev.ino << ",\"aegis_device\":" << ev.dev
        << ",\"aegis_cgroup_id\":" << ev.cgid;
    if (!cgpath.empty()) {
        oss << ",\"aegis_cgroup_path\":\"" << json_escape(cgpath) << "\"";
    }
    if (!parent_exec_id.empty()) {
        oss << ",\"aegis_parent_exec_id\":\"" << json_escape(parent_exec_id) << "\"";
    }
    oss << "}}";

    return oss.str();
}

std::string format_net_block_event_ocsf(const NetBlockEvent& ev, const std::string& cgpath, const std::string& comm,
                                        const std::string& exec_id, const std::string& parent_exec_id,
                                        const std::string& event_type, const std::string& remote_ip,
                                        const std::string& hostname)
{
    const std::string action(ev.action, strnlen(ev.action, sizeof(ev.action)));
    const bool audit = is_audit_action(action);
    const int action_id = audit ? kActionAllowed : kActionDenied;
    const int severity_id = audit ? kSeverityLow : kSeverityHigh;

    // Map AegisBPF direction codes to OCSF Network Activity activity_id.
    int activity_id = kNetActivityOpen;
    const char* activity_name = "Open";
    switch (ev.direction) {
        case 0: // egress (connect)
        case 1: // bind
        case 2: // listen
        case 3: // accept
            activity_id = kNetActivityOpen;
            activity_name = "Open";
            break;
        case 4: // sendmsg
        case 5: // recvmsg
            activity_id = kNetActivityTraffic;
            activity_name = "Traffic";
            break;
        default:
            break;
    }
    const int type_uid = kClassNetworkActivity * 100 + activity_id;

    // Local vs remote endpoint orientation.
    // egress / send: the daemon's process is the source; remote is destination.
    // bind / listen: the daemon's process is the source; "remote" describes the
    //   bound port (no remote peer yet).
    // accept / recv: peer is source; daemon's process is destination.
    const bool peer_is_destination = (ev.direction == 0 || ev.direction == 4);
    const bool peer_is_source = (ev.direction == 3 || ev.direction == 5);

    std::ostringstream oss;
    oss << "{" << "\"class_uid\":" << kClassNetworkActivity << ",\"class_name\":\"Network Activity\""
        << ",\"category_uid\":" << kCategoryNetworkActivity << ",\"category_name\":\"Network Activity\""
        << ",\"activity_id\":" << activity_id << ",\"activity_name\":\"" << activity_name << "\""
        << ",\"type_uid\":" << type_uid << ",\"type_name\":\"Network Activity: " << activity_name << "\""
        << ",\"action_id\":" << action_id << ",\"action\":\"" << (audit ? "Allowed" : "Denied") << "\"";
    if (!audit) {
        oss << ",\"disposition_id\":" << kDispositionBlocked << ",\"disposition\":\"Blocked\"";
    }
    oss << ",\"status_id\":" << kStatusSuccess << ",\"status\":\"Success\"" << ",\"severity_id\":" << severity_id
        << ",\"severity\":\"" << (audit ? "Low" : "High") << "\"" << ",\"time\":" << epoch_ms_now() << ",\"message\":\""
        << (audit ? "AegisBPF audit: network operation observed" : "AegisBPF: network operation denied") << " ("
        << json_escape(event_type) << ")\",";

    write_metadata_block(oss, exec_id);
    oss << ",";
    write_actor_block(oss, ev.pid, ev.ppid, comm, ev.start_time);
    oss << ",";
    write_device_block(oss, hostname);

    // connection_info
    oss << ",\"connection_info\":{" << "\"protocol_num\":" << static_cast<int>(ev.protocol);
    if (ev.protocol == kProtoTCP) {
        oss << ",\"protocol_name\":\"tcp\"";
    } else if (ev.protocol == kProtoUDP) {
        oss << ",\"protocol_name\":\"udp\"";
    }
    oss << ",\"protocol_ver_id\":" << (ev.family == kFamilyIPv4 ? 4 : 6) << "}";

    // Endpoints. We always emit dst_endpoint when there's a remote peer;
    // src_endpoint when we know the local side.
    auto write_endpoint = [&](const char* label, const std::string& ip, uint16_t port) {
        oss << ",\"" << label << "\":{";
        if (!ip.empty() && ip != "0.0.0.0" && ip != "::") {
            oss << "\"ip\":\"" << json_escape(ip) << "\"";
            if (port != 0) {
                oss << ",";
            }
        }
        if (port != 0) {
            oss << "\"port\":" << port;
        }
        oss << "}";
    };

    if (peer_is_destination) {
        write_endpoint("dst_endpoint", remote_ip, ev.remote_port);
        if (ev.local_port != 0) {
            write_endpoint("src_endpoint", "", ev.local_port);
        }
    } else if (peer_is_source) {
        write_endpoint("src_endpoint", remote_ip, ev.remote_port);
        if (ev.local_port != 0) {
            write_endpoint("dst_endpoint", "", ev.local_port);
        }
    } else {
        // bind / listen -- no remote peer yet, just a local port.
        if (ev.local_port != 0 || !remote_ip.empty()) {
            write_endpoint("dst_endpoint", remote_ip, ev.local_port != 0 ? ev.local_port : ev.remote_port);
        }
    }

    oss << ",\"unmapped\":{" << "\"aegis_cgroup_id\":" << ev.cgid
        << ",\"aegis_direction\":" << static_cast<int>(ev.direction) << ",\"aegis_event_type\":\""
        << json_escape(event_type) << "\"" << ",\"aegis_rule_type\":\""
        << json_escape(std::string(ev.rule_type, strnlen(ev.rule_type, sizeof(ev.rule_type)))) << "\"";
    if (!cgpath.empty()) {
        oss << ",\"aegis_cgroup_path\":\"" << json_escape(cgpath) << "\"";
    }
    if (!parent_exec_id.empty()) {
        oss << ",\"aegis_parent_exec_id\":\"" << json_escape(parent_exec_id) << "\"";
    }
    oss << "}}";

    return oss.str();
}

} // namespace aegis
