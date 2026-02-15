// cppcheck-suppress-file missingIncludeSystem
#include "events.hpp"

#include <arpa/inet.h>

#include <atomic>
#include <cstring>
#include <sstream>

#include "logging.hpp"
#include "utils.hpp"

#ifdef HAVE_SYSTEMD
#    include <syslog.h>
#    include <systemd/sd-journal.h>
#endif

namespace aegis {

EventLogSink g_event_sink = EventLogSink::Stdout;

bool sink_wants_stdout(EventLogSink sink)
{
    return sink == EventLogSink::Stdout || sink == EventLogSink::StdoutAndJournald;
}

bool sink_wants_journald(EventLogSink sink)
{
    return sink == EventLogSink::Journald || sink == EventLogSink::StdoutAndJournald;
}

bool set_event_log_sink(const std::string& value)
{
    if (value == "stdout") {
        g_event_sink = EventLogSink::Stdout;
        return true;
    }
#ifdef HAVE_SYSTEMD
    if (value == "journal" || value == "journald") {
        g_event_sink = EventLogSink::Journald;
        return true;
    }
    if (value == "both") {
        g_event_sink = EventLogSink::StdoutAndJournald;
        return true;
    }
#else
    if (value == "journal" || value == "journald" || value == "both") {
        logger().log(SLOG_ERROR("Journald logging requested but libsystemd support is unavailable at build time"));
        return false;
    }
#endif
    return false;
}

#ifdef HAVE_SYSTEMD
static void journal_report_error(int rc)
{
    // Use atomic flag instead of static bool to avoid race condition
    static std::atomic<bool> reported{false};
    if (rc >= 0) {
        return;
    }
    // Only report once using atomic compare-exchange
    bool expected = false;
    if (reported.compare_exchange_strong(expected, true)) {
        logger().log(SLOG_ERROR("journald logging failed").error_code(-rc));
    }
}

void journal_send_exec(const ExecEvent& ev, const std::string& payload, const std::string& cgpath,
                       const std::string& comm, const std::string& exec_id)
{
    int rc = sd_journal_send("MESSAGE=%s", payload.c_str(), "SYSLOG_IDENTIFIER=aegisbpf", "AEGIS_TYPE=exec",
                             "AEGIS_PID=%u", ev.pid, "AEGIS_PPID=%u", ev.ppid, "AEGIS_START_TIME=%llu",
                             static_cast<unsigned long long>(ev.start_time), "AEGIS_EXEC_ID=%s", exec_id.c_str(),
                             "AEGIS_TRACE_ID=%s", exec_id.c_str(), "AEGIS_CGID=%llu",
                             static_cast<unsigned long long>(ev.cgid), "AEGIS_CGROUP_PATH=%s", cgpath.c_str(),
                             "AEGIS_COMM=%s", comm.c_str(), "PRIORITY=%i", LOG_INFO, static_cast<const char*>(nullptr));
    journal_report_error(rc);
}

void journal_send_block(const BlockEvent& ev, const std::string& payload, const std::string& cgpath,
                        const std::string& path, const std::string& resolved_path, const std::string& action,
                        const std::string& comm, const std::string& exec_id, const std::string& parent_exec_id)
{
    int priority = (action == "AUDIT") ? LOG_INFO : LOG_WARNING;
    int rc = sd_journal_send(
        "MESSAGE=%s", payload.c_str(), "SYSLOG_IDENTIFIER=aegisbpf", "AEGIS_TYPE=block", "AEGIS_PID=%u", ev.pid,
        "AEGIS_PPID=%u", ev.ppid, "AEGIS_START_TIME=%llu", static_cast<unsigned long long>(ev.start_time),
        "AEGIS_EXEC_ID=%s", exec_id.c_str(), "AEGIS_TRACE_ID=%s", exec_id.c_str(), "AEGIS_PARENT_START_TIME=%llu",
        static_cast<unsigned long long>(ev.parent_start_time), "AEGIS_PARENT_EXEC_ID=%s", parent_exec_id.c_str(),
        "AEGIS_PARENT_TRACE_ID=%s", parent_exec_id.c_str(), "AEGIS_CGID=%llu", static_cast<unsigned long long>(ev.cgid),
        "AEGIS_CGROUP_PATH=%s", cgpath.c_str(), "AEGIS_INO=%llu", static_cast<unsigned long long>(ev.ino),
        "AEGIS_DEV=%u", ev.dev, "AEGIS_PATH=%s", path.c_str(), "AEGIS_RESOLVED_PATH=%s", resolved_path.c_str(),
        "AEGIS_ACTION=%s", action.c_str(), "AEGIS_COMM=%s", comm.c_str(), "PRIORITY=%i", priority,
        static_cast<const char*>(nullptr));
    journal_report_error(rc);
}

void journal_send_net_block(const NetBlockEvent& ev, const std::string& payload, const std::string& cgpath,
                            const std::string& comm, const std::string& exec_id, const std::string& parent_exec_id,
                            const std::string& event_type, const std::string& remote_ip)
{
    int priority = LOG_WARNING; // Network blocks are warnings by default
    std::string protocol = (ev.protocol == 6) ? "tcp" : (ev.protocol == 17) ? "udp" : std::to_string(ev.protocol);
    std::string family = (ev.family == 2) ? "ipv4" : "ipv6";
    std::string direction = (ev.direction == 0) ? "egress" : "bind";
    std::string rule_type = to_string(ev.rule_type, sizeof(ev.rule_type));
    std::string action = to_string(ev.action, sizeof(ev.action));

    int rc = sd_journal_send(
        "MESSAGE=%s", payload.c_str(), "SYSLOG_IDENTIFIER=aegisbpf", "AEGIS_TYPE=%s", event_type.c_str(),
        "AEGIS_PID=%u", ev.pid, "AEGIS_PPID=%u", ev.ppid, "AEGIS_START_TIME=%llu",
        static_cast<unsigned long long>(ev.start_time), "AEGIS_EXEC_ID=%s", exec_id.c_str(), "AEGIS_TRACE_ID=%s",
        exec_id.c_str(), "AEGIS_PARENT_START_TIME=%llu", static_cast<unsigned long long>(ev.parent_start_time),
        "AEGIS_PARENT_EXEC_ID=%s", parent_exec_id.c_str(), "AEGIS_PARENT_TRACE_ID=%s", parent_exec_id.c_str(),
        "AEGIS_CGID=%llu", static_cast<unsigned long long>(ev.cgid), "AEGIS_CGROUP_PATH=%s", cgpath.c_str(),
        "AEGIS_FAMILY=%s", family.c_str(), "AEGIS_PROTOCOL=%s", protocol.c_str(), "AEGIS_DIRECTION=%s",
        direction.c_str(), "AEGIS_REMOTE_IP=%s", remote_ip.c_str(), "AEGIS_REMOTE_PORT=%u", ev.remote_port,
        "AEGIS_LOCAL_PORT=%u", ev.local_port, "AEGIS_RULE_TYPE=%s", rule_type.c_str(), "AEGIS_ACTION=%s",
        action.c_str(), "AEGIS_COMM=%s", comm.c_str(), "PRIORITY=%i", priority, static_cast<const char*>(nullptr));
    journal_report_error(rc);
}
#endif

void print_exec_event(const ExecEvent& ev)
{
    std::ostringstream oss;
    std::string cgpath = resolve_cgroup_path(ev.cgid);
    std::string comm = to_string(ev.comm, sizeof(ev.comm));
    std::string exec_id = build_exec_id(ev.pid, ev.start_time);

    oss << "{\"type\":\"exec\",\"pid\":" << ev.pid << ",\"ppid\":" << ev.ppid << ",\"start_time\":" << ev.start_time;
    if (!exec_id.empty()) {
        oss << ",\"exec_id\":\"" << json_escape(exec_id) << "\"";
        oss << ",\"trace_id\":\"" << json_escape(exec_id) << "\"";
    }
    oss << ",\"cgid\":" << ev.cgid << ",\"cgroup_path\":\"" << json_escape(cgpath) << "\"" << ",\"comm\":\""
        << json_escape(comm) << "\"}";

    std::string payload = oss.str();
    if (sink_wants_stdout(g_event_sink)) {
        std::cout << payload << '\n';
    }
#ifdef HAVE_SYSTEMD
    if (sink_wants_journald(g_event_sink)) {
        journal_send_exec(ev, payload, cgpath, comm, exec_id);
    }
#endif
}

void print_block_event(const BlockEvent& ev)
{
    std::ostringstream oss;
    std::string cgpath = resolve_cgroup_path(ev.cgid);
    std::string path = to_string(ev.path, sizeof(ev.path));
    std::string resolved_path = resolve_relative_path(ev.pid, ev.start_time, path);
    std::string action = to_string(ev.action, sizeof(ev.action));
    std::string comm = to_string(ev.comm, sizeof(ev.comm));
    std::string exec_id = build_exec_id(ev.pid, ev.start_time);
    std::string parent_exec_id = build_exec_id(ev.ppid, ev.parent_start_time);

    oss << "{\"type\":\"block\",\"pid\":" << ev.pid << ",\"ppid\":" << ev.ppid << ",\"start_time\":" << ev.start_time;
    if (!exec_id.empty()) {
        oss << ",\"exec_id\":\"" << json_escape(exec_id) << "\"";
        oss << ",\"trace_id\":\"" << json_escape(exec_id) << "\"";
    }
    oss << ",\"parent_start_time\":" << ev.parent_start_time;
    if (!parent_exec_id.empty()) {
        oss << ",\"parent_exec_id\":\"" << json_escape(parent_exec_id) << "\"";
        oss << ",\"parent_trace_id\":\"" << json_escape(parent_exec_id) << "\"";
    }
    oss << ",\"cgid\":" << ev.cgid << ",\"cgroup_path\":\"" << json_escape(cgpath) << "\"";
    if (!path.empty()) {
        oss << ",\"path\":\"" << json_escape(path) << "\"";
    }
    if (!resolved_path.empty() && resolved_path != path) {
        oss << ",\"resolved_path\":\"" << json_escape(resolved_path) << "\"";
    }
    oss << ",\"ino\":" << ev.ino << ",\"dev\":" << ev.dev << ",\"action\":\"" << json_escape(action) << "\",\"comm\":\""
        << json_escape(comm) << "\"}";

    std::string payload = oss.str();
    if (sink_wants_stdout(g_event_sink)) {
        std::cout << payload << '\n';
    }
#ifdef HAVE_SYSTEMD
    if (sink_wants_journald(g_event_sink)) {
        journal_send_block(ev, payload, cgpath, path, resolved_path, action, comm, exec_id, parent_exec_id);
    }
#endif
}

static std::string format_ipv4_addr(uint32_t ip_be)
{
    char buf[INET_ADDRSTRLEN];
    struct in_addr addr {};
    addr.s_addr = ip_be;
    if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) == nullptr) {
        return "?.?.?.?";
    }
    return std::string(buf);
}

static std::string format_ipv6_addr(const uint8_t ip[16])
{
    char buf[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, ip, buf, sizeof(buf)) == nullptr) {
        return "::";
    }
    return std::string(buf);
}

static std::string protocol_to_string(uint8_t protocol)
{
    switch (protocol) {
        case 6:
            return "tcp";
        case 17:
            return "udp";
        default:
            return std::to_string(protocol);
    }
}

void print_net_block_event(const NetBlockEvent& ev)
{
    std::ostringstream oss;
    std::string cgpath = resolve_cgroup_path(ev.cgid);
    std::string action = to_string(ev.action, sizeof(ev.action));
    std::string rule_type = to_string(ev.rule_type, sizeof(ev.rule_type));
    std::string comm = to_string(ev.comm, sizeof(ev.comm));
    std::string exec_id = build_exec_id(ev.pid, ev.start_time);
    std::string parent_exec_id = build_exec_id(ev.ppid, ev.parent_start_time);

    std::string event_type = (ev.direction == 0) ? "net_connect_block" : "net_bind_block";
    std::string direction = (ev.direction == 0) ? "egress" : "bind";

    oss << "{\"type\":\"" << event_type << "\"" << ",\"pid\":" << ev.pid << ",\"ppid\":" << ev.ppid
        << ",\"start_time\":" << ev.start_time;
    if (!exec_id.empty()) {
        oss << ",\"exec_id\":\"" << json_escape(exec_id) << "\"";
        oss << ",\"trace_id\":\"" << json_escape(exec_id) << "\"";
    }
    oss << ",\"parent_start_time\":" << ev.parent_start_time;
    if (!parent_exec_id.empty()) {
        oss << ",\"parent_exec_id\":\"" << json_escape(parent_exec_id) << "\"";
        oss << ",\"parent_trace_id\":\"" << json_escape(parent_exec_id) << "\"";
    }
    oss << ",\"cgid\":" << ev.cgid << ",\"cgroup_path\":\"" << json_escape(cgpath) << "\"";

    // Network-specific fields
    oss << ",\"family\":\"" << (ev.family == 2 ? "ipv4" : "ipv6") << "\"";
    oss << ",\"protocol\":\"" << protocol_to_string(ev.protocol) << "\"";
    oss << ",\"direction\":\"" << direction << "\"";

    if (ev.direction == 0) {
        // Egress (connect) - show remote address
        if (ev.family == 2) {
            oss << ",\"remote_ip\":\"" << format_ipv4_addr(ev.remote_ipv4) << "\"";
        } else if (ev.family == 10) {
            oss << ",\"remote_ip\":\"" << format_ipv6_addr(ev.remote_ipv6) << "\"";
        }
        oss << ",\"remote_port\":" << ev.remote_port;
    } else {
        // Bind - show local port
        oss << ",\"local_port\":" << ev.local_port;
    }

    oss << ",\"rule_type\":\"" << json_escape(rule_type) << "\"" << ",\"action\":\"" << json_escape(action) << "\""
        << ",\"comm\":\"" << json_escape(comm) << "\"}";

    std::string payload = oss.str();
    if (sink_wants_stdout(g_event_sink)) {
        std::cout << payload << '\n';
    }
#ifdef HAVE_SYSTEMD
    if (sink_wants_journald(g_event_sink)) {
        std::string remote_ip;
        if (ev.family == 2) {
            remote_ip = format_ipv4_addr(ev.remote_ipv4);
        } else if (ev.family == 10) {
            remote_ip = format_ipv6_addr(ev.remote_ipv6);
        }
        journal_send_net_block(ev, payload, cgpath, comm, exec_id, parent_exec_id, event_type, remote_ip);
    }
#endif
}

// cppcheck-suppress constParameterPointer
int handle_event(void* ctx, void* data, size_t)
{
    const auto* e = static_cast<const Event*>(data);
    const auto* callbacks = static_cast<const EventCallbacks*>(ctx);
    if (e->type == EVENT_EXEC) {
        print_exec_event(e->exec);
        if (callbacks && callbacks->on_exec) {
            callbacks->on_exec(callbacks->user_ctx, e->exec);
        }
    } else if (e->type == EVENT_BLOCK) {
        print_block_event(e->block);
    } else if (e->type == EVENT_NET_CONNECT_BLOCK || e->type == EVENT_NET_BIND_BLOCK) {
        print_net_block_event(e->net_block);
    }
    return 0;
}

} // namespace aegis
