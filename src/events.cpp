#include "events.hpp"
#include "logging.hpp"
#include "utils.hpp"

#include <atomic>
#include <cstring>
#include <sstream>

#ifdef HAVE_SYSTEMD
#include <systemd/sd-journal.h>
#include <syslog.h>
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

bool set_event_log_sink(const std::string &value)
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

void journal_send_exec(const ExecEvent &ev, const std::string &payload, const std::string &cgpath,
                       const std::string &comm, const std::string &exec_id)
{
    int rc = sd_journal_send(
        "MESSAGE=%s", payload.c_str(),
        "SYSLOG_IDENTIFIER=aegisbpf",
        "AEGIS_TYPE=exec",
        "AEGIS_PID=%u", ev.pid,
        "AEGIS_PPID=%u", ev.ppid,
        "AEGIS_START_TIME=%llu", static_cast<unsigned long long>(ev.start_time),
        "AEGIS_EXEC_ID=%s", exec_id.c_str(),
        "AEGIS_CGID=%llu", static_cast<unsigned long long>(ev.cgid),
        "AEGIS_CGROUP_PATH=%s", cgpath.c_str(),
        "AEGIS_COMM=%s", comm.c_str(),
        "PRIORITY=%i", LOG_INFO,
        static_cast<const char *>(nullptr));
    journal_report_error(rc);
}

void journal_send_block(const BlockEvent &ev, const std::string &payload, const std::string &cgpath,
                        const std::string &path, const std::string &resolved_path, const std::string &action,
                        const std::string &comm, const std::string &exec_id, const std::string &parent_exec_id)
{
    int priority = (action == "AUDIT") ? LOG_INFO : LOG_WARNING;
    int rc = sd_journal_send(
        "MESSAGE=%s", payload.c_str(),
        "SYSLOG_IDENTIFIER=aegisbpf",
        "AEGIS_TYPE=block",
        "AEGIS_PID=%u", ev.pid,
        "AEGIS_PPID=%u", ev.ppid,
        "AEGIS_START_TIME=%llu", static_cast<unsigned long long>(ev.start_time),
        "AEGIS_EXEC_ID=%s", exec_id.c_str(),
        "AEGIS_PARENT_START_TIME=%llu", static_cast<unsigned long long>(ev.parent_start_time),
        "AEGIS_PARENT_EXEC_ID=%s", parent_exec_id.c_str(),
        "AEGIS_CGID=%llu", static_cast<unsigned long long>(ev.cgid),
        "AEGIS_CGROUP_PATH=%s", cgpath.c_str(),
        "AEGIS_INO=%llu", static_cast<unsigned long long>(ev.ino),
        "AEGIS_DEV=%u", ev.dev,
        "AEGIS_PATH=%s", path.c_str(),
        "AEGIS_RESOLVED_PATH=%s", resolved_path.c_str(),
        "AEGIS_ACTION=%s", action.c_str(),
        "AEGIS_COMM=%s", comm.c_str(),
        "PRIORITY=%i", priority,
        static_cast<const char *>(nullptr));
    journal_report_error(rc);
}
#endif

void print_exec_event(const ExecEvent &ev)
{
    std::ostringstream oss;
    std::string cgpath = resolve_cgroup_path(ev.cgid);
    std::string comm = to_string(ev.comm, sizeof(ev.comm));
    std::string exec_id = build_exec_id(ev.pid, ev.start_time);

    oss << "{\"type\":\"exec\",\"pid\":" << ev.pid
        << ",\"ppid\":" << ev.ppid
        << ",\"start_time\":" << ev.start_time;
    if (!exec_id.empty()) {
        oss << ",\"exec_id\":\"" << json_escape(exec_id) << "\"";
    }
    oss << ",\"cgid\":" << ev.cgid
        << ",\"cgroup_path\":\"" << json_escape(cgpath) << "\""
        << ",\"comm\":\"" << json_escape(comm) << "\"}";

    std::string payload = oss.str();
    if (sink_wants_stdout(g_event_sink)) {
        std::cout << payload << std::endl;
    }
#ifdef HAVE_SYSTEMD
    if (sink_wants_journald(g_event_sink)) {
        journal_send_exec(ev, payload, cgpath, comm, exec_id);
    }
#endif
}

void print_block_event(const BlockEvent &ev)
{
    std::ostringstream oss;
    std::string cgpath = resolve_cgroup_path(ev.cgid);
    std::string path = to_string(ev.path, sizeof(ev.path));
    std::string resolved_path = resolve_relative_path(ev.pid, ev.start_time, path);
    std::string action = to_string(ev.action, sizeof(ev.action));
    std::string comm = to_string(ev.comm, sizeof(ev.comm));
    std::string exec_id = build_exec_id(ev.pid, ev.start_time);
    std::string parent_exec_id = build_exec_id(ev.ppid, ev.parent_start_time);

    oss << "{\"type\":\"block\",\"pid\":" << ev.pid
        << ",\"ppid\":" << ev.ppid
        << ",\"start_time\":" << ev.start_time;
    if (!exec_id.empty()) {
        oss << ",\"exec_id\":\"" << json_escape(exec_id) << "\"";
    }
    oss << ",\"parent_start_time\":" << ev.parent_start_time;
    if (!parent_exec_id.empty()) {
        oss << ",\"parent_exec_id\":\"" << json_escape(parent_exec_id) << "\"";
    }
    oss << ",\"cgid\":" << ev.cgid
        << ",\"cgroup_path\":\"" << json_escape(cgpath) << "\"";
    if (!path.empty()) {
        oss << ",\"path\":\"" << json_escape(path) << "\"";
    }
    if (!resolved_path.empty() && resolved_path != path) {
        oss << ",\"resolved_path\":\"" << json_escape(resolved_path) << "\"";
    }
    oss << ",\"ino\":" << ev.ino
        << ",\"dev\":" << ev.dev
        << ",\"action\":\"" << json_escape(action)
        << "\",\"comm\":\"" << json_escape(comm) << "\"}";

    std::string payload = oss.str();
    if (sink_wants_stdout(g_event_sink)) {
        std::cout << payload << std::endl;
    }
#ifdef HAVE_SYSTEMD
    if (sink_wants_journald(g_event_sink)) {
        journal_send_block(ev, payload, cgpath, path, resolved_path, action, comm, exec_id, parent_exec_id);
    }
#endif
}

int handle_event(void *, void *data, size_t)
{
    const auto *e = static_cast<const Event *>(data);
    if (e->type == EVENT_EXEC) {
        print_exec_event(e->exec);
    } else if (e->type == EVENT_BLOCK) {
        print_block_event(e->block);
    }
    return 0;
}

} // namespace aegis
