// cppcheck-suppress-file missingIncludeSystem
#include "otlp_exporter.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <sstream>
#include <utility>

#include "logging.hpp"
#include "utils.hpp"

namespace aegis {

OtlpExporter::OtlpExporter(Config cfg) : config_(std::move(cfg)) {}

OtlpExporter::~OtlpExporter()
{
    shutdown();
}

void OtlpExporter::start()
{
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true))
        return;

    worker_ = std::thread([this] { worker_loop(); });
}

void OtlpExporter::shutdown()
{
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false))
        return;

    cv_.notify_one();
    if (worker_.joinable())
        worker_.join();

    // Final flush
    flush_batch();
}

static std::string otlp_log_record(const std::string& severity, const std::string& body,
                                   const std::string& attributes_json, uint64_t timestamp_ns)
{
    std::ostringstream oss;
    oss << "{\"timeUnixNano\":\"" << timestamp_ns << "\"" << ",\"severityText\":\"" << severity << "\""
        << ",\"body\":{\"stringValue\":" << body << "}";
    if (!attributes_json.empty()) {
        oss << ",\"attributes\":[" << attributes_json << "]";
    }
    oss << "}";
    return oss.str();
}

static std::string otlp_attr(const std::string& key, const std::string& value)
{
    return "{\"key\":\"" + key + "\",\"value\":{\"stringValue\":\"" + json_escape(value) + "\"}}";
}

static std::string otlp_attr_int(const std::string& key, uint64_t value)
{
    return "{\"key\":\"" + key + "\",\"value\":{\"intValue\":\"" + std::to_string(value) + "\"}}";
}

static uint64_t now_unix_ns()
{
    auto now = std::chrono::system_clock::now();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count());
}

void OtlpExporter::export_exec(const ExecEvent& ev)
{
    std::string comm_str = to_string(ev.comm, sizeof(ev.comm));
    std::string exec_id = build_exec_id(ev.pid, ev.start_time);

    std::ostringstream attrs;
    attrs << otlp_attr("aegis.event.type", "exec") << "," << otlp_attr_int("aegis.pid", ev.pid) << ","
          << otlp_attr_int("aegis.ppid", ev.ppid) << "," << otlp_attr("aegis.comm", comm_str) << ","
          << otlp_attr("aegis.exec_id", exec_id) << "," << otlp_attr_int("aegis.cgid", ev.cgid);

    std::string body_json = "\"exec pid=" + std::to_string(ev.pid) + " comm=" + json_escape(comm_str) + "\"";
    std::string record = otlp_log_record("INFO", body_json, attrs.str(), now_unix_ns());

    std::lock_guard<std::mutex> lock(mu_);
    if (queue_.size() >= config_.max_queue_size) {
        events_dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    queue_.push_back(std::move(record));
    if (queue_.size() >= config_.batch_size)
        cv_.notify_one();
}

void OtlpExporter::export_exec_argv(const ExecArgvEvent& ev)
{
    std::ostringstream argv_str;
    int offset = 0;
    for (int i = 0; i < ev.argc && offset < ev.total_len; i++) {
        if (i > 0)
            argv_str << " ";
        while (offset < ev.total_len && ev.argv[offset] != '\0') {
            argv_str << ev.argv[offset];
            offset++;
        }
        offset++;
    }

    std::ostringstream attrs;
    attrs << otlp_attr("aegis.event.type", "exec_argv") << "," << otlp_attr_int("aegis.pid", ev.pid) << ","
          << otlp_attr_int("aegis.argc", ev.argc) << "," << otlp_attr("aegis.argv", argv_str.str());

    std::string body_json = "\"exec_argv pid=" + std::to_string(ev.pid) + " argv=" + json_escape(argv_str.str()) + "\"";
    std::string record = otlp_log_record("INFO", body_json, attrs.str(), now_unix_ns());

    std::lock_guard<std::mutex> lock(mu_);
    if (queue_.size() >= config_.max_queue_size) {
        events_dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    queue_.push_back(std::move(record));
    if (queue_.size() >= config_.batch_size)
        cv_.notify_one();
}

void OtlpExporter::export_block(const BlockEvent& ev)
{
    std::string comm_str = to_string(ev.comm, sizeof(ev.comm));
    std::string path_str = to_string(ev.path, sizeof(ev.path));
    std::string action_str = to_string(ev.action, sizeof(ev.action));
    std::string exec_id = build_exec_id(ev.pid, ev.start_time);

    std::string severity = (action_str == "AUDIT") ? "INFO" : "WARN";

    std::ostringstream attrs;
    attrs << otlp_attr("aegis.event.type", "block") << "," << otlp_attr_int("aegis.pid", ev.pid) << ","
          << otlp_attr_int("aegis.ppid", ev.ppid) << "," << otlp_attr("aegis.comm", comm_str) << ","
          << otlp_attr("aegis.exec_id", exec_id) << "," << otlp_attr("aegis.action", action_str) << ","
          << otlp_attr("aegis.path", path_str) << "," << otlp_attr_int("aegis.ino", ev.ino) << ","
          << otlp_attr_int("aegis.dev", ev.dev);

    std::string body_json =
        "\"block pid=" + std::to_string(ev.pid) + " path=" + json_escape(path_str) + " action=" + action_str + "\"";
    std::string record = otlp_log_record(severity, body_json, attrs.str(), now_unix_ns());

    std::lock_guard<std::mutex> lock(mu_);
    if (queue_.size() >= config_.max_queue_size) {
        events_dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    queue_.push_back(std::move(record));
    if (queue_.size() >= config_.batch_size)
        cv_.notify_one();
}

void OtlpExporter::export_net_block(const NetBlockEvent& ev, uint32_t event_type)
{
    std::string comm_str = to_string(ev.comm, sizeof(ev.comm));
    std::string action_str = to_string(ev.action, sizeof(ev.action));
    std::string rule_type_str = to_string(ev.rule_type, sizeof(ev.rule_type));
    std::string exec_id = build_exec_id(ev.pid, ev.start_time);

    std::string type_name;
    std::string direction;
    switch (event_type) {
        case EVENT_NET_CONNECT_BLOCK:
            type_name = "net_connect_block";
            direction = "egress";
            break;
        case EVENT_NET_BIND_BLOCK:
            type_name = "net_bind_block";
            direction = "bind";
            break;
        case EVENT_NET_LISTEN_BLOCK:
            type_name = "net_listen_block";
            direction = "listen";
            break;
        case EVENT_NET_ACCEPT_BLOCK:
            type_name = "net_accept_block";
            direction = "accept";
            break;
        case EVENT_NET_SENDMSG_BLOCK:
            type_name = "net_sendmsg_block";
            direction = "send";
            break;
        default:
            type_name = "net_block";
            direction = "unknown";
    }

    std::string remote_ip;
    char buf[INET6_ADDRSTRLEN] = {};
    if (ev.family == 2) {
        struct in_addr addr {};
        addr.s_addr = ev.remote_ipv4;
        if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)))
            remote_ip = buf;
    } else if (ev.family == 10) {
        if (inet_ntop(AF_INET6, ev.remote_ipv6, buf, sizeof(buf)))
            remote_ip = buf;
    }

    std::ostringstream attrs;
    attrs << otlp_attr("aegis.event.type", type_name) << "," << otlp_attr_int("aegis.pid", ev.pid) << ","
          << otlp_attr_int("aegis.ppid", ev.ppid) << "," << otlp_attr("aegis.comm", comm_str) << ","
          << otlp_attr("aegis.exec_id", exec_id) << "," << otlp_attr("aegis.action", action_str) << ","
          << otlp_attr("aegis.direction", direction) << "," << otlp_attr("aegis.rule_type", rule_type_str) << ","
          << otlp_attr("aegis.family", ev.family == 2 ? "ipv4" : "ipv6") << ","
          << otlp_attr("aegis.protocol", ev.protocol == 6 ? "tcp" : (ev.protocol == 17 ? "udp" : "other"));

    if (!remote_ip.empty()) {
        attrs << "," << otlp_attr("aegis.remote_ip", remote_ip) << ","
              << otlp_attr_int("aegis.remote_port", ev.remote_port);
    }
    if (ev.local_port > 0) {
        attrs << "," << otlp_attr_int("aegis.local_port", ev.local_port);
    }

    std::string body_json = "\"" + type_name + " pid=" + std::to_string(ev.pid) + " action=" + action_str + "\"";
    std::string record = otlp_log_record("WARN", body_json, attrs.str(), now_unix_ns());

    std::lock_guard<std::mutex> lock(mu_);
    if (queue_.size() >= config_.max_queue_size) {
        events_dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    queue_.push_back(std::move(record));
    if (queue_.size() >= config_.batch_size)
        cv_.notify_one();
}

void OtlpExporter::worker_loop()
{
    while (running_.load(std::memory_order_relaxed)) {
        std::unique_lock<std::mutex> lock(mu_);
        cv_.wait_for(lock, std::chrono::milliseconds(config_.flush_interval_ms),
                     [this] { return !running_.load() || queue_.size() >= config_.batch_size; });
        lock.unlock();
        flush_batch();
    }
}

void OtlpExporter::flush_batch()
{
    std::deque<std::string> batch;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (queue_.empty())
            return;
        batch.swap(queue_);
    }

    std::string payload = build_otlp_payload(batch);
    if (http_post(payload)) {
        events_exported_.fetch_add(batch.size(), std::memory_order_relaxed);
    } else {
        export_errors_.fetch_add(1, std::memory_order_relaxed);
    }
}

std::string OtlpExporter::build_otlp_payload(const std::deque<std::string>& records) const
{
    std::ostringstream oss;
    oss << "{\"resourceLogs\":[{\"resource\":{\"attributes\":[" << otlp_attr("service.name", config_.service_name);
    if (!config_.service_version.empty()) {
        oss << "," << otlp_attr("service.version", config_.service_version);
    }
    if (!config_.node_name.empty()) {
        oss << "," << otlp_attr("host.name", config_.node_name);
    }
    if (!config_.namespace_name.empty()) {
        oss << "," << otlp_attr("k8s.namespace.name", config_.namespace_name);
    }
    oss << "]},\"scopeLogs\":[{\"scope\":{\"name\":\"aegisbpf\"}";
    oss << ",\"logRecords\":[";
    for (size_t i = 0; i < records.size(); i++) {
        if (i > 0)
            oss << ",";
        oss << records[i];
    }
    oss << "]}]}]}";
    return oss.str();
}

bool OtlpExporter::http_post(const std::string& payload) const
{
    // Parse endpoint URL: http://host:port/path
    std::string url = config_.endpoint;

    // Strip scheme
    std::string host;
    std::string path = "/v1/logs";
    uint16_t port = 4318;

    size_t scheme_end = url.find("://");
    if (scheme_end != std::string::npos)
        url = url.substr(scheme_end + 3);

    size_t path_start = url.find('/');
    if (path_start != std::string::npos) {
        path = url.substr(path_start);
        url.resize(path_start);
    }

    size_t colon = url.find(':');
    if (colon != std::string::npos) {
        host = url.substr(0, colon);
        port = static_cast<uint16_t>(std::stoi(url.substr(colon + 1)));
    } else {
        host = url;
    }

    // Resolve host
    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* result = nullptr;
    std::string port_str = std::to_string(port);
    int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    if (rc != 0 || !result) {
        return false;
    }

    // Connect
    int fd = socket(result->ai_family, SOCK_STREAM, 0);
    if (fd < 0) {
        freeaddrinfo(result);
        return false;
    }

    // Set timeout
    struct timeval tv {};
    tv.tv_sec = static_cast<long>(config_.timeout_ms / 1000);
    tv.tv_usec = static_cast<long>((config_.timeout_ms % 1000) * 1000);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(fd, result->ai_addr, result->ai_addrlen) < 0) {
        close(fd);
        freeaddrinfo(result);
        return false;
    }
    freeaddrinfo(result);

    // Send HTTP request
    std::ostringstream req;
    req << "POST " << path << " HTTP/1.1\r\n";
    req << "Host: " << host << ":" << port << "\r\n";
    req << "Content-Type: application/json\r\n";
    req << "Content-Length: " << payload.size() << "\r\n";
    req << "Connection: close\r\n\r\n";
    req << payload;

    std::string request = req.str();
    ssize_t sent = send(fd, request.c_str(), request.size(), MSG_NOSIGNAL);
    if (sent < 0 || static_cast<size_t>(sent) != request.size()) {
        close(fd);
        return false;
    }

    // Read response status line
    char resp_buf[256] = {};
    ssize_t n = recv(fd, resp_buf, sizeof(resp_buf) - 1, 0);
    close(fd);

    if (n <= 0)
        return false;

    // Check for 2xx status
    // HTTP/1.1 200 OK
    const char* status_start = std::strchr(resp_buf, ' ');
    if (!status_start)
        return false;
    int status = std::atoi(status_start + 1);
    return status >= 200 && status < 300;
}

} // namespace aegis
