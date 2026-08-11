// cppcheck-suppress-file missingIncludeSystem
#include "metrics_server.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <utility>

#include "logging.hpp"

namespace aegis {

namespace {

// Prometheus text exposition content type.
constexpr const char* kContentType = "text/plain; version=0.0.4; charset=utf-8";

std::string http_response(const std::string& status, const std::string& content_type, const std::string& body)
{
    std::string out = "HTTP/1.0 " + status + "\r\n";
    out += "Content-Type: " + content_type + "\r\n";
    out += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    out += "Connection: close\r\n\r\n";
    out += body;
    return out;
}

} // namespace

MetricsServer::MetricsServer(Config cfg) : config_(std::move(cfg)) {}

MetricsServer::~MetricsServer()
{
    stop();
}

bool MetricsServer::parse_bind_addr(const std::string& addr, std::string& host, uint16_t& port)
{
    const size_t colon = addr.rfind(':');
    if (colon == std::string::npos) {
        return false;
    }
    host = addr.substr(0, colon);
    const std::string port_str = addr.substr(colon + 1);
    if (port_str.empty()) {
        return false;
    }
    for (char c : port_str) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    unsigned long value = 0;
    try {
        value = std::stoul(port_str);
    } catch (...) {
        return false;
    }
    if (value == 0 || value > 65535) {
        return false;
    }
    port = static_cast<uint16_t>(value);
    return true;
}

bool MetricsServer::start()
{
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) {
        return false;
    }

    std::string host;
    uint16_t port = 0;
    if (!parse_bind_addr(config_.bind_addr, host, port)) {
        logger().log(SLOG_ERROR("Invalid metrics bind address").field("addr", config_.bind_addr));
        running_.store(false);
        return false;
    }

    listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        logger().log(SLOG_ERROR("Failed to create metrics socket").field("error", std::strerror(errno)));
        running_.store(false);
        return false;
    }

    int reuse = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (host.empty()) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        logger().log(SLOG_ERROR("Invalid metrics bind host (expect IPv4)").field("host", host));
        close(listen_fd_);
        listen_fd_ = -1;
        running_.store(false);
        return false;
    }

    if (bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        logger().log(SLOG_ERROR("Failed to bind metrics socket")
                         .field("addr", config_.bind_addr)
                         .field("error", std::strerror(errno)));
        close(listen_fd_);
        listen_fd_ = -1;
        running_.store(false);
        return false;
    }

    if (listen(listen_fd_, config_.backlog) < 0) {
        logger().log(SLOG_ERROR("Failed to listen on metrics socket").field("error", std::strerror(errno)));
        close(listen_fd_);
        listen_fd_ = -1;
        running_.store(false);
        return false;
    }

    accept_thread_ = std::thread([this] { accept_loop(); });
    logger().log(SLOG_INFO("Metrics endpoint listening").field("addr", config_.bind_addr));
    return true;
}

void MetricsServer::stop()
{
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false)) {
        return;
    }

    // Wake the blocked accept() before joining.
    if (listen_fd_ >= 0) {
        shutdown(listen_fd_, SHUT_RDWR);
    }
    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }
    if (listen_fd_ >= 0) {
        close(listen_fd_);
        listen_fd_ = -1;
    }
}

void MetricsServer::accept_loop()
{
    while (running_.load(std::memory_order_relaxed)) {
        int client_fd = accept(listen_fd_, nullptr, nullptr);
        if (client_fd < 0) {
            if (running_.load(std::memory_order_relaxed)) {
                continue;
            }
            break;
        }

        struct timeval tv {};
        tv.tv_sec = config_.recv_timeout_sec;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        handle_client(client_fd);
    }
}

void MetricsServer::handle_client(int client_fd)
{
    char buf[2048] = {};
    ssize_t n = recv(client_fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        close(client_fd);
        return;
    }

    std::string request(buf, static_cast<size_t>(n));
    // The request line is everything up to the first CR/LF.
    size_t eol = request.find_first_of("\r\n");
    std::string request_line = (eol == std::string::npos) ? request : request.substr(0, eol);

    const std::string response = route(request_line);
    send(client_fd, response.c_str(), response.size(), MSG_NOSIGNAL);
    close(client_fd);
}

std::string MetricsServer::route(const std::string& request_line)
{
    // Expect "GET <path> HTTP/1.x".
    if (request_line.rfind("GET ", 0) != 0) {
        return http_response("405 Method Not Allowed", "text/plain", "method not allowed\n");
    }
    const size_t path_start = 4;
    size_t path_end = request_line.find(' ', path_start);
    std::string path =
        request_line.substr(path_start, path_end == std::string::npos ? std::string::npos : path_end - path_start);

    if (path == "/metrics") {
        if (!metrics_cb_) {
            return http_response("503 Service Unavailable", "text/plain", "metrics not available\n");
        }
        return http_response("200 OK", kContentType, metrics_cb_());
    }
    if (path == "/healthz" || path == "/") {
        return http_response("200 OK", "text/plain", "ok\n");
    }
    return http_response("404 Not Found", "text/plain", "not found\n");
}

} // namespace aegis
