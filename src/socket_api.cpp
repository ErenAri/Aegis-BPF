// cppcheck-suppress-file missingIncludeSystem
#include "socket_api.hpp"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <utility>

#include "logging.hpp"

namespace aegis {

SocketApiServer::SocketApiServer(Config cfg) : config_(std::move(cfg)) {}

SocketApiServer::~SocketApiServer()
{
    stop();
}

bool SocketApiServer::start()
{
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true))
        return false;

    // Remove stale socket
    unlink(config_.socket_path.c_str());

    // Ensure parent directory exists
    std::string parent = config_.socket_path.substr(0, config_.socket_path.rfind('/'));
    if (!parent.empty()) {
        mkdir(parent.c_str(), 0755);
    }

    listen_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        logger().log(SLOG_ERROR("Failed to create API socket").field("error", std::strerror(errno)));
        running_.store(false);
        return false;
    }

    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (config_.socket_path.size() >= sizeof(addr.sun_path)) {
        logger().log(SLOG_ERROR("Socket path too long").field("path", config_.socket_path));
        close(listen_fd_);
        listen_fd_ = -1;
        running_.store(false);
        return false;
    }
    std::strncpy(addr.sun_path, config_.socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        logger().log(SLOG_ERROR("Failed to bind API socket")
                         .field("path", config_.socket_path)
                         .field("error", std::strerror(errno)));
        close(listen_fd_);
        listen_fd_ = -1;
        running_.store(false);
        return false;
    }

    // Restrict socket permissions to root only
    chmod(config_.socket_path.c_str(), 0600);

    if (listen(listen_fd_, config_.backlog) < 0) {
        logger().log(SLOG_ERROR("Failed to listen on API socket").field("error", std::strerror(errno)));
        close(listen_fd_);
        listen_fd_ = -1;
        unlink(config_.socket_path.c_str());
        running_.store(false);
        return false;
    }

    accept_thread_ = std::thread([this] { accept_loop(); });
    logger().log(SLOG_INFO("API socket listening").field("path", config_.socket_path));
    return true;
}

void SocketApiServer::stop()
{
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false))
        return;

    // Close listen fd to wake up accept()
    if (listen_fd_ >= 0) {
        shutdown(listen_fd_, SHUT_RDWR);
        close(listen_fd_);
        listen_fd_ = -1;
    }

    if (accept_thread_.joinable())
        accept_thread_.join();

    // Close streaming clients
    {
        std::lock_guard<std::mutex> lock(clients_mu_);
        for (int fd : streaming_clients_) {
            close(fd);
        }
        streaming_clients_.clear();
    }

    unlink(config_.socket_path.c_str());
}

void SocketApiServer::accept_loop()
{
    while (running_.load(std::memory_order_relaxed)) {
        int client_fd = accept(listen_fd_, nullptr, nullptr);
        if (client_fd < 0) {
            if (running_.load())
                continue;
            break;
        }

        // Set read timeout on client
        struct timeval tv {};
        tv.tv_sec = 5;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // Handle client inline (simple protocol, non-blocking)
        handle_client(client_fd);
    }
}

void SocketApiServer::handle_client(int client_fd)
{
    char buf[1024] = {};
    ssize_t n = recv(client_fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        close(client_fd);
        return;
    }

    std::string request(buf, static_cast<size_t>(n));
    // Strip trailing newline
    while (!request.empty() && (request.back() == '\n' || request.back() == '\r'))
        request.pop_back();

    std::string response = handle_request(request, client_fd);

    if (!response.empty()) {
        // Send response followed by empty line delimiter
        response += "\n\n";
        send(client_fd, response.c_str(), response.size(), MSG_NOSIGNAL);
        close(client_fd);
    }
    // If response is empty, client_fd has been moved to streaming list
}

std::string SocketApiServer::handle_request(const std::string& request, int client_fd)
{
    if (request == "GET /health" || request == "{\"method\":\"health\"}") {
        return build_health_response();
    }

    if (request == "GET /status" || request == "{\"method\":\"status\"}") {
        if (status_cb_)
            return status_cb_();
        return R"({"error":"status not available"})";
    }

    if (request == "GET /stats" || request == "{\"method\":\"stats\"}") {
        if (stats_cb_)
            return stats_cb_();
        return R"({"error":"stats not available"})";
    }

    if (request == "GET /events" || request == "{\"method\":\"events\"}") {
        // Add to streaming clients
        std::lock_guard<std::mutex> lock(clients_mu_);
        if (static_cast<int>(streaming_clients_.size()) >= config_.max_clients) {
            return R"({"error":"too many streaming clients"})";
        }
        streaming_clients_.push_back(client_fd);
        // Send initial ack but don't close the fd
        std::string ack = R"({"status":"streaming"})"
                          "\n";
        send(client_fd, ack.c_str(), ack.size(), MSG_NOSIGNAL);
        return ""; // empty = don't close fd
    }

    return R"({"error":"unknown request","help":"GET /health, GET /status, GET /stats, GET /events"})";
}

void SocketApiServer::broadcast_event(const std::string& json_line)
{
    std::lock_guard<std::mutex> lock(clients_mu_);
    if (streaming_clients_.empty())
        return;

    std::string msg = json_line + "\n";
    auto it = streaming_clients_.begin();
    while (it != streaming_clients_.end()) {
        ssize_t sent = send(*it, msg.c_str(), msg.size(), MSG_NOSIGNAL);
        if (sent < 0) {
            // Client disconnected
            close(*it);
            it = streaming_clients_.erase(it);
        } else {
            ++it;
        }
    }
}

std::string SocketApiServer::build_health_response()
{
    return R"({"status":"ok","service":"aegisbpf"})";
}

} // namespace aegis
