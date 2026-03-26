// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <vector>

namespace aegis {

/**
 * Unix domain socket API server for programmatic access.
 *
 * Provides a JSON-over-Unix-socket interface for:
 *   - Status queries (GET /status)
 *   - Stats retrieval (GET /stats)
 *   - Live event streaming (GET /events)
 *   - Health checks (GET /health)
 *
 * Protocol: newline-delimited JSON. Each request is a single JSON line,
 * each response is one or more JSON lines terminated by an empty line.
 *
 * Default socket path: /var/run/aegisbpf/aegisbpf.sock
 */
class SocketApiServer {
  public:
    struct Config {
        std::string socket_path = "/var/run/aegisbpf/aegisbpf.sock";
        int max_clients = 8;
        int backlog = 4;
    };

    // Callbacks for retrieving live data
    using StatusCallback = std::function<std::string()>;
    using StatsCallback = std::function<std::string()>;

    explicit SocketApiServer(Config cfg);
    ~SocketApiServer();

    // Non-copyable
    SocketApiServer(const SocketApiServer&) = delete;
    SocketApiServer& operator=(const SocketApiServer&) = delete;

    void set_status_callback(StatusCallback cb) { status_cb_ = std::move(cb); }
    void set_stats_callback(StatsCallback cb) { stats_cb_ = std::move(cb); }

    // Start/stop the server
    bool start();
    void stop();

    [[nodiscard]] bool is_running() const { return running_.load(std::memory_order_relaxed); }

    // Broadcast an event to all connected streaming clients
    void broadcast_event(const std::string& json_line);

  private:
    void accept_loop();
    void handle_client(int client_fd);
    std::string handle_request(const std::string& request, int client_fd);
    static std::string build_health_response();

    Config config_;
    int listen_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;

    StatusCallback status_cb_;
    StatsCallback stats_cb_;

    // Connected streaming clients (protected by mutex)
    std::mutex clients_mu_;
    std::vector<int> streaming_clients_;
};

} // namespace aegis
