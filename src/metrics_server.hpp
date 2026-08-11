// cppcheck-suppress-file missingIncludeSystem
#pragma once

// Optional Prometheus metrics endpoint.
//
// A minimal, opt-in HTTP/1.0 server that exposes the agent's Prometheus
// exposition (the same text `aegisbpf metrics` prints) over TCP so Prometheus /
// kube-prometheus can scrape it. Off unless AEGIS_METRICS_ADDR is set. The body
// is produced by a caller-supplied callback so this server has no BPF/kernel
// dependency and stays unit-testable.
//
// Routes: GET /metrics -> exposition; GET /healthz (or /) -> "ok"; else 404.
//
// Security: no auth (standard for Prometheus scrape targets). Bind to loopback
// ("127.0.0.1:9635") unless a scraper needs the pod/host IP, in which case bind
// ":9635" / "0.0.0.0:9635" and restrict with a NetworkPolicy / firewall.

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

namespace aegis {

class MetricsServer {
  public:
    struct Config {
        std::string bind_addr = "127.0.0.1:9635"; // "host:port"; empty host => all interfaces
        int backlog = 16;
        int recv_timeout_sec = 5;
    };

    // Returns the Prometheus exposition body for a GET /metrics.
    using MetricsCallback = std::function<std::string()>;

    explicit MetricsServer(Config cfg);
    ~MetricsServer();

    MetricsServer(const MetricsServer&) = delete;
    MetricsServer& operator=(const MetricsServer&) = delete;

    void set_metrics_callback(MetricsCallback cb) { metrics_cb_ = std::move(cb); }

    // Bind + listen + spawn the accept thread. Returns false on any setup error.
    bool start();
    // Idempotent; joins the accept thread and closes the socket.
    void stop();

    // Parse "host:port" (or ":port"). Returns false if malformed. Exposed for tests.
    static bool parse_bind_addr(const std::string& addr, std::string& host, uint16_t& port);

  private:
    void accept_loop();
    void handle_client(int client_fd);
    std::string route(const std::string& request_line);

    Config config_;
    MetricsCallback metrics_cb_;
    int listen_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;
};

} // namespace aegis
