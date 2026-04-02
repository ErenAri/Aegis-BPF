// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>

#include "types.hpp"

namespace aegis {

/**
 * Lightweight OTLP/HTTP JSON log exporter.
 *
 * Batches security events and ships them to an OpenTelemetry collector via
 * OTLP/HTTP (JSON encoding). No dependency on the full OpenTelemetry SDK —
 * produces the JSON payload directly to keep the binary small.
 *
 * Wire format: OTLP Logs v1 (https://opentelemetry.io/docs/specs/otlp/)
 *
 * Usage:
 *   OtlpExporter exporter("http://localhost:4318/v1/logs");
 *   exporter.start();
 *   exporter.export_exec(ev);
 *   exporter.export_block(ev);
 *   exporter.shutdown(); // flushes pending batch
 */
class OtlpExporter {
  public:
    struct Config {
        std::string endpoint = "http://localhost:4318/v1/logs";
        std::string service_name = "aegisbpf";
        std::string service_version;       // set from build version
        uint32_t batch_size = 64;          // flush when batch reaches this size
        uint32_t flush_interval_ms = 5000; // flush at least this often
        uint32_t max_queue_size = 4096;    // drop events beyond this
        uint32_t timeout_ms = 10000;       // HTTP timeout per request
        std::string node_name;             // k8s node or hostname
        std::string namespace_name;        // k8s namespace (optional)
    };

    explicit OtlpExporter(Config cfg);
    ~OtlpExporter();

    // Non-copyable, non-movable
    OtlpExporter(const OtlpExporter&) = delete;
    OtlpExporter& operator=(const OtlpExporter&) = delete;

    void start();
    void shutdown();

    // Thread-safe event submission
    void export_exec(const ExecEvent& ev);
    void export_exec_argv(const ExecArgvEvent& ev);
    void export_block(const BlockEvent& ev);
    void export_net_block(const NetBlockEvent& ev, uint32_t event_type);

    // Statistics
    [[nodiscard]] uint64_t events_exported() const { return events_exported_.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t events_dropped() const { return events_dropped_.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t export_errors() const { return export_errors_.load(std::memory_order_relaxed); }

  private:
    void worker_loop();
    void flush_batch();
    std::string build_otlp_payload(const std::deque<std::string>& records) const;
    bool http_post(const std::string& payload) const;

    Config config_;
    std::thread worker_;
    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<std::string> queue_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> events_exported_{0};
    std::atomic<uint64_t> events_dropped_{0};
    std::atomic<uint64_t> export_errors_{0};
};

} // namespace aegis
