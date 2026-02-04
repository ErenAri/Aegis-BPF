// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include "logging.hpp"

#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <sstream>
#include <string>
#include <unistd.h>

namespace aegis {

namespace trace_context {
inline thread_local std::string g_current_trace_id;
inline thread_local std::string g_current_span_id;
}  // namespace trace_context

inline bool otel_spans_enabled()
{
    const char* env = std::getenv("AEGIS_OTEL_SPANS");
    if (!env || !*env) {
        return false;
    }

    std::string value(env);
    for (char& c : value) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return value == "1" || value == "true" || value == "yes" || value == "on";
}

inline std::string make_span_id(const std::string& prefix = "span")
{
    static std::atomic<uint64_t> seq{0};
    uint64_t step = seq.fetch_add(1, std::memory_order_relaxed) + 1;
    uint64_t now_ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
    uint64_t pid = static_cast<uint64_t>(getpid());

    std::ostringstream oss;
    oss << prefix << "-" << std::hex << now_ns << "-" << pid << "-" << step;
    return oss.str();
}

inline std::string current_trace_id()
{
    return trace_context::g_current_trace_id;
}

inline std::string current_span_id()
{
    return trace_context::g_current_span_id;
}

class ScopedSpan {
  public:
    ScopedSpan(std::string name, std::string trace_id, std::string parent_span_id = std::string())
        : enabled_(otel_spans_enabled()),
          name_(std::move(name)),
          trace_id_(std::move(trace_id)),
          span_id_(make_span_id("span")),
          parent_span_id_(std::move(parent_span_id)),
          previous_trace_id_(trace_context::g_current_trace_id),
          previous_span_id_(trace_context::g_current_span_id),
          started_(std::chrono::steady_clock::now())
    {
        trace_context::g_current_trace_id = trace_id_;
        trace_context::g_current_span_id = span_id_;

        if (!enabled_) {
            return;
        }

        auto entry = SLOG_INFO("otel_span_start")
                         .field("span_name", name_)
                         .field("trace_id", trace_id_)
                         .field("span_id", span_id_);
        if (!parent_span_id_.empty()) {
            entry.field("parent_span_id", parent_span_id_);
        }
        logger().log(entry);
    }

    ~ScopedSpan()
    {
        trace_context::g_current_trace_id = previous_trace_id_;
        trace_context::g_current_span_id = previous_span_id_;

        if (!enabled_ || ended_) {
            return;
        }
        ended_ = true;

        uint64_t duration_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - started_)
                .count());

        auto entry = SLOG_INFO("otel_span_end")
                         .field("span_name", name_)
                         .field("trace_id", trace_id_)
                         .field("span_id", span_id_)
                         .field("duration_ms", duration_ms)
                         .field("status", success_ ? std::string("ok") : std::string("error"));
        if (!parent_span_id_.empty()) {
            entry.field("parent_span_id", parent_span_id_);
        }
        if (!error_message_.empty()) {
            entry.field("error", error_message_);
        }
        logger().log(entry);
    }

    void fail(const std::string& message)
    {
        success_ = false;
        error_message_ = message;
    }

    [[nodiscard]] const std::string& span_id() const { return span_id_; }
    [[nodiscard]] const std::string& trace_id() const { return trace_id_; }

  private:
    bool enabled_{false};
    bool ended_{false};
    bool success_{true};
    std::string name_;
    std::string trace_id_;
    std::string span_id_;
    std::string parent_span_id_;
    std::string error_message_;
    std::string previous_trace_id_;
    std::string previous_span_id_;
    std::chrono::steady_clock::time_point started_;
};

}  // namespace aegis
