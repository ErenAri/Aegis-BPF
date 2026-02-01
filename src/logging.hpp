#pragma once

#include <chrono>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace aegis {

enum class LogLevel {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
    Fatal = 4,
};

inline const char* log_level_string(LogLevel level) {
    switch (level) {
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info:  return "INFO";
        case LogLevel::Warn:  return "WARN";
        case LogLevel::Error: return "ERROR";
        case LogLevel::Fatal: return "FATAL";
        default: return "UNKNOWN";
    }
}

/**
 * Structured log entry with key-value fields
 */
class LogEntry {
public:
    LogEntry(LogLevel level, std::string message)
        : level_(level), message_(std::move(message)) {
        timestamp_ = std::chrono::system_clock::now();
    }

    LogEntry& field(const std::string& key, const std::string& value) {
        fields_.emplace_back(key, value);
        return *this;
    }

    LogEntry& field(const std::string& key, int64_t value) {
        fields_.emplace_back(key, std::to_string(value));
        return *this;
    }

    LogEntry& field(const std::string& key, uint64_t value) {
        fields_.emplace_back(key, std::to_string(value));
        return *this;
    }

    LogEntry& field(const std::string& key, double value) {
        fields_.emplace_back(key, std::to_string(value));
        return *this;
    }

    LogEntry& field(const std::string& key, bool value) {
        fields_.emplace_back(key, value ? "true" : "false");
        return *this;
    }

    LogEntry& error_code(int err) {
        fields_.emplace_back("errno", std::to_string(err));
        fields_.emplace_back("error", std::strerror(err));
        return *this;
    }

    [[nodiscard]] LogLevel level() const { return level_; }
    [[nodiscard]] const std::string& message() const { return message_; }
    [[nodiscard]] const std::vector<std::pair<std::string, std::string>>& fields() const {
        return fields_;
    }
    [[nodiscard]] std::chrono::system_clock::time_point timestamp() const {
        return timestamp_;
    }

    [[nodiscard]] std::string format_text() const {
        std::ostringstream oss;

        // Timestamp
        auto time_t = std::chrono::system_clock::to_time_t(timestamp_);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            timestamp_.time_since_epoch()) % 1000;
        oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        oss << '.' << std::setfill('0') << std::setw(3) << ms.count();

        // Level
        oss << " [" << log_level_string(level_) << "] ";

        // Message
        oss << message_;

        // Fields
        if (!fields_.empty()) {
            oss << " {";
            bool first = true;
            for (const auto& [key, value] : fields_) {
                if (!first) oss << ", ";
                oss << key << "=" << escape_value(value);
                first = false;
            }
            oss << "}";
        }

        return oss.str();
    }

    [[nodiscard]] std::string format_json() const {
        std::ostringstream oss;
        oss << "{";

        // Timestamp as ISO8601
        auto time_t = std::chrono::system_clock::to_time_t(timestamp_);
        oss << "\"timestamp\":\"";
        oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
        oss << "Z\"";

        // Level
        oss << ",\"level\":\"" << log_level_string(level_) << "\"";

        // Message
        oss << ",\"message\":\"" << json_escape(message_) << "\"";

        // Fields
        for (const auto& [key, value] : fields_) {
            oss << ",\"" << key << "\":\"" << json_escape(value) << "\"";
        }

        oss << "}";
        return oss.str();
    }

private:
    static std::string escape_value(const std::string& s) {
        if (s.find(' ') != std::string::npos || s.find('"') != std::string::npos) {
            std::string escaped = "\"";
            for (char c : s) {
                if (c == '"') escaped += "\\\"";
                else if (c == '\\') escaped += "\\\\";
                else escaped += c;
            }
            escaped += "\"";
            return escaped;
        }
        return s;
    }

    static std::string json_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default: out += c;
            }
        }
        return out;
    }

    LogLevel level_;
    std::string message_;
    std::vector<std::pair<std::string, std::string>> fields_;
    std::chrono::system_clock::time_point timestamp_;
};

/**
 * Logger singleton with configurable output and level filtering
 */
class Logger {
public:
    static Logger& instance() {
        static Logger logger;
        return logger;
    }

    void set_level(LogLevel level) { min_level_ = level; }
    void set_json_format(bool json) { json_format_ = json; }
    void set_output(std::ostream* out) { output_ = out; }

    void log(const LogEntry& entry) {
        if (entry.level() < min_level_) return;

        std::lock_guard<std::mutex> lock(mutex_);
        if (json_format_) {
            *output_ << entry.format_json() << std::endl;
        } else {
            *output_ << entry.format_text() << std::endl;
        }
    }

    void log(LogLevel level, const std::string& message) {
        log(LogEntry(level, message));
    }

    // Convenience methods that return LogEntry for chaining
    LogEntry debug(const std::string& message) { return LogEntry(LogLevel::Debug, message); }
    LogEntry info(const std::string& message) { return LogEntry(LogLevel::Info, message); }
    LogEntry warn(const std::string& message) { return LogEntry(LogLevel::Warn, message); }
    LogEntry error(const std::string& message) { return LogEntry(LogLevel::Error, message); }
    LogEntry fatal(const std::string& message) { return LogEntry(LogLevel::Fatal, message); }

private:
    Logger() : min_level_(LogLevel::Info), json_format_(false), output_(&std::cerr) {}

    LogLevel min_level_;
    bool json_format_;
    std::ostream* output_;
    std::mutex mutex_;
};

// Global convenience functions
inline Logger& logger() { return Logger::instance(); }

inline void log_debug(const std::string& msg) {
    logger().log(LogEntry(LogLevel::Debug, msg));
}

inline void log_info(const std::string& msg) {
    logger().log(LogEntry(LogLevel::Info, msg));
}

inline void log_warn(const std::string& msg) {
    logger().log(LogEntry(LogLevel::Warn, msg));
}

inline void log_error(const std::string& msg) {
    logger().log(LogEntry(LogLevel::Error, msg));
}

inline void log_fatal(const std::string& msg) {
    logger().log(LogEntry(LogLevel::Fatal, msg));
}

// Macro for logging with automatic field chaining
#define LOG_DEBUG(msg) aegis::logger().log(aegis::logger().debug(msg))
#define LOG_INFO(msg)  aegis::logger().log(aegis::logger().info(msg))
#define LOG_WARN(msg)  aegis::logger().log(aegis::logger().warn(msg))
#define LOG_ERROR(msg) aegis::logger().log(aegis::logger().error(msg))
#define LOG_FATAL(msg) aegis::logger().log(aegis::logger().fatal(msg))

// Structured logging macros
#define SLOG_DEBUG(msg) aegis::logger().debug(msg)
#define SLOG_INFO(msg)  aegis::logger().info(msg)
#define SLOG_WARN(msg)  aegis::logger().warn(msg)
#define SLOG_ERROR(msg) aegis::logger().error(msg)
#define SLOG_FATAL(msg) aegis::logger().fatal(msg)

// Helper to log and return
#define LOG_AND_RETURN(entry, ret) do { aegis::logger().log(entry); return (ret); } while(0)

} // namespace aegis
