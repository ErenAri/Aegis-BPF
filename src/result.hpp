#pragma once

#include <cstring>
#include <optional>
#include <string>
#include <variant>

namespace aegis {

/**
 * Error categories for the agent
 */
enum class ErrorCode {
    // General errors
    Success = 0,
    Unknown,
    InvalidArgument,

    // System errors
    PermissionDenied,
    ResourceNotFound,
    ResourceBusy,
    IoError,

    // BPF errors
    BpfLoadFailed,
    BpfAttachFailed,
    BpfMapOperationFailed,
    BpfPinFailed,

    // Policy errors
    PolicyParseFailed,
    PolicyVersionMismatch,
    PolicyHashMismatch,
    PolicyApplyFailed,

    // Path errors
    PathNotFound,
    PathResolutionFailed,
    PathTooLong,

    // Configuration errors
    ConfigInvalid,
    LayoutVersionMismatch,

    // Crypto/signing errors
    CryptoError,
    SignatureInvalid,
    IntegrityCheckFailed,
    PolicyExpired,
    PolicyRollback,
};

/**
 * Structured error with code, message, and optional context
 */
class Error {
  public:
    Error(ErrorCode code, std::string message)
        : code_(code), message_(std::move(message)) {}

    Error(ErrorCode code, std::string message, std::string context)
        : code_(code), message_(std::move(message)), context_(std::move(context)) {}

    [[nodiscard]] ErrorCode code() const { return code_; }
    [[nodiscard]] const std::string& message() const { return message_; }
    [[nodiscard]] const std::string& context() const { return context_; }

    [[nodiscard]] std::string to_string() const
    {
        if (context_.empty()) {
            return message_;
        }
        return message_ + ": " + context_;
    }

    // Convenience constructors for common errors
    static Error system(int errno_val, const std::string& operation)
    {
        return Error(ErrorCode::IoError, operation, std::strerror(errno_val));
    }

    static Error not_found(const std::string& what)
    {
        return Error(ErrorCode::ResourceNotFound, what + " not found");
    }

    static Error invalid_argument(const std::string& what)
    {
        return Error(ErrorCode::InvalidArgument, "Invalid argument", what);
    }

    static Error bpf_error(int err, const std::string& operation)
    {
        return Error(ErrorCode::BpfLoadFailed, operation, std::strerror(-err));
    }

  private:
    ErrorCode code_;
    std::string message_;
    std::string context_;
};

/**
 * Result type for operations that can fail
 *
 * Usage:
 *   Result<int> get_value() {
 *       if (error) return Error(ErrorCode::IoError, "failed");
 *       return 42;
 *   }
 *
 *   auto result = get_value();
 *   if (!result) {
 *       log_error(result.error().to_string());
 *       return;
 *   }
 *   int value = *result;
 */
template <typename T>
class Result {
  public:
    // Implicit construction from value (success)
    Result(T value) : data_(std::move(value)) {}

    // Implicit construction from Error (failure)
    Result(Error error) : data_(std::move(error)) {}

    // Check if result is success
    [[nodiscard]] bool ok() const { return std::holds_alternative<T>(data_); }
    [[nodiscard]] explicit operator bool() const { return ok(); }

    // Access value (undefined behavior if not ok())
    [[nodiscard]] T& value() { return std::get<T>(data_); }
    [[nodiscard]] const T& value() const { return std::get<T>(data_); }
    [[nodiscard]] T& operator*() { return value(); }
    [[nodiscard]] const T& operator*() const { return value(); }
    [[nodiscard]] T* operator->() { return &value(); }
    [[nodiscard]] const T* operator->() const { return &value(); }

    // Access error (undefined behavior if ok())
    [[nodiscard]] Error& error() { return std::get<Error>(data_); }
    [[nodiscard]] const Error& error() const { return std::get<Error>(data_); }

    // Get value or default
    [[nodiscard]] T value_or(T default_value) const
    {
        if (ok()) return value();
        return default_value;
    }

    // Map success value to new type
    template <typename F>
    auto map(F&& f) -> Result<decltype(f(std::declval<T>()))>
    {
        using U = decltype(f(std::declval<T>()));
        if (ok()) {
            return Result<U>(f(value()));
        }
        return Result<U>(error());
    }

  private:
    std::variant<T, Error> data_;
};

/**
 * Specialization for void - operations that succeed or fail with no value
 */
template <>
class Result<void> {
  public:
    // Success
    Result() : error_(std::nullopt) {}

    // Failure
    Result(Error error) : error_(std::move(error)) {}

    [[nodiscard]] bool ok() const { return !error_.has_value(); }
    [[nodiscard]] explicit operator bool() const { return ok(); }

    [[nodiscard]] Error& error() { return *error_; }
    [[nodiscard]] const Error& error() const { return *error_; }

  private:
    std::optional<Error> error_;
};

// Helper for early return on error
#define TRY(expr)                             \
    do {                                      \
        auto _result = (expr);                \
        if (!_result) return _result.error(); \
    } while (0)

#define TRY_OR(expr, error_expr)           \
    do {                                   \
        auto _result = (expr);             \
        if (!_result) return (error_expr); \
    } while (0)

}  // namespace aegis
