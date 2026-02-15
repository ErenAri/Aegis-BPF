// cppcheck-suppress-file missingIncludeSystem
#include "exec_identity.hpp"

#include <limits.h>
#include <signal.h>
#include <unistd.h>

#include <cerrno>

#include "logging.hpp"
#include "policy.hpp"
#include "sha256.hpp"
#include "utils.hpp"

namespace aegis {

namespace {

bool read_process_exe_path(uint32_t pid, std::string& exe_path)
{
    char path[PATH_MAX] = {};
    const std::string link = "/proc/" + std::to_string(pid) + "/exe";
    ssize_t len = ::readlink(link.c_str(), path, sizeof(path) - 1);
    if (len <= 0) {
        return false;
    }
    path[len] = '\0';
    exe_path.assign(path, static_cast<size_t>(len));
    return true;
}

const char* signal_name(uint8_t sig)
{
    switch (sig) {
        case kEnforceSignalInt:
            return "sigint";
        case kEnforceSignalKill:
            return "sigkill";
        case kEnforceSignalTerm:
            return "sigterm";
        default:
            return "sigterm";
    }
}

uint8_t effective_exec_signal(uint8_t configured)
{
    if (configured == kEnforceSignalInt || configured == kEnforceSignalKill || configured == kEnforceSignalTerm) {
        return configured;
    }
    return kEnforceSignalTerm;
}

} // namespace

Result<std::vector<std::string>> load_allow_binary_hashes_from_policy(const std::string& policy_path)
{
    PolicyIssues issues;
    auto parsed = parse_policy_file(policy_path, issues);
    if (!parsed) {
        if (!issues.errors.empty()) {
            return Error(ErrorCode::PolicyParseFailed, "Failed to parse applied policy", issues.errors.front());
        }
        return parsed.error();
    }
    return parsed->allow_binary_hashes;
}

ExecIdentityEnforcer::ExecIdentityEnforcer(std::vector<std::string> allow_hashes, bool audit_only, bool allow_unknown,
                                           uint8_t enforce_signal)
    : allow_hashes_(allow_hashes.begin(), allow_hashes.end()), audit_only_(audit_only), allow_unknown_(allow_unknown),
      enforce_signal_(enforce_signal)
{
}

void ExecIdentityEnforcer::on_exec(const ExecEvent& ev) const
{
    if (allow_hashes_.empty()) {
        return;
    }

    if (ev.pid == 0 || ev.pid == static_cast<uint32_t>(::getpid())) {
        return;
    }

    const std::string comm = to_string(ev.comm, sizeof(ev.comm));
    std::string exe_path;
    if (!read_process_exe_path(ev.pid, exe_path)) {
        if (allow_unknown_ || audit_only_) {
            logger().log(SLOG_WARN("Exec identity verification skipped for process")
                             .field("pid", static_cast<int64_t>(ev.pid))
                             .field("comm", comm)
                             .field("reason", "exe_path_unavailable")
                             .field("audit_only", audit_only_)
                             .field("allow_unknown_binary_identity", allow_unknown_));
            return;
        }

        uint8_t sig = effective_exec_signal(enforce_signal_);
        int rc = ::kill(static_cast<pid_t>(ev.pid), sig);
        if (rc == 0) {
            logger().log(SLOG_ERROR("Exec identity enforcement blocked process")
                             .field("pid", static_cast<int64_t>(ev.pid))
                             .field("comm", comm)
                             .field("reason", "exe_path_unavailable")
                             .field("signal", signal_name(sig)));
            return;
        }
        logger().log(SLOG_WARN("Exec identity enforcement attempted block but process was unavailable")
                         .field("pid", static_cast<int64_t>(ev.pid))
                         .field("comm", comm)
                         .field("reason", "exe_path_unavailable")
                         .field("errno", static_cast<int64_t>(errno)));
        return;
    }

    std::string hash_hex;
    if (!sha256_file_hex(exe_path, hash_hex)) {
        if (allow_unknown_ || audit_only_) {
            logger().log(SLOG_WARN("Exec identity hash unavailable")
                             .field("pid", static_cast<int64_t>(ev.pid))
                             .field("comm", comm)
                             .field("exe", exe_path)
                             .field("reason", "hash_unavailable")
                             .field("audit_only", audit_only_)
                             .field("allow_unknown_binary_identity", allow_unknown_));
            return;
        }

        uint8_t sig = effective_exec_signal(enforce_signal_);
        int rc = ::kill(static_cast<pid_t>(ev.pid), sig);
        if (rc == 0) {
            logger().log(SLOG_ERROR("Exec identity enforcement blocked process")
                             .field("pid", static_cast<int64_t>(ev.pid))
                             .field("comm", comm)
                             .field("exe", exe_path)
                             .field("reason", "hash_unavailable")
                             .field("signal", signal_name(sig)));
            return;
        }
        logger().log(SLOG_WARN("Exec identity enforcement attempted block but process was unavailable")
                         .field("pid", static_cast<int64_t>(ev.pid))
                         .field("comm", comm)
                         .field("exe", exe_path)
                         .field("reason", "hash_unavailable")
                         .field("errno", static_cast<int64_t>(errno)));
        return;
    }

    if (allow_hashes_.find(hash_hex) != allow_hashes_.end()) {
        return;
    }

    if (audit_only_) {
        logger().log(SLOG_WARN("Exec identity policy mismatch (audit)")
                         .field("pid", static_cast<int64_t>(ev.pid))
                         .field("comm", comm)
                         .field("exe", exe_path)
                         .field("sha256", hash_hex)
                         .field("reason", "hash_not_allowlisted"));
        return;
    }

    uint8_t sig = effective_exec_signal(enforce_signal_);
    int rc = ::kill(static_cast<pid_t>(ev.pid), sig);
    if (rc == 0) {
        logger().log(SLOG_ERROR("Exec identity policy blocked process")
                         .field("pid", static_cast<int64_t>(ev.pid))
                         .field("comm", comm)
                         .field("exe", exe_path)
                         .field("sha256", hash_hex)
                         .field("reason", "hash_not_allowlisted")
                         .field("signal", signal_name(sig)));
        return;
    }

    logger().log(SLOG_WARN("Exec identity policy attempted block but process was unavailable")
                     .field("pid", static_cast<int64_t>(ev.pid))
                     .field("comm", comm)
                     .field("exe", exe_path)
                     .field("sha256", hash_hex)
                     .field("reason", "hash_not_allowlisted")
                     .field("errno", static_cast<int64_t>(errno)));
}

} // namespace aegis
