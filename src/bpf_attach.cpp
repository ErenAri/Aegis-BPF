// cppcheck-suppress-file missingIncludeSystem
#include "bpf_attach.hpp"

#include <cerrno>
#include <cstring>

#include "bpf_ops.hpp"
#include "logging.hpp"
#include "tracing.hpp"

namespace aegis {

namespace {

Result<void> attach_prog(bpf_program* prog, BpfState& state)
{
    const char* sec = bpf_program__section_name(prog);
    const bool is_lsm = sec && (std::strncmp(sec, "lsm/", 4) == 0 || std::strncmp(sec, "lsm.s/", 6) == 0);

    bpf_link* link = is_lsm ? bpf_program__attach_lsm(prog) : bpf_program__attach(prog);
    int err = libbpf_get_error(link);
    if (err || !link) {
        if (err == 0) {
            err = -EINVAL;
        }
        return Error::bpf_error(err, "Failed to attach BPF program");
    }
    state.links.push_back(link);
    return {};
}

Result<void> attach_required_program(BpfState& state, const std::string& trace_id, const std::string& parent_span_id,
                                     const char* span_name, const char* prog_name, const std::string& missing_message)
{
    ScopedSpan span(span_name, trace_id, parent_span_id);
    bpf_program* prog = bpf_object__find_program_by_name(state.obj, prog_name);
    if (!prog) {
        Error error(ErrorCode::BpfAttachFailed, missing_message);
        span.fail(error.to_string());
        return error;
    }
    auto result = attach_prog(prog, state);
    if (!result) {
        span.fail(result.error().to_string());
        return result.error();
    }
    return {};
}

void attach_optional_program(BpfState& state, bpf_program* prog, bool& attached, const char* attach_failed_message)
{
    if (!prog) {
        return;
    }
    auto result = attach_prog(prog, state);
    if (!result) {
        logger().log(SLOG_WARN(attach_failed_message).field("error", result.error().to_string()));
        return;
    }
    attached = true;
}

} // namespace

Result<void> attach_all(BpfState& state, bool lsm_enabled, bool use_inode_permission, bool use_file_open,
                        bool attach_network_hooks)
{
    const std::string inherited_trace_id = current_trace_id();
    const std::string trace_id = inherited_trace_id.empty() ? make_span_id("trace") : inherited_trace_id;
    ScopedSpan root_span("bpf.attach_all", trace_id, current_span_id());
    state.attach_contract_valid = false;
    state.file_hooks_expected = 0;
    state.file_hooks_attached = 0;
    state.exec_identity_hook_attached = false;
    state.exec_identity_runtime_deps_hook_attached = false;
    state.socket_connect_hook_attached = false;
    state.socket_bind_hook_attached = false;
    state.socket_listen_hook_attached = false;
    state.socket_accept_hook_attached = false;
    state.socket_sendmsg_hook_attached = false;
    state.ptrace_hook_attached = false;
    state.module_load_hook_attached = false;
    state.bpf_hook_attached = false;

    auto fail = [&root_span](const Error& error) -> Result<void> {
        root_span.fail(error.to_string());
        return error;
    };

    auto result = attach_required_program(state, trace_id, root_span.span_id(), "bpf.attach.execve", "handle_execve",
                                          "BPF program not found: handle_execve");
    if (!result) {
        return fail(result.error());
    }

    if (lsm_enabled) {
        ScopedSpan span("bpf.attach.file_hooks_lsm", trace_id, root_span.span_id());
        state.file_hooks_expected = static_cast<uint8_t>((use_inode_permission ? 1 : 0) + (use_file_open ? 1 : 0));
        if (state.file_hooks_expected > 0) {
            if (use_inode_permission) {
                bpf_program* prog = bpf_object__find_program_by_name(state.obj, "handle_inode_permission");
                if (!prog) {
                    Error error(ErrorCode::BpfAttachFailed, "Requested LSM hook not found: handle_inode_permission");
                    span.fail(error.to_string());
                    return fail(error);
                }
                auto attach_result = attach_prog(prog, state);
                if (!attach_result) {
                    span.fail(attach_result.error().to_string());
                    return fail(attach_result.error());
                }
                ++state.file_hooks_attached;
            }
            if (use_file_open) {
                bpf_program* prog = bpf_object__find_program_by_name(state.obj, "handle_file_open");
                if (!prog) {
                    Error error(ErrorCode::BpfAttachFailed, "Requested LSM hook not found: handle_file_open");
                    span.fail(error.to_string());
                    return fail(error);
                }
                auto attach_result = attach_prog(prog, state);
                if (!attach_result) {
                    span.fail(attach_result.error().to_string());
                    return fail(attach_result.error());
                }
                ++state.file_hooks_attached;
            }
            if (state.file_hooks_attached != state.file_hooks_expected) {
                Error error(ErrorCode::BpfAttachFailed, "LSM file hook attach contract violated");
                span.fail(error.to_string());
                return fail(error);
            }
        }

        {
            ScopedSpan exec_identity_span("bpf.attach.exec_identity_hook", trace_id, root_span.span_id());
            (void)exec_identity_span;
            bpf_program* prog = bpf_object__find_program_by_name(state.obj, "handle_bprm_check_security");
            if (!prog) {
                logger().log(
                    SLOG_WARN("Optional exec identity hook not found").field("program", "handle_bprm_check_security"));
            } else {
                attach_optional_program(state, prog, state.exec_identity_hook_attached,
                                        "Optional exec identity hook attach failed");
            }
        }

        {
            ScopedSpan exec_runtime_deps_span("bpf.attach.exec_runtime_deps_hook", trace_id, root_span.span_id());
            (void)exec_runtime_deps_span;
            bpf_program* prog = bpf_object__find_program_by_name(state.obj, "handle_file_mmap");
            if (!prog) {
                logger().log(
                    SLOG_WARN("Optional exec runtime deps hook not found").field("program", "handle_file_mmap"));
            } else {
                attach_optional_program(state, prog, state.exec_identity_runtime_deps_hook_attached,
                                        "Optional exec runtime deps hook attach failed");
            }
        }
    } else {
        ScopedSpan span("bpf.attach.file_hooks_tracepoint", trace_id, root_span.span_id());
        state.file_hooks_expected = 1;
        bpf_program* prog = bpf_object__find_program_by_name(state.obj, "handle_openat");
        if (!prog) {
            Error error(ErrorCode::BpfAttachFailed, "BPF file open program not found");
            span.fail(error.to_string());
            return fail(error);
        }
        auto attach_result = attach_prog(prog, state);
        if (!attach_result) {
            span.fail(attach_result.error().to_string());
            return fail(attach_result.error());
        }
        state.file_hooks_attached = 1;
    }

    result = attach_required_program(state, trace_id, root_span.span_id(), "bpf.attach.fork", "handle_fork",
                                     "BPF program not found: handle_fork");
    if (!result) {
        return fail(result.error());
    }

    result = attach_required_program(state, trace_id, root_span.span_id(), "bpf.attach.exit", "handle_exit",
                                     "BPF program not found: handle_exit");
    if (!result) {
        return fail(result.error());
    }

    if (lsm_enabled && attach_network_hooks) {
        ScopedSpan span("bpf.attach.network_hooks", trace_id, root_span.span_id());
        (void)span;

        bpf_program* prog = bpf_object__find_program_by_name(state.obj, "handle_socket_connect");
        attach_optional_program(state, prog, state.socket_connect_hook_attached,
                                "Optional socket_connect hook attach failed");

        prog = bpf_object__find_program_by_name(state.obj, "handle_socket_bind");
        attach_optional_program(state, prog, state.socket_bind_hook_attached,
                                "Optional socket_bind hook attach failed");

        prog = bpf_object__find_program_by_name(state.obj, "handle_socket_listen");
        attach_optional_program(state, prog, state.socket_listen_hook_attached,
                                "Optional socket_listen hook attach failed");

        prog = bpf_object__find_program_by_name(state.obj, "handle_socket_accept");
        attach_optional_program(state, prog, state.socket_accept_hook_attached,
                                "Optional socket_accept hook attach failed");

        prog = bpf_object__find_program_by_name(state.obj, "handle_socket_sendmsg");
        attach_optional_program(state, prog, state.socket_sendmsg_hook_attached,
                                "Optional socket_sendmsg hook attach failed");
    }

    // Kernel security hooks (ptrace, module load, bpf) - all optional
    if (lsm_enabled) {
        ScopedSpan span("bpf.attach.kernel_security_hooks", trace_id, root_span.span_id());
        (void)span;

        bpf_program* ptrace_prog = bpf_object__find_program_by_name(state.obj, "handle_ptrace_access_check");
        attach_optional_program(state, ptrace_prog, state.ptrace_hook_attached,
                                "Optional ptrace hook attach failed");

        bpf_program* module_prog = bpf_object__find_program_by_name(state.obj, "handle_locked_down");
        attach_optional_program(state, module_prog, state.module_load_hook_attached,
                                "Optional module load hook attach failed");

        bpf_program* bpf_prog = bpf_object__find_program_by_name(state.obj, "handle_bpf");
        attach_optional_program(state, bpf_prog, state.bpf_hook_attached,
                                "Optional BPF hook attach failed");
    }

    state.attach_contract_valid = true;
    return {};
}

} // namespace aegis
