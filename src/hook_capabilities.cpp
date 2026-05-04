// cppcheck-suppress-file missingIncludeSystem
#include "hook_capabilities.hpp"

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <array>

namespace aegis {

namespace {

struct HookSpec {
    const char* name;
    const char* btf_symbol;
    bool required;
    const char* description;
};

// Catalog of every LSM hook that any AegisBPF program currently attaches.
// Names mirror the keys used by the daemon's runtime capabilities.json
// (`lsm_*`) so consumers can join the predicted-capability and runtime-
// attachment views by hook name.
//
// `btf_symbol` is the BPF-LSM trampoline name in vmlinux BTF —
// `bpf_lsm_<hook>` — which is what an LSM-attach BPF program actually
// needs to bind to. The bare hook name (e.g. "socket_listen") would be
// the upstream LSM dispatcher's call site, but most of those are inlined
// or static and aren't reliably present as standalone BTF FUNC entries
// across kernels.
constexpr std::array<HookSpec, 14> kHookCatalog = {{
    {"lsm_file_open", "bpf_lsm_file_open", true, "File open authorization (required)."},
    {"lsm_inode_permission", "bpf_lsm_inode_permission", true, "Inode access authorization (required)."},
    {"lsm_bprm_check_security", "bpf_lsm_bprm_check_security", false, "Exec identity / allowlist enforcement."},
    {"lsm_bprm_ima_check", "bpf_lsm_bprm_ima_check", false, "IMA-appraised exec verification."},
    {"lsm_file_mmap", "bpf_lsm_mmap_file", false, "Runtime-loaded library / mmap exec verification."},
    {"lsm_socket_connect", "bpf_lsm_socket_connect", false, "Outbound network connect authorization."},
    {"lsm_socket_bind", "bpf_lsm_socket_bind", false, "Local socket bind authorization."},
    {"lsm_socket_listen", "bpf_lsm_socket_listen", false, "TCP listen authorization (kernel-version-gated)."},
    {"lsm_socket_accept", "bpf_lsm_socket_accept", false, "TCP accept authorization (kernel-version-gated)."},
    {"lsm_socket_sendmsg", "bpf_lsm_socket_sendmsg", false, "Outbound datagram authorization."},
    {"lsm_socket_recvmsg", "bpf_lsm_socket_recvmsg", false, "Inbound datagram authorization (kernel-version-gated)."},
    {"lsm_ptrace_access_check", "bpf_lsm_ptrace_access_check", false, "ptrace attach authorization."},
    {"lsm_locked_down", "bpf_lsm_locked_down", false, "Kernel lockdown integration."},
    {"lsm_inode_copy_up", "bpf_lsm_inode_copy_up", false, "Overlayfs copy-up propagation."},
}};

} // namespace

std::vector<HookCapability> probe_hook_capabilities(bool* btf_available)
{
    std::vector<HookCapability> result;
    result.reserve(kHookCatalog.size());

    struct btf* vmlinux = btf__load_vmlinux_btf();
    const long btf_err = libbpf_get_error(vmlinux);
    const bool have_btf = (btf_err == 0 && vmlinux != nullptr);
    if (btf_available != nullptr) {
        *btf_available = have_btf;
    }

    for (const auto& spec : kHookCatalog) {
        HookCapability cap;
        cap.name = spec.name;
        cap.btf_symbol = spec.btf_symbol;
        cap.required = spec.required;
        cap.description = spec.description;
        if (have_btf) {
            cap.kernel_supported = btf__find_by_name_kind(vmlinux, spec.btf_symbol, BTF_KIND_FUNC) >= 0;
        } else {
            cap.kernel_supported = false;
        }
        result.push_back(std::move(cap));
    }

    if (have_btf) {
        btf__free(vmlinux);
    }
    return result;
}

} // namespace aegis
