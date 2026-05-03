// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>
#include <vector>

namespace aegis {

// Result of a BTF resolution attempt.
//
// `path` is the chosen BTF blob to pass to libbpf via
// `bpf_object_open_opts.btf_custom_path`. An empty `path` means "use
// the kernel's built-in BTF at /sys/kernel/btf/vmlinux"; libbpf will
// pick that up automatically when btf_custom_path is null.
//
// `source` is a short tag describing where `path` came from, for
// logging: "kernel", "override", "modules", "var-lib", "usr-lib",
// "etc", or "none" (no BTF available — daemon will likely fail to
// load on a kernel without built-in BTF).
//
// `searched` is the ordered list of paths that were probed (skipping
// the kernel-built-in fast path); useful for the "no BTF found" log
// message and for tests.
struct BtfResolution {
    std::string path;
    std::string source;
    std::vector<std::string> searched;
};

// Resolve the BTF blob to use at BPF object load time.
//
// Lookup order (first hit wins):
//   1. Explicit override (CLI flag or AEGIS_BTF_PATH env var). If the
//      override is set but the file is unreadable, the resolution
//      returns source="override-missing" and an empty path so the
//      caller can decide whether to fail or fall through.
//   2. Kernel built-in: if `/sys/kernel/btf/vmlinux` is readable,
//      return path="" with source="kernel" — libbpf picks it up.
//   3. `/lib/modules/<release>/btf/vmlinux` — Debian/Ubuntu kernels
//      sometimes ship BTF here even when /sys/kernel/btf is absent.
//   4. `/var/lib/aegisbpf/btfs/<release>.btf` — runtime-writable
//      cache populated by `aegisbpfctl btf install` or the package
//      post-install hook.
//   5. `/usr/lib/aegisbpf/btfs/<release>.btf` — package-shipped.
//   6. `/etc/aegisbpf/btfs/<release>.btf` — operator-managed.
//
// `kernel_release` is typically `utsname.release` from `uname(2)`.
// `override` is the value of `--btf-path` / `AEGIS_BTF_PATH`, or
// empty.
BtfResolution resolve_btf_path(const std::string& kernel_release, const std::string& override);

// Convenience: read AEGIS_BTF_PATH from the environment. Returns
// empty string if unset.
std::string btf_path_env_override();

} // namespace aegis
