//! C ABI for the policy parser — the (staged) integration seam for the C++ agent.
//!
//! NOT yet called by the production load path. It exists so the eventual swap is
//! a wiring change, not a rewrite, and so the boundary is reviewable now. The
//! C++ side passes a sink of callbacks; Rust parses and reports each error and
//! warning back through it. Panics are caught so unwinding never crosses FFI.
use core::ffi::{c_char, c_int, c_void};

use crate::policy::{parse_policy, Flag};

/// Callback sink. All `*const c_char` pointers are valid only for the duration
/// of the call and carry an explicit length (the text may contain interior NULs
/// from adversarial input, so callers must honor `len`).
#[repr(C)]
pub struct AegisPolicySink {
    pub ctx: *mut c_void,
    pub add_error: Option<extern "C" fn(*mut c_void, *const c_char, usize)>,
    pub add_warning: Option<extern "C" fn(*mut c_void, *const c_char, usize)>,
}

/// Parse `len` bytes of policy text, reporting issues through `sink`. Returns the
/// number of errors (0 == clean), or a negative code on a bad call / panic.
///
/// # Safety
/// `text` must point to `len` readable bytes; `sink` must be a valid pointer to
/// an `AegisPolicySink` whose callbacks are sound.
#[no_mangle]
pub unsafe extern "C" fn aegis_policy_parse(
    text: *const c_char,
    len: usize,
    sink: *const AegisPolicySink,
) -> c_int {
    if (text.is_null() && len != 0) || sink.is_null() {
        return -1;
    }
    let result = std::panic::catch_unwind(|| {
        // SAFETY: caller guarantees `text`/`len` describe a readable region and
        // `sink` is valid for the duration of this call.
        let bytes: &[u8] = if len == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(text as *const u8, len) }
        };
        let sink: &AegisPolicySink = unsafe { &*sink };
        let (_policy, issues) = parse_policy(bytes, true);
        if let Some(cb) = sink.add_error {
            for e in &issues.errors {
                cb(sink.ctx, e.as_ptr() as *const c_char, e.len());
            }
        }
        if let Some(cb) = sink.add_warning {
            for w in &issues.warnings {
                cb(sink.ctx, w.as_ptr() as *const c_char, w.len());
            }
        }
        issues.errors.len() as c_int
    });
    result.unwrap_or(-2)
}

/// Emit callback for a canonical decode dump. Receives `(ctx, ptr, len)` where the
/// `len` bytes at `ptr` are the dump and are valid ONLY for the duration of the
/// call (the caller must copy if it needs them after). The bytes are ASCII
/// (decimal + lowercase hex), but consumers should still honor `len` rather than
/// assume NUL-termination.
pub type AegisEmitFn = extern "C" fn(*mut c_void, *const c_char, usize);

/// Decode a signed-policy-bundle header from `len` bytes and emit its canonical
/// dump (the same one `scripts/rust_bundle_parity.sh` compares) through `emit`.
/// Returns 0 on success, -1 on a bad call, -2 on a caught panic. The dump encodes
/// both the success (`ok` + fields) and failure (`err <message>`) cases, so this
/// never reports parse failures as a negative code.
///
/// # Safety
/// `data` must point to `len` readable bytes; `emit` (if `Some`) must be sound.
#[no_mangle]
pub unsafe extern "C" fn aegis_bundle_canonical(
    data: *const c_char,
    len: usize,
    emit: Option<AegisEmitFn>,
    ctx: *mut c_void,
) -> c_int {
    if data.is_null() && len != 0 {
        return -1;
    }
    let result = std::panic::catch_unwind(|| {
        // SAFETY: caller guarantees `data`/`len` describe a readable region.
        let bytes: &[u8] = if len == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(data as *const u8, len) }
        };
        let parsed = crate::bundle::parse_signed_bundle(bytes);
        let dump = crate::bundle::canonical_report(&parsed);
        if let Some(cb) = emit {
            cb(ctx, dump.as_ptr() as *const c_char, dump.len());
        }
        0
    });
    result.unwrap_or(-2)
}

/// Parse `len` bytes of policy text and emit its FULL canonical dump (the same one
/// `scripts/rust_policy_parity.sh` compares — version, flags, every stored entry
/// in every category, and the sorted errors/warnings) through `emit`. This is the
/// structural-equivalence surface the consensus/enforce mode compares, stronger
/// than the errors/warnings `aegis_policy_parse` reports. Returns 0 on success, -1
/// on a bad call, -2 on a caught panic.
///
/// # Safety
/// `data` must point to `len` readable bytes; `emit` (if `Some`) must be sound.
#[no_mangle]
pub unsafe extern "C" fn aegis_policy_canonical(
    data: *const c_char,
    len: usize,
    emit: Option<AegisEmitFn>,
    ctx: *mut c_void,
) -> c_int {
    if data.is_null() && len != 0 {
        return -1;
    }
    let result = std::panic::catch_unwind(|| {
        // SAFETY: caller guarantees `data`/`len` describe a readable region.
        let bytes: &[u8] = if len == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(data as *const u8, len) }
        };
        let (policy, issues) = parse_policy(bytes, true);
        let dump = crate::policy::canonical_report(&policy, &issues);
        if let Some(cb) = emit {
            cb(ctx, dump.as_ptr() as *const c_char, dump.len());
        }
        0
    });
    result.unwrap_or(-2)
}

/// Decode a BPF ring-buffer event record from `len` bytes and emit its canonical
/// dump (the same one `scripts/rust_event_parity.sh` compares) through `emit`. A
/// short or unrecognized record yields a defined dump (`err short_buffer` /
/// `unknown_type`), never an out-of-bounds read. Returns 0 on success, -1 on a
/// bad call, -2 on a caught panic.
///
/// # Safety
/// `data` must point to `len` readable bytes; `emit` (if `Some`) must be sound.
#[no_mangle]
pub unsafe extern "C" fn aegis_event_canonical(
    data: *const c_char,
    len: usize,
    emit: Option<AegisEmitFn>,
    ctx: *mut c_void,
) -> c_int {
    if data.is_null() && len != 0 {
        return -1;
    }
    let result = std::panic::catch_unwind(|| {
        // SAFETY: caller guarantees `data`/`len` describe a readable region.
        let bytes: &[u8] = if len == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(data as *const u8, len) }
        };
        let dump = crate::event::canonical_report(bytes);
        if let Some(cb) = emit {
            cb(ctx, dump.as_ptr() as *const c_char, dump.len());
        }
        0
    });
    result.unwrap_or(-2)
}

/// Builder sink for transporting a fully-parsed policy across the FFI — the
/// *content* surface for the eventual swap (vs `aegis_policy_parse`, which only
/// reports errors/warnings). All callbacks are optional; `*const c_char` args are
/// valid only for the call and carry an explicit length. The string CATEGORY ids
/// (`add_string`) and FLAG ids (`set_flag`) are the ABI contract with the C side
/// (`src/aegis_parser_ffi.h`, `AEGIS_PCAT_*` / `AEGIS_PFLAG_*`) — keep in lockstep.
#[repr(C)]
pub struct AegisPolicyBuilder {
    pub ctx: *mut c_void,
    pub set_version: Option<extern "C" fn(*mut c_void, u64)>,
    pub set_flag: Option<extern "C" fn(*mut c_void, u32)>,
    pub add_string: Option<extern "C" fn(*mut c_void, u32, *const c_char, usize)>,
    pub add_cgroup_id: Option<extern "C" fn(*mut c_void, u64)>,
    pub add_deny_port: Option<extern "C" fn(*mut c_void, u16, u8, u8)>,
    pub add_cgroup_deny_port: Option<extern "C" fn(*mut c_void, *const c_char, usize, u16, u8, u8)>,
}

// FLAG ids (set_flag) — the first 7 mirror the `Flag` enum order; 7/8 are the
// network/cgroup section-enabled bits.
const PFLAG_NETWORK_ENABLED: u32 = 7;
const PFLAG_CGROUP_ENABLED: u32 = 8;

fn flag_id(f: Flag) -> u32 {
    match f {
        Flag::ProtectConnect => 0,
        Flag::ProtectRuntimeDeps => 1,
        Flag::RequireImaAppraisal => 2,
        Flag::ImaFailClosed => 3,
        Flag::DenyPtrace => 4,
        Flag::DenyModuleLoad => 5,
        Flag::DenyBpf => 6,
    }
}

/// Parse `len` bytes of policy text and, IF it parses without errors, transport
/// every field of the resulting `Policy` through `builder`. Returns the number of
/// errors (0 == a clean policy was built; >0 == parse failed, nothing built —
/// mirroring the C++ apply path, which discards a policy on error), or a negative
/// code on a bad call (-1) / caught panic (-2). Never unwinds across FFI.
///
/// # Safety
/// `text` must point to `len` readable bytes; `builder` must be a valid pointer to
/// an `AegisPolicyBuilder` whose callbacks are sound.
#[no_mangle]
pub unsafe extern "C" fn aegis_policy_build(
    text: *const c_char,
    len: usize,
    builder: *const AegisPolicyBuilder,
) -> c_int {
    if (text.is_null() && len != 0) || builder.is_null() {
        return -1;
    }
    let result = std::panic::catch_unwind(|| {
        // SAFETY: caller guarantees `text`/`len` describe a readable region and
        // `builder` is valid for the duration of this call.
        let bytes: &[u8] = if len == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(text as *const u8, len) }
        };
        let b: &AegisPolicyBuilder = unsafe { &*builder };

        let (p, issues) = parse_policy(bytes, true);
        if !issues.errors.is_empty() {
            // Parse failed: the C++ apply path discards the policy, so build nothing.
            return issues.errors.len() as c_int;
        }

        if let Some(f) = b.set_version {
            f(b.ctx, p.version);
        }
        if let Some(f) = b.set_flag {
            for &flag in &p.flags {
                f(b.ctx, flag_id(flag));
            }
            if p.network_enabled {
                f(b.ctx, PFLAG_NETWORK_ENABLED);
            }
            if p.cgroup_enabled {
                f(b.ctx, PFLAG_CGROUP_ENABLED);
            }
        }
        if let Some(f) = b.add_string {
            // (category, entries) in the canonical-report order. Categories that
            // carry compound data (inodes/ip:ports/cgroup keys) ship their canonical
            // string form; the C side reconstructs the struct from it.
            let emit = |cat: u32, s: &[u8]| f(b.ctx, cat, s.as_ptr() as *const c_char, s.len());
            for v in &p.deny_paths {
                emit(0, v);
            }
            for v in &p.protect_paths {
                emit(1, v);
            }
            for v in &p.deny_inodes {
                emit(2, v.as_bytes());
            }
            for v in &p.allow_cgroup_paths {
                emit(3, v);
            }
            for v in &p.deny_ips {
                emit(4, v);
            }
            for v in &p.deny_cidrs {
                emit(5, v);
            }
            for v in &p.deny_ip_ports {
                emit(6, v.as_bytes());
            }
            for v in &p.deny_binary_hashes {
                emit(7, v.as_bytes());
            }
            for v in &p.allow_binary_hashes {
                emit(8, v.as_bytes());
            }
            for v in &p.trusted_exec_hashes {
                emit(9, v.as_bytes());
            }
            for v in &p.deny_comm {
                emit(10, v);
            }
            for v in &p.scan_paths {
                emit(11, v);
            }
            for v in &p.cgroup_deny_inodes {
                emit(12, v.as_bytes());
            }
            for v in &p.cgroup_deny_ips {
                emit(13, v.as_bytes());
            }
        }
        if let Some(f) = b.add_cgroup_id {
            for &id in &p.allow_cgroup_ids {
                f(b.ctx, id);
            }
        }
        if let Some(f) = b.add_deny_port {
            for &(port, proto, dir) in &p.deny_ports {
                f(b.ctx, port, proto, dir);
            }
        }
        if let Some(f) = b.add_cgroup_deny_port {
            for (cg, (port, proto, dir)) in &p.cgroup_deny_ports {
                f(
                    b.ctx,
                    cg.as_ptr() as *const c_char,
                    cg.len(),
                    *port,
                    *proto,
                    *dir,
                );
            }
        }
        0
    });
    result.unwrap_or(-2)
}
