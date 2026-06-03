//! C ABI for the policy parser — the (staged) integration seam for the C++ agent.
//!
//! NOT yet called by the production load path. It exists so the eventual swap is
//! a wiring change, not a rewrite, and so the boundary is reviewable now. The
//! C++ side passes a sink of callbacks; Rust parses and reports each error and
//! warning back through it. Panics are caught so unwinding never crosses FFI.
use core::ffi::{c_char, c_int, c_void};

use crate::policy::parse_policy;

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
