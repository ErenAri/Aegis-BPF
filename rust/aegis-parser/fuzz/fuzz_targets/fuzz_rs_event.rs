//! Continuous-fuzzing target for the memory-safe BPF ring-buffer event decoder.
//!
//! Drives `event_canonical_report` over arbitrary bytes of every length — the
//! decoder bounds-checks each read where the C++ `handle_event` discards the
//! record size, so a short/garbage record must yield a defined result
//! (`err short_buffer` / `unknown_type` / a decoded dump), never a panic or
//! out-of-bounds read. This is the highest-value target: it is the one decoder
//! that walks raw kernel records with manual offsets.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = aegis_parser::event_canonical_report(data);
});
