//! Continuous-fuzzing target for the memory-safe policy parser.
//!
//! Drives `parse_policy` (with conflict detection) over arbitrary bytes, then the
//! `canonical_report` dump of the result. Both must terminate without panicking
//! for ANY input — the memory-safety property the differential-parity harness and
//! the in-tree `adversarial_inputs_never_panic` test assert, now exercised
//! continuously by libFuzzer.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (policy, issues) = aegis_parser::parse_policy(data, true);
    // The canonical dump walks every parsed/stored entry; it must also never panic.
    let _ = aegis_parser::canonical_report(&policy, &issues);
});
