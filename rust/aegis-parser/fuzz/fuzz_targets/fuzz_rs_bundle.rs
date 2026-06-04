//! Continuous-fuzzing target for the memory-safe signed-bundle decoder.
//!
//! Drives `parse_signed_bundle` over arbitrary bytes (the signed-bundle header is
//! operator/CI-supplied and is the input to signature verification), then the
//! `canonical_report` dump. Must never panic for any input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let result = aegis_parser::parse_signed_bundle(data);
    let _ = aegis_parser::bundle_canonical_report(&result);
});
