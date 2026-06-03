//! Differential-harness driver: parse a signed-policy-bundle file and print the
//! canonical dump (ok + fields, or `err <message>`) the parity harness compares
//! byte-for-byte against the C++ `aegisbpf policy bundle-canonical` output.
//!
//! Usage: aegis_bundle_lint <bundle-file>
use std::process::ExitCode;

fn main() -> ExitCode {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: aegis_bundle_lint <bundle-file>");
            return ExitCode::from(2);
        }
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let result = aegis_parser::parse_signed_bundle(&bytes);
    print!("{}", aegis_parser::bundle_canonical_report(&result));
    if result.is_err() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
