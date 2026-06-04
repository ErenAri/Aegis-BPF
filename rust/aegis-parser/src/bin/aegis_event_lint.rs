//! Differential-harness driver: decode a raw BPF ring-buffer event record from a
//! file and print the canonical field dump that the parity harness
//! (`scripts/rust_event_parity.sh`) compares byte-for-byte against the C++
//! `aegisbpf policy event-canonical` output.
//!
//! The file holds the raw bytes of one `Event` record (the same blob
//! `handle_event` receives via `void* data`). Decoding never fails for I/O
//! reasons here; a too-short record yields `err short_buffer <len>` and an
//! unrecognized type yields `unknown_type <n>`, both matching the C++ emitter.
//!
//! Usage: aegis_event_lint <event-file>
use std::process::ExitCode;

fn main() -> ExitCode {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: aegis_event_lint <event-file>");
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
    print!("{}", aegis_parser::event_canonical_report(&bytes));
    ExitCode::SUCCESS
}
