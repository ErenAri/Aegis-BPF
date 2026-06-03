//! Differential-harness driver: parse a policy file and print the full canonical
//! dump (version, flags, every stored entry, sorted errors/warnings) the parity
//! harness compares byte-for-byte against the C++ `aegisbpf policy canonical`
//! output.
//!
//! Usage: aegis_policy_lint <policy-file>
use std::process::ExitCode;

fn main() -> ExitCode {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: aegis_policy_lint <policy-file>");
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
    // with_conflicts=true mirrors `policy lint` (parse + detect_policy_conflicts).
    let (policy, issues) = aegis_parser::parse_policy(&bytes, true);
    print!("{}", aegis_parser::canonical_report(&policy, &issues));
    if issues.has_errors() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
