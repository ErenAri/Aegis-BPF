//! Memory-safe parsers for the AegisBPF untrusted-input boundary.
//!
//! `policy` is a faithful Rust port of the C++ policy parser
//! (`src/policy_parse.cpp`). It is validated against the C++ implementation by
//! the differential parity harness (`scripts/rust_policy_parity.sh`) and is NOT
//! yet wired into the production load path — see `README.md` for the staged-swap
//! plan. `ffi` is the (staged) C ABI seam for that swap.
#![forbid(unsafe_op_in_unsafe_fn)]

pub mod policy;

mod ffi;

pub use ffi::{aegis_policy_parse, AegisPolicySink};
pub use policy::{canonical_report, parse_policy, Flag, Policy, PolicyIssues};
