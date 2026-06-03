//! Memory-safe parsers for the AegisBPF untrusted-input boundary.
//!
//! `policy` is a faithful Rust port of the C++ policy parser
//! (`src/policy_parse.cpp`); `bundle` is a faithful port of the signed-policy-
//! bundle decoder (`parse_signed_bundle`, `src/crypto.cpp`). Each is validated
//! against the C++ implementation by a differential parity harness
//! (`scripts/rust_policy_parity.sh`, `scripts/rust_bundle_parity.sh`) and is NOT
//! yet wired into the production load path — see `README.md` for the staged-swap
//! plan. `ffi` is the (staged) C ABI seam for that swap.
#![forbid(unsafe_op_in_unsafe_fn)]

pub mod bundle;
pub mod policy;

mod ffi;

pub use bundle::{canonical_report as bundle_canonical_report, parse_signed_bundle, Bundle};
pub use ffi::{aegis_policy_parse, AegisPolicySink};
pub use policy::{canonical_report, parse_policy, Flag, Policy, PolicyIssues};
