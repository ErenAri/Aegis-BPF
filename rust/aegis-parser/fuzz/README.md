# aegis-parser fuzz targets

Continuous-fuzzing harness ([`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
/ libFuzzer) for the three memory-safe decoders on the untrusted-input boundary.
This is the "wire the Rust targets into continuous fuzzing" step from
`docs/MEMORY_SAFETY.md`.

| target            | drives                                                        |
|-------------------|---------------------------------------------------------------|
| `fuzz_rs_policy`  | `parse_policy(data, true)` + `canonical_report`               |
| `fuzz_rs_bundle`  | `parse_signed_bundle` + `bundle_canonical_report`             |
| `fuzz_rs_event`   | `event_canonical_report` (raw ring-buffer event records)      |

Each target asserts the decoder **terminates without panicking** on arbitrary
bytes of any length — the same property the in-tree `adversarial_inputs_never_panic`
unit tests check, here exercised continuously. The decoders are `#![forbid(unsafe_op_in_unsafe_fn)]`
and contain no `unsafe`, so a libFuzzer crash would mean a logic panic
(index/slice/overflow), not memory corruption.

This is a **separate package** (it has its own `[workspace]`), so it is invisible
to the parent crate's `cargo fmt/clippy/test/build` and to the stable
`rust-parser.yml` merge gate. It needs a **nightly** toolchain + libFuzzer and runs
in `.github/workflows/nightly-fuzz.yml`.

## Run locally

```bash
cd rust/aegis-parser
rustup toolchain install nightly
cargo install cargo-fuzz --locked

cargo +nightly fuzz build                       # build all three targets
cargo +nightly fuzz run fuzz_rs_event -- -max_total_time=60
```

Seed corpora under `corpus/<target>/` are copied from the differential-parity
fixtures so coverage starts non-empty; libFuzzer grows them at runtime (the
nightly job caches the grown corpus across runs).
