# aegis-parser

Memory-safe Rust parsers for the AegisBPF **untrusted-input boundary**, starting
with the policy file. This crate is part of the Rust-oxidation track of the
enforcement wedge (memory-safe parsing of attacker/CI-influenced input).

## Status: proven, staged — NOT yet in the production path

`policy::parse_policy` is a **faithful Rust port** of the C++ policy parser
(`src/policy_parse.cpp` + `detect_policy_conflicts`). It reproduces the exact
observable behavior — per-line errors/warnings (verbatim text + line numbers),
section/flag/version handling, de-duplication, post-parse version gating, and
lint conflicts.

It is **not** wired into the live `policy apply`/`run` path yet. Swapping the
production parser is a load-bearing, security-critical change (a silent parse
divergence = a policy that enforces differently than the operator expects), so
the swap is gated on two things:

1. **Differential parity** — `scripts/rust_policy_parity.sh` compares the
   **full canonical dump** of *both* parsers (the C++ `aegisbpf policy canonical`
   subcommand and this crate's `canonical_report`): `version`, the set flags,
   **every stored entry in every category** (in insertion order, with ports and
   ip:port rules normalized to their parsed/canonical forms), and the sorted
   error/warning strings. This proves *structural* equivalence — same accept/
   reject, same de-dup, same canonicalization, same stored result — not merely
   that the two agree on counts. It runs over the corpus + examples + fixtures
   plus two deterministic generated families (adversarial junk for the reject/
   error surface, and always-valid v6 policies for the stored-entry surface),
   and fails on any divergence. This is the merge gate
   (`.github/workflows/rust-parser.yml`).
2. **Human review** of the swap PR.

Until both are satisfied, the C++ parser remains authoritative. The `ffi` module
(`aegis_policy_parse` + `AegisPolicySink`) is the C ABI seam the swap will use,
so promotion is a wiring change rather than a rewrite.

## Why oxidize this first

The policy parser is the most operator-facing untrusted-input surface. The C++
implementation is already `std::string`-based (bounds-safe), so the immediate win
is *defense-in-depth* and a single, `unsafe`-free, exhaustively-fuzzable parser —
not a fix for a known memory bug. The next oxidation targets (the signed-bundle
and event binary decoders, which walk raw byte buffers with manual offsets) carry
more raw memory-safety value and reuse this crate's FFI + parity pattern.

## Develop

```bash
cd rust/aegis-parser
cargo test                 # unit + adversarial tests
cargo clippy -- -D warnings
cargo fmt --check

# differential parity vs the C++ parser (needs build/aegisbpf):
../../scripts/rust_policy_parity.sh --fuzz 2000
```

## Fidelity caveats (honest scope)

- IP / CIDR validation uses Rust's `std::net::{Ipv4Addr, Ipv6Addr}`, which closely
  track `inet_pton`/`inet_ntop`. The full-structured harness now also compares the
  *canonicalized* `deny_ip_port` keys (e.g. `2001:db8:0:0:0:0:0:1` →
  `2001:db8::1`), so any `inet_ntop`-vs-Rust formatting divergence would fail the
  gate; none is observed over the corpus + fixtures + 4000 generated inputs.
- Entry text and error/warning *messages* are compared over the UTF-8 input
  domain: values render via `from_utf8_lossy`, so a non-UTF-8 byte in a stored
  value or message would render cosmetically differently from C++ (the parse
  decision and de-dup are unaffected). Realistic operator/CI policies are
  UTF-8/ASCII; the corpus's only non-ASCII bytes are in comment lines.
- The proof is "structurally equivalent over the tested corpus + fixtures +
  fuzzing," not an exhaustive equivalence proof — which is exactly why the
  production swap also requires review.
