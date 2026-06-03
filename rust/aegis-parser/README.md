# aegis-parser

Memory-safe Rust parsers for the AegisBPF **untrusted-input boundary**. This
crate is part of the Rust-oxidation track of the enforcement wedge (memory-safe
parsing of attacker/CI-influenced input). Two targets are ported and proven:

- `policy` — the policy-file parser (`src/policy_parse.cpp`).
- `bundle` — the signed-policy-bundle decoder (`parse_signed_bundle`,
  `src/crypto.cpp`), the input to signature verification.

## Status: proven, staged — NOT yet in the production path

`policy::parse_policy` is a **faithful Rust port** of the C++ policy parser
(`src/policy_parse.cpp` + `detect_policy_conflicts`). It reproduces the exact
observable behavior — per-line errors/warnings (verbatim text + line numbers),
section/flag/version handling, de-duplication, post-parse version gating, and
lint conflicts.

`bundle::parse_signed_bundle` is a faithful port of `parse_signed_bundle`: the
same separator rule (first `"---"` substring anywhere), header/field handling,
recognized keys, first-error-wins ordering and error classes, and — crucially —
the same *lenient* integer parsing as C++ `std::stoul`/`std::stoull` (skip
leading whitespace, accept a leading sign with `-` wrapping for unsigned, ignore
trailing non-digits, treat overflow as an error; `format_version` truncates to
`u32` like the C++ `static_cast`).

Neither is wired into the live `policy apply`/`run` path yet. Swapping a
production parser is a load-bearing, security-critical change (a silent parse
divergence = a policy that enforces differently than the operator expects, or a
different byte range treated as the signed body), so each swap is gated on two
things:

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
   and fails on any divergence. The signed bundle has its own harness,
   `scripts/rust_bundle_parity.sh`, comparing the C++ `aegisbpf policy
   bundle-canonical` dump against the crate's `bundle::canonical_report` over
   committed fixtures, **real** `keygen`+`sign` bundles, and two generated
   families (valid synthetic + adversarial). Both are merge gates
   (`.github/workflows/rust-parser.yml`).
2. **Human review** of the swap PR.

Until both are satisfied, the C++ parser remains authoritative. The `ffi` module
(`aegis_policy_parse` + `AegisPolicySink`) is the C ABI seam the swap will use,
so promotion is a wiring change rather than a rewrite.

## Why oxidize this first

The policy parser is the most operator-facing untrusted-input surface. The C++
implementation is already `std::string`-based (bounds-safe), so the immediate win
is *defense-in-depth* and a single, `unsafe`-free, exhaustively-fuzzable parser —
not a fix for a known memory bug. The signed-bundle decoder (now ported in
`bundle`) is the second target: it sits on the same untrusted boundary and its
split point decides which bytes are treated as the signed policy body. The
remaining target — the event binary decoder, which walks raw ringbuf buffers with
manual offsets — carries the most raw memory-safety value and reuses this crate's
FFI + parity pattern.

## Develop

```bash
cd rust/aegis-parser
cargo test                 # unit + adversarial tests
cargo clippy -- -D warnings
cargo fmt --check

# differential parity vs the C++ originals (needs build/aegisbpf):
../../scripts/rust_policy_parity.sh --fuzz 2000
../../scripts/rust_bundle_parity.sh --fuzz 2000
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
- The bundle harness compares the extracted policy body by length + FNV-1a 64
  (computed identically on both sides) rather than dumping raw bytes; this pins
  the separator split exactly without emitting large/binary bodies. It validates
  *parsing*, not signature cryptography (`verify_bundle` is unchanged C++).
- The proof is "structurally equivalent over the tested corpus + fixtures +
  fuzzing," not an exhaustive equivalence proof — which is exactly why the
  production swap also requires review.
