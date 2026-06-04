# aegis-parser

Memory-safe Rust parsers for the AegisBPF **untrusted-input boundary**. This
crate is part of the Rust-oxidation track of the enforcement wedge (memory-safe
parsing of attacker/CI-influenced input). Three targets are ported and proven:

- `policy` — the policy-file parser (`src/policy_parse.cpp`).
- `bundle` — the signed-policy-bundle decoder (`parse_signed_bundle`,
  `src/crypto.cpp`), the input to signature verification.
- `event` — the BPF ring-buffer event decoder (`handle_event` + the
  `print_*_event` field extraction, `src/events.cpp`), which walks raw kernel
  records with manual offsets.

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

`event::canonical_report` is a faithful, bounds-checked port of the C++ event
consumer `handle_event`: dispatch on the `u32` `type` at record offset 0, read
every typed payload through the `Event` union (payload at offset 8, verified by a
layout probe against `src/types.hpp`), extract `char[]` fields like C++
`to_string` (`string(buf, strnlen(buf, n))`), and derive the net-block label from
`direction` / the kernel-block label from the `rule_type` string exactly as
`print_net_block_event` / `print_kernel_block_event` do. Where the C++ consumer
does `static_cast<const Event*>(data)` and **discards the record size**, the Rust
decoder bounds-checks every read — a short record yields `err short_buffer <len>`
instead of an out-of-bounds read. (Oxidizing this surfaced — and the same change
fixed — a real latent bug: `handle_event` had been decoding forensic events through
a stale `Event::forensic` union member at offset 8 against a BPF-emitted *bare*
`forensic_event` (offset 0, 104 B), an 8-byte field shift plus an 8-byte over-read;
both the C++ consumer and this port now decode the bare record at offset 0, guarded
by an ASan regression test. See the module docs.)

None is wired into the live `policy apply`/`run` (or event-consumer) path yet. Swapping a
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
   (`.github/workflows/rust-parser.yml`). The BPF-event decoder has a third
   harness, `scripts/rust_event_parity.sh`, comparing the C++ `aegisbpf policy
   event-canonical` dump against the crate's `event::canonical_report` over
   committed binary fixtures and two generated families (valid Event-shaped
   records across every event type, and adversarial random-length/random-byte
   records). It is also a merge gate.
2. **Human review** of the swap PR.

Until both are satisfied, the C++ parser remains authoritative. The `ffi` module
(`aegis_policy_parse` + `AegisPolicySink`) is the C ABI seam for the **policy**
swap specifically; it is the template each swap follows — the `bundle` and
`event` decoders still need their own analogous C ABI exports wired before they
can be promoted. So promotion is a (still-pending) wiring change against an
established pattern rather than a rewrite.

## Why these three

The policy parser is the most operator-facing untrusted-input surface. The C++
implementation is already `std::string`-based (bounds-safe), so the immediate win
is *defense-in-depth* and a single, `unsafe`-free, exhaustively-fuzzable parser —
not a fix for a known memory bug. The signed-bundle decoder (`bundle`) is the
second target: it sits on the same untrusted boundary and its split point decides
which bytes are treated as the signed policy body. The event binary decoder
(`event`) is the third and carries the most raw memory-safety value: the C++
`handle_event` does `static_cast<const Event*>(data)` over a raw ring-buffer
record, reads fixed-offset fields and walks fixed-size `char` arrays, and
**discards the record size** — so a producer/consumer struct-layout drift or a
short record becomes a silent out-of-bounds read. The Rust port bounds-checks
every read and reuses this crate's parity pattern.

## Develop

```bash
cd rust/aegis-parser
cargo test                 # unit + adversarial tests
cargo clippy -- -D warnings
cargo fmt --check

# differential parity vs the C++ originals (needs build/aegisbpf):
../../scripts/rust_policy_parity.sh --fuzz 2000
../../scripts/rust_bundle_parity.sh --fuzz 2000
../../scripts/rust_event_parity.sh  --fuzz 2000
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
- The event harness pins the *decode* (field offsets, integer endianness,
  NUL-terminated `char[]` extraction via length-exact hex, and the
  direction/`rule_type` → label derivation), not address *text* formatting:
  remote addresses are compared as raw hex bytes, so the `inet_ntop`-vs-Rust
  formatting question (already a documented caveat above) is deliberately out of
  this gate's scope — the bytes are pinned, the presentation is not. Forensic
  records are decoded at offset 0 as a *bare* `forensic_event` (104 B), matching
  the BPF producer and the now-corrected `handle_event` (this change fixed the
  prior offset-8 union read; a host-side ASan test guards the over-read). All
  other event types are decoded from the 344-byte `Event` envelope at offset 8.
  Multi-byte integers are read little-endian (native order on the x86-64/aarch64
  hosts that run the daemon); a big-endian consumer host is out of scope.
- The proof is "structurally equivalent over the tested corpus + fixtures +
  fuzzing," not an exhaustive equivalence proof — which is exactly why the
  production swap also requires review.
