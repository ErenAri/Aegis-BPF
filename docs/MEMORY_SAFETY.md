# Memory Safety Posture

AegisBPF's privileged userspace agent is written in C++20. A root-privileged
agent that parses attacker-influenceable input is a memory-safety-sensitive
surface, so this document states what we do about it honestly, rather than
claiming a property the language does not give us for free.

## Current posture

The userspace agent is **hardened C++**, not memory-safe-by-construction. The
mitigations in place today:

- **Compiler hardening:** `_FORTIFY_SOURCE`, stack-protector-strong, PIE,
  full RELRO, and the standard warning/`-Werror` surface (see `CMakeLists.txt`
  and the binary-hardening contract test).
- **Sanitizer CI:** AddressSanitizer, ThreadSanitizer, and
  UndefinedBehaviorSanitizer builds run in CI (`build-asan*`, `build-tsan*`,
  `build-ubsan*`).
- **Fuzzing:** parser/decoder fuzz harnesses under `tests/fuzz/` run via the
  nightly fuzz workflow.
- **Runtime sandboxing:** the daemon can restrict itself with a **seccomp**
  allowlist and a **Landlock** self-sandbox, shrinking the syscall/filesystem
  surface available post-compromise.
- **Vendored crypto** (`tweetnacl`) is pinned and gated by a periodic
  human-review staleness check (`vendored_dependency_contract`).

## The risk we are managing

The highest-risk code is the **untrusted-input boundary** — anything that
parses bytes an attacker can influence:

- the policy file parser (`src/policy_parse.cpp`),
- the signed-policy-bundle decoder (`parse_signed_bundle`, `src/crypto.cpp`),
- the BPF ring-buffer event decoder (`handle_event` + `print_*_event`,
  `src/events.cpp`), which `static_cast`s a raw kernel record and walks
  fixed-offset fields,
- the event / JSON decoders (`src/json_scan.cpp`, the `explain <event.json>`
  path).

A memory-safety defect is far more dangerous here than in code that only
touches trusted, agent-generated data.

## Direction

1. **Harden further (cheap, in progress):** `_FORTIFY_SOURCE=3`,
   `-D_GLIBCXX_ASSERTIONS`, `-fstack-clash-protection`, and CFI
   (`-fsanitize=cfi` with LTO); evaluate a hardened allocator.
2. **Oxidize the untrusted-input boundary (in progress):** memory-safe Rust
   ports of the three highest-risk decoders now live in `rust/aegis-parser`
   (`policy`, `bundle`, `event`), each proven behavior-equivalent to its C++
   original by a differential-parity merge gate
   (`scripts/rust_*_parity.sh`, `.github/workflows/rust-parser.yml`) over a
   corpus + fixtures + deterministic fuzzing. They are also **continuously
   fuzzed**: `rust/aegis-parser/fuzz` holds cargo-fuzz/libFuzzer targets for all
   three decoders, run nightly (`.github/workflows/nightly-fuzz.yml`, the
   `rust-fuzz` job) seeded from the parity fixtures. They are **staged, not yet
   swapped**: the C++ implementations remain authoritative until each swap
   passes its parity gate *and* human review (and the crate is linked into the
   build — an architectural step deliberately kept separate). The remaining next
   step is wiring the Rust targets in behind their C ABI shim (an in-process
   shadow comparison, then promotion); a hosted OSS-Fuzz/ClusterFuzzLite-Rust
   integration is a further option beyond the nightly job. This puts memory-safe
   code exactly where attacker-influenced bytes are parsed, without rewriting the
   working, test-covered remainder.
3. **Full Rust/Aya rewrite is explicitly deferred.** It is the right greenfield
   answer, but it would discard a verified, test-covered asset for a property
   that hardening + privilege-separation + targeted Rust + fuzzing already
   largely deliver. Revisit only for a v2 or at the request of a major adopter.

## What this is not

This is not a claim that the agent is memory-safe. It is a claim that the
memory-safety risk is **identified, bounded, mitigated, and on a path to
reduction** — and that the most dangerous 10% (untrusted parsers) is the first
thing being moved to a memory-safe language: the three highest-risk decoders
already have proven-equivalent Rust ports staged behind parity gates, awaiting
the human-reviewed production swap.
