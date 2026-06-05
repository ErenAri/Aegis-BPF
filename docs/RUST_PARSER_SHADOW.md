# Rust-parser shadow & consensus — operator runbook

This is the operational guide for the memory-safe Rust **policy parser** running
alongside the authoritative C++ parser. It is the staged path toward swapping the
parser of attacker/CI-influenced input to a memory-safe implementation (see
`docs/MEMORY_SAFETY.md` and `rust/aegis-parser/README.md`).

**The point of this runbook:** turn the shadow on in a real environment, collect
divergence evidence over time, and only then consider tightening to `enforce` and
(eventually) the full swap. The work is already parity-proven offline; this is
about earning confidence on *your* real policies before changing enforcement.

## What it is (and is not)

When built and enabled, every `policy apply` re-parses the same policy through the
Rust parser's C ABI seam and compares its **full canonical dump** (version, flags,
every stored entry, sorted errors/warnings) against the C++ canonical for the same
file.

- It is a **diagnostic / consensus** layer. The **C++ parser is always
  authoritative for policy content** — the Rust result never changes *what* is
  enforced.
- In `enforce` mode it can **reject** an apply on divergence (fail-closed), but it
  can never *apply something different* — the only behavior change is "reject
  instead of apply" when the two parsers disagree.
- It is **OFF by default** and absent entirely from a normal build.

> Scope caveat: this protects the *applied policy* (a C++ parse bug that corrupted
> the policy would diverge from Rust and be caught/rejected). It does **not** yet
> remove the C++ parser's exposure to untrusted input at parse time — C++ still
> parses. Eliminating that is the full swap (a future, human-gated step requiring a
> richer FFI that transports the whole parsed policy).

## Build

The shadow needs the Rust staticlib linked in, which needs a Rust toolchain
(`cargo`). It is **x86_64 only** for now — do **not** enable it on the ARM64 /
Docker build lanes (they have no Rust cross-toolchain).

```bash
# A normal build is unchanged and needs no Rust toolchain:
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release

# Shadow-enabled build (links rust/aegis-parser; defines AEGIS_RUST_SHADOW):
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DENABLE_RUST_PARSER_LINK=ON
cmake --build build --target aegisbpf
```

With the option **off** (the default) the build is byte-identical to before and
the shadow code compiles to a no-op.

## Runtime modes — `AEGIS_RUST_SHADOW`

The mode is read from the `AEGIS_RUST_SHADOW` environment variable at apply time.
Even a shadow-enabled binary is inert until you set it.

| value          | mode    | behavior                                                        |
|----------------|---------|-----------------------------------------------------------------|
| *(unset/other)*| Off     | no-op (default)                                                 |
| `shadow` / `1` | Shadow  | re-parse + **log** any canonical divergence; apply proceeds     |
| `enforce`      | Enforce | a divergence **rejects** the apply, fail-closed                 |

Set it on the daemon's environment (systemd drop-in, k8s env, etc.), e.g.:

```ini
# /etc/systemd/system/aegisbpf.service.d/rust-shadow.conf
[Service]
Environment=AEGIS_RUST_SHADOW=shadow
```

## What to watch

All signals are structured logs (no new metric is emitted yet). Grep your log
sink for `rust parse shadow`:

- **Agreement** (the expected steady state) — `DEBUG`:
  `rust parse shadow: canonical agrees with C++ parser`
- **Divergence** (investigate immediately) — `WARN`:
  `rust parse shadow: canonical divergence vs authoritative C++ parser`
  with `path`, `enforce`, and `cpp_canonical_len` / `rust_canonical_len`.
- **Seam failure** (should never happen) — `WARN`:
  `rust parse shadow: FFI returned a negative code`.

In `enforce` mode, a divergence also fails the apply with
`PolicyParseFailed` — `Rust/C++ parser canonical divergence; rejecting policy
(fail-closed)`.

A divergence is a real finding: the two parsers are proven equivalent over the
corpus + fuzzing, so any divergence on a real policy is either a parser bug worth
filing or a policy construct the test corpus doesn't cover. Capture the policy
file and open an issue.

## Recommended rollout

1. **Shadow (observe).** Deploy the shadow-enabled build with
   `AEGIS_RUST_SHADOW=shadow` to a representative fleet. Run for a few weeks
   across your real policies. Expected result: only `DEBUG` agreement lines, zero
   `divergence` warnings.
2. **Enforce (fail-closed).** Once shadow has been clean for long enough on your
   policy mix, switch a canary to `AEGIS_RUST_SHADOW=enforce`. Now a (still
   not-expected) divergence rejects the apply rather than logging — the safe
   direction. Confirm legitimate policies still apply.
3. **Full swap (future, human-gated).** Making Rust the *sole* parser (so C++ no
   longer touches untrusted input) is a separate change — a richer FFI + a canary'd
   flip — and a decision to make only after enforce has been clean in production.

## Rollback

Instant and total at every stage, no redeploy needed for the runtime gate:

- **Disable at runtime:** unset `AEGIS_RUST_SHADOW` (or set it to anything other
  than `shadow`/`1`/`enforce`) and re-apply / restart the daemon. The shadow goes
  inert; the C++ parser was authoritative all along, so nothing about enforcement
  changes.
- **Remove entirely:** rebuild without `-DENABLE_RUST_PARSER_LINK=ON`. The binary
  is byte-identical to a stock build and carries no Rust code.

Because the C++ parser is authoritative in every mode, there is no state to
unwind — the applied policy is identical whether the shadow ran or not (Shadow
mode) or the apply was simply rejected (Enforce mode).
