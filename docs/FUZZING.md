# AegisBPF Fuzzing Strategy

AegisBPF uses **libFuzzer with AddressSanitizer** on every parser and
untrusted-input handler. This document is the single source of truth for
what we fuzz, how often, and how to reproduce a finding locally.

## Targets

Five fuzz targets, all sanitized with `-fsanitize=fuzzer,address`:

| Target | Entry point | What it covers |
|--------|-------------|----------------|
| `fuzz_policy` | `parse_policy_file` | INI policy files (§ `[deny_path]`, `[deny_ip]`, `[deny_port]`, `[deny_cidr]`, `[allow_cgroup]`, etc.) |
| `fuzz_bundle` | `parse_signed_bundle` | Signed policy bundle parser (`AEGIS-POLICY-BUNDLE-V1` header + separator + embedded INI) |
| `fuzz_network` | `parse_ipv4`, `parse_ipv6`, `parse_cidr_v4`, `parse_cidr_v6`, `format_ipv4`, `format_ipv6` | IPv4/IPv6 and CIDR parsing/formatting |
| `fuzz_path` | `validate_path`, `parse_inode_id`, `parse_uint64`, `parse_key_value`, `trim`, `json_escape`, `prometheus_escape_label` | String-handling helpers with direct untrusted-input exposure |
| `fuzz_event` | `print_exec_event`, `print_block_event`, `print_net_block_event` | Event serializer surface (defensive: decodes untrusted ringbuf bytes before we own them as typed structs) |

Harness sources live in `tests/fuzz/fuzz_*.cpp`.
Build wiring lives in `CMakeLists.txt` guarded by `-DENABLE_FUZZING=ON`.

## Cadence

Every change is fuzzed at three intensities:

| Tier | Trigger | Duration per target | Budget (5 targets) |
|------|---------|--------------------:|-------------------:|
| **Smoke** | Every CI run on every PR and push | 60s | 5 min |
| **Parser-scoped** | PR/push that touches `src/{policy,network_ops,events,commands_policy,crypto,sha256}.cpp`, `tests/fuzz/*`, or `config/event-schema.json` | 120s | 10 min (when triggered) |
| **Deep nightly** | `cron 0 2 * * *` (02:00 UTC) and `workflow_dispatch` | 600s (configurable) | 50 min |

The smoke tier is a **blocking CI check** — PRs cannot land if a fuzzer
crashes in 60s. The parser-scoped tier uses `scripts/run_parser_fuzz_changed.sh`
to run only when parser-adjacent files change. The nightly tier surfaces
deeper bugs that need more than a minute of mutation to trigger.

Workflow files:
- `.github/workflows/ci.yml` → `smoke-fuzz` and `parser-fuzz` jobs
- `.github/workflows/nightly-fuzz.yml` → `fuzz` job

## Seed corpus

Seeds live in `tests/fuzz/corpus/<target>/` and are committed to the repo.
libFuzzer loads every file in the directory as an initial input before it
starts mutating, so well-chosen seeds dramatically reduce time-to-first-
interesting-coverage. A 6-second local run with the current seed set adds
~1,500 new coverage units to `fuzz_policy` — inputs the unseeded fuzzer
would need minutes of random mutation to discover.

See `tests/fuzz/corpus/README.md` for the layout and contribution rules.
**When you add or modify a parser, add at least one seed covering the
new shape.**

## Persistent corpus (nightly only)

The nightly job caches its runtime corpus between runs using
`actions/cache`:

```yaml
- name: Restore previous corpus
  uses: actions/cache/restore@v4
  with:
    path: runtime-corpus
    key: fuzz-corpus-${{ github.run_id }}
    restore-keys: |
      fuzz-corpus-
```

Effect: interesting inputs discovered on night N become seeds for night
N+1. Coverage compounds over time. The smoke and parser-scoped tiers
**do not** persist their corpus (every run starts from the committed
seeds) to keep PR CI deterministic.

Cache is scoped per branch with `main` as the fallback, so PR fuzz
jobs inherit `main`'s accumulated corpus without being able to pollute it.

## Reproducing a crash locally

When a fuzzer crashes, libFuzzer writes the minimized reproducer to
`crash-<sha>` in the current working directory and uploads it as a CI
artifact (`fuzz-crashes` or `nightly-fuzz-crashes`).

To reproduce:

```bash
# 1. Configure + build fuzzers
CC=clang CXX=clang++ cmake -S . -B build-fuzz -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DENABLE_FUZZING=ON \
    -DBUILD_TESTING=OFF \
    -DSKIP_BPF_BUILD=ON
cmake --build build-fuzz --target fuzz_policy   # or whichever target

# 2. Run the fuzzer against the single reproducer
./build-fuzz/fuzz_policy crash-abc123...

# 3. For ASan stack traces, add symbolization
export ASAN_OPTIONS=abort_on_error=1:symbolize=1
./build-fuzz/fuzz_policy crash-abc123...
```

The AddressSanitizer report tells you:
- What kind of bug (heap-buffer-overflow, use-after-free, etc.)
- The offending line (with `RelWithDebInfo`)
- The allocation/free stack for memory bugs

## Triage and regression

1. **Reproduce locally** with the artifact (above).
2. **Minimize** if the reproducer is large:
   ```bash
   ./build-fuzz/fuzz_policy -minimize_crash=1 -runs=100000 crash-abc123...
   ```
3. **Fix the bug** in `src/`.
4. **Regression seed**: copy the minimized crash into
   `tests/fuzz/corpus/<target>/` with a descriptive name
   (e.g. `fuzz_policy/regression-gh-issue-123.conf`). This guarantees
   every future CI run re-executes the crasher against the fixed code.
5. **File a security advisory** if the bug is exploitable (see
   `SECURITY.md`).

Do **not** put crashes in an out-of-band "regression suite" — keep them
in the seed corpus so they are exercised by the same libFuzzer path
every other seed is.

## OpenSSF Best Practices mapping

The OpenSSF Best Practices Badge criteria `security_7` (dynamic analysis)
and `analysis_3` (dynamic analysis on releases) require the project to
run dynamic analysis tooling against the codebase. AegisBPF satisfies
both via:

- **`security_7`**: libFuzzer + ASan on every CI run (smoke) and on every
  parser-touching PR (scoped). This is both ongoing and release-gating.
- **`analysis_3`**: nightly 600s-per-target deep fuzzing runs with
  compounding corpus, plus the soak harness in `scripts/soak_reliability.sh`.

See `docs/compliance/OPENSSF_BEST_PRACTICES.md` for the full
self-assessment.

## Not yet done (honest)

- **OSS-Fuzz integration** — Google's continuous fuzzing service accepts
  public projects and runs fuzzers on their ClusterFuzz infrastructure.
  AegisBPF is eligible; onboarding requires a PR to `google/oss-fuzz`.
  This is a **roadmap item**; the in-repo fuzzing above does not depend
  on it.
- **ClusterFuzzLite** — self-hosted lightweight variant. Also roadmap.
- **Structure-aware mutators** (protobuf-mutator, etc.) — the INI and
  bundle parsers could benefit, but plain libFuzzer + seeds already
  produces good coverage on these grammars.
- **Coverage reporting to a dashboard** — we run with
  `-print_final_stats=1` in CI but don't publish coverage deltas yet.

## References

- libFuzzer:           <https://llvm.org/docs/LibFuzzer.html>
- AddressSanitizer:    <https://clang.llvm.org/docs/AddressSanitizer.html>
- Seed corpus guide:   <https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md#corpus>
- OSS-Fuzz:            <https://google.github.io/oss-fuzz/>
- ClusterFuzzLite:     <https://google.github.io/clusterfuzzlite/>
