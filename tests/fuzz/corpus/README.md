# Fuzz Seed Corpus

This directory contains **seed inputs** for each libFuzzer target defined
in `tests/fuzz/`. Seeds give the fuzzer a head start by establishing
coverage of known-good shapes; libFuzzer then mutates them to explore
edge cases much faster than starting from a zero-byte input.

## Layout

```
tests/fuzz/corpus/
├── fuzz_policy/    — INI policy files (parse_policy_file)
├── fuzz_bundle/    — signed policy bundles  (parse_signed_bundle)
├── fuzz_network/   — IP / CIDR / port strings (parse_ipv4 / parse_cidr_* / parse_ipvN)
├── fuzz_path/      — path, inode-id, key=value strings (validate_path / parse_inode_id / parse_key_value)
└── fuzz_event/     — raw event struct bytes (print_{exec,block,net_block}_event)
```

## How seeds are used

Each fuzz executable in `.github/workflows/ci.yml` (`smoke-fuzz` and
`parser-fuzz`) and `.github/workflows/nightly-fuzz.yml` is invoked with
the corresponding corpus directory as its first positional argument:

```bash
./build-fuzz/fuzz_policy tests/fuzz/corpus/fuzz_policy -max_total_time=60
```

libFuzzer:

1. Loads every file in the directory as an initial input.
2. Executes the target with each seed once (fast coverage mapping).
3. Mutates interesting seeds and writes new interesting mutations
   **back to the same directory** (that is why the nightly workflow
   caches this directory between runs — see `actions/cache` in
   `nightly-fuzz.yml`).

## Adding new seeds

- Keep each seed small (< 4 KiB).
- Filenames are human-readable hints; libFuzzer does not rely on them.
- Commit only deterministic, reviewable inputs. If an input is binary,
  note its layout in this README.
- Do **not** commit crash reproducers here — put them in
  `tests/fuzz/regression/` (separate directory, exercised by a unit
  test that must pass, not a fuzz run).

## Persistence model

- **`tests/fuzz/corpus/`** is the **seed** corpus checked into git.
  It is immutable from CI's perspective (seeds are never deleted by
  the fuzz run).
- The **runtime** corpus used in CI is a writable copy. In the
  `smoke-fuzz` and `parser-fuzz` jobs this copy lives in a tmp dir and
  is discarded at job end. In the nightly job it is cached via
  `actions/cache` so discoveries compound night-over-night.

## Minimum coverage claim

Seed coverage is the minimum AegisBPF expects libFuzzer to reach in
≤ 10 seconds. If you add or modify a parser in
`src/{policy,crypto,network_ops,utils,events}.*`, please add at least
one seed exercising the new shape before merging.
