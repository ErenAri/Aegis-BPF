# Test Coverage

This document records the project's **honest** code-coverage state, the
gating mechanism that prevents regressions, and the concrete plan to
reach the 80% line-coverage roadmap target.

## Current state (as of this commit)

| Metric         | Measured | Gate (CI fails below) |
|----------------|---------:|----------------------:|
| Line coverage  |   29.7 % |               28 %    |
| Branch coverage|   12.1 % |               11 %    |
| Function       |   43.0 % |          *(not gated)* |

Measured locally via:

```bash
cmake -S . -B build-cov -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_TESTING=ON -DENABLE_COVERAGE=ON -DSKIP_BPF_BUILD=ON
cmake --build build-cov
ctest --test-dir build-cov --output-on-failure
gcovr --root . --object-directory build-cov \
  --exclude tests --exclude 'build-cov/_deps' \
  --merge-mode-functions=merge-use-line-min --print-summary
```

The CI job in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)
runs the same command with `--fail-under-line` / `--fail-under-branch`
pulled from [`config/coverage_thresholds.json`](../config/coverage_thresholds.json).

## Why we're not at 80% yet

About 60% of the C++ source tree is one of:

- **Command handlers** that drive the live daemon, talk to the kernel,
  or open netlink/perf sockets (`commands_emergency.cpp`,
  `commands_health.cpp`, `commands_block_allow.cpp`, `bpf_attach.cpp`,
  `bpf_signing.cpp`, `commands_cgroup.cpp`, `control.cpp`, …).
  These are exercised by integration tests on a real kernel
  (`tests/e2e/`, the `kernel-matrix` workflow), not by GTest unit tests.
  Their `.gcda` files don't show up in the unit-test coverage run.
- **Hot paths covered indirectly** through end-to-end fixtures that the
  ASAN / UBSAN / TSAN unit-test pipeline doesn't replay.

So today's 29.7% line coverage is roughly "everything reachable from
ctest without root + a live BPF subsystem". Closing the gap to 80%
isn't a question of writing more unit tests for the well-covered
files — those already sit at 70–85%. It requires merging integration-
test coverage into the same `.gcov` summary.

## Top under-covered modules (by absolute uncovered LOC)

| File                              | Lines | Covered | Uncovered |
|-----------------------------------|------:|--------:|----------:|
| `src/policy_runtime.cpp`          |   843 |    109  |       734 |
| `src/network_ops.cpp`             |   780 |    124  |       656 |
| `src/bpf_ops.cpp`                 |   890 |     98  |       792 |
| `src/daemon.cpp`                  |   595 |    272  |       323 |
| `src/commands_metrics.cpp`        |   476 |     50  |       426 |
| `src/events.cpp`                  |   409 |     27  |       382 |
| `src/commands_network.cpp`        |   362 |     36  |       326 |
| `src/utils.cpp`                   |   503 |    230  |       273 |
| `src/commands_emergency.cpp`      |   203 |     12  |       191 |

The top three (`policy_runtime`, `network_ops`, `bpf_ops`) account for
~2.2k uncovered lines on their own — about 20 percentage points of
project-wide line coverage if fully tested. They're also the modules
with the most kernel-side dependencies, so they're the hardest to lift.

## Roadmap to 80%

Ordered by effort-to-gain ratio:

1. **`src/utils.cpp` (45% → 80%, +35pp on this file, ~+1.5pp project-wide)**
   Pure functions; no kernel surface. Add unit tests around path
   resolution, cgroup parsing, hex/base64 helpers.
2. **`src/commands_*` cluster (most at <30%)**
   Add table-driven CLI tests that exercise each subcommand's
   argument-parsing and short-circuit error paths. Avoids touching
   the BPF runtime.
3. **`src/policy_runtime.cpp` (13% → 60%, ~+8pp project-wide)**
   The reload + merge logic is testable with a mocked BPF map layer.
   Already partly factored; needs a fake `bpf_maps` shim.
4. **Integration coverage merge** (largest single jump)
   Build the daemon with `ENABLE_COVERAGE=ON` for the `kernel-matrix`
   and `e2e` jobs, merge the resulting `.gcov` artifacts into the
   unit-test summary with `gcovr --add-tracefile`. Expected jump:
   ~+25–30pp once we cover `bpf_attach`, `bpf_ops`, `events`,
   `network_ops`, and the command handlers exercised end-to-end.

Each of those four steps is a separate PR. The CI gate ratchets
upward via [`coverage-ratchet.yml`](../.github/workflows/coverage-ratchet.yml):
once measured coverage exceeds the gate by `ratchet_margin` (3pp) for
`streak_required` (3) consecutive weekly runs, it opens an issue
proposing a threshold bump of `ratchet_step_line` (2pp).

## How the gate works

[`config/coverage_thresholds.json`](../config/coverage_thresholds.json):

```json
{
  "line_min": 28,
  "branch_min": 11,
  "ratchet_margin": 3,
  "ratchet_step_line": 2,
  "ratchet_step_branch": 1,
  "streak_required": 3
}
```

- `line_min` / `branch_min`: hard floors. PRs that drop below either
  fail the `coverage` job in `ci.yml`.
- `ratchet_margin`: the *advisory* margin above the floor. The
  `coverage-ratchet` workflow only proposes a bump when measured
  coverage exceeds floor + margin.
- `ratchet_step_*`: how much to bump the floor per ratchet cycle.
- `streak_required`: how many consecutive weekly runs must meet the
  margin before a bump is proposed.

## Why this commit moves the floor 20→28 / 8→11

Before this commit, the floor was set during early scaffolding and
never updated. Locking in the actually-measured floor (with a 1.7pp /
1.1pp safety gap that matches the existing ratchet advisor's
convention) means a regression in any PR that drops, say, `crypto.cpp`
from 69% to 50% will now fail CI rather than silently slip through.

The 80% target is *not* moved into the gate by this commit. That's
the destination, reached via the four-step roadmap above.

## See also

- [`docs/QUALITY_GATES.md`](QUALITY_GATES.md) — full CI gate policy
- [`scripts/coverage_ratchet_advisor.py`](../scripts/coverage_ratchet_advisor.py)
  — ratchet recommendation logic
- [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) `coverage:` job
- [`.github/workflows/coverage-ratchet.yml`](../.github/workflows/coverage-ratchet.yml)
  — weekly ratchet proposal
