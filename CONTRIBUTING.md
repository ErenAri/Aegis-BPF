# Contributing to AegisBPF

Thanks for contributing. Keep changes small, tested, and reviewable.

## Licensing of contributions

AegisBPF is licensed under the [Apache License, Version 2.0](LICENSE).

By submitting a pull request, you agree that your contribution is
licensed under Apache-2.0 — explicitly per Section 5 of the license:

> Unless You explicitly state otherwise, any Contribution intentionally
> submitted for inclusion in the Work by You to the Licensor shall be
> under the terms and conditions of this License, without any
> additional terms or conditions.

This is the standard Apache-2.0 inbound-equals-outbound model and
matches Falco, Tetragon, KubeArmor, bpfman, and other CNCF projects
in this category. There is no separate Contributor License Agreement
(CLA) to sign and no Developer Certificate of Origin (DCO) sign-off
requirement at this time.

If a contribution carries a different license (for example, code
imported from another open-source project), call it out in the PR
description and ensure the imported license is compatible with
Apache-2.0. The maintainer will determine whether the import requires
a `NOTICE` entry or a vendor-directory placement (e.g., `vendor/`
with a preserved license header).

## Development setup

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

## Pull request expectations

- One logical change per PR.
- Include tests for behavior changes.
- Update docs when user-visible behavior changes.
- Keep commit history clean (squash fixups before merge).
- For `release/*` PRs, use `security`, `critical`, or `release-approved` labels
  (feature labels are blocked by policy).

## Local quality checks

```bash
# formatting + static analysis
find src tests -name '*.cpp' -o -name '*.hpp' | xargs clang-format --dry-run --Werror
cppcheck --std=c++20 --enable=all --error-exitcode=1 --inline-suppr \
  --suppress=missingIncludeSystem --suppress=unmatchedSuppression \
  --suppress=syntaxError:tests/test_commands.cpp --suppress=syntaxError:tests/test_tracing.cpp \
  --suppress=checkersReport \
  -I src src/ tests/
BASE_REF=main scripts/run_clang_tidy_changed.sh
BASE_REF=main scripts/run_semgrep_changed.sh

# vendored dependency metadata check
scripts/check_vendored_dependencies.sh
```

## Security reporting

Do not open public issues for vulnerabilities.
Use private reporting as described in `SECURITY.md`.

## Code review checklist

### Security
- Validate all externally controlled input.
- Avoid introducing unnecessary privilege requirements.
- Log security-relevant operations with context.
- Use `constant_time_hex_compare()` for cryptographic comparisons (hashes, signatures).
- Handle parsing exceptions to prevent crashes on malformed input.
- Escape control characters in log output (use `json_escape()`).

### Correctness
- Cover error paths in tests.
- Preserve resource cleanup guarantees.
- Keep behavior deterministic and explicit.

### Performance
- Benchmark hot-path changes.
- Avoid avoidable allocations in critical paths.

### Maintainability
- Keep interfaces simple.
- Document non-obvious "why", not obvious "what".
