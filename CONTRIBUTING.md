# Contributing to AegisBPF

Thanks for contributing. Keep changes small, tested, and reviewable.

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
