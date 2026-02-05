## What changed

<!-- Concisely describe behavior change and scope -->

## Why

<!-- Explain problem and design choice -->

## Validation

<!-- Include exact commands and key outputs -->
- [ ] `cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`
- [ ] `cmake --build build`
- [ ] `ctest --test-dir build --output-on-failure`
- [ ] `scripts/run_clang_tidy_changed.sh` (or CI equivalent)
- [ ] `scripts/run_semgrep_changed.sh` (or CI equivalent)

## Evidence links (required for release-impacting changes)

<!-- Paste direct links (actions/runs, artifacts, docs sections) -->
- CI run URL:
- Security/perf run URL (if applicable):
- Contract/evidence doc URL (if applicable):

## Market-leadership claim mapping (required for enforcement changes)

<!-- Keep claim discipline strict: ENFORCED/AUDITED/PLANNED + evidence -->
- Claim label (ENFORCED/AUDITED/PLANNED):
- Spec section:
- Test suite/contract:
- CI artifact URL:
- Runbook/operator guidance:

## Risk and rollback

<!-- Operational risk, migration impact, and rollback plan -->

## Checklist

### Security
- [ ] No new unsafe operation without justification
- [ ] Input validation added/kept for externally controlled data
- [ ] No secrets/credentials introduced
- [ ] Security-relevant actions are logged

### Correctness
- [ ] Error paths are covered by tests
- [ ] Resources are cleaned up (RAII / no leaks)
- [ ] Thread-safety assumptions are explicit
- [ ] BPF verifier compatibility considered for BPF changes

### Performance
- [ ] Hot paths reviewed for unnecessary allocations/loops
- [ ] Benchmarks run when behavior touches critical paths
- [ ] No benchmark regression >10% (or justified)

### Maintainability
- [ ] Public APIs/docs updated for behavior changes
- [ ] Complex logic includes concise "why" comments
- [ ] Magic numbers replaced with named constants where practical
