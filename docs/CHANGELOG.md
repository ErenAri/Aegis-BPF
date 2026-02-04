# Changelog

All notable changes to AegisBPF will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Result<T> error handling throughout the codebase
- Constant-time hash comparison (`constant_time_hex_compare()`) to prevent timing side-channel attacks
- Structured logging with text and JSON output formats
- `--log-level` and `--log-format` CLI options
- `--seccomp` flag for runtime syscall filtering
- Thread-safe caching for cgroup and path resolution
- RAII wrappers for popen (PipeGuard) and ring_buffer (RingBufferGuard)
- Input validation for CLI path arguments
- Google Test unit tests for core components
- Google Benchmark performance tests
- Sanitizer builds (ASAN, UBSAN, TSAN)
- Code coverage reporting with gcovr and Codecov
- Comprehensive CI pipeline with test, sanitizer, and coverage jobs
- AppArmor profile for runtime confinement
- SELinux policy module
- Sigstore/Cosign code signing for releases
- SBOM generation (SPDX and CycloneDX)
- Prometheus alert rules
- Grafana dashboard
- JSON Schema for event validation
- Event schema validation tests and sample payloads
- SIEM integration documentation
- Dockerfile for containerized deployment
- Helm chart for Kubernetes deployment
- Architecture documentation
- Troubleshooting guide
- Man page
- Dev check and environment verification scripts
- Enforce-mode smoke test script
- Nightly fuzz workflow, perf regression workflow, and kernel matrix workflow

### Changed
- All functions now return Result<T> instead of int/bool
- Replaced std::cerr/std::cout with structured logging
- Improved error messages with context
- Event schema aligned with emitted JSON fields
- README/architecture diagrams updated to file-open enforcement

### Fixed
- popen() file descriptor leak in kernel config check
- Race conditions in cgroup path cache
- Race conditions in CWD resolution cache
- Thread-safety issue in journal error reporting

### Security
- Added seccomp-bpf syscall filter
- Added AppArmor and SELinux policies
- Added input validation for all user-provided paths
- Added constant-time comparison for all hash verification (BPF integrity, policy SHA256, bundle verification)
- Disabled `AEGIS_SKIP_BPF_VERIFY` bypass in Release builds (only available in Debug builds)
- Added try-catch exception handling in signed bundle parser to prevent crashes on malformed input
- Extended `json_escape()` to handle all control characters, preventing JSON injection in logs

## [0.1.0] - 2024-01-01

### Added
- Initial release
- BPF LSM-based execution blocking
- Tracepoint-based audit mode (fallback)
- Policy file support with deny_path, deny_inode, allow_cgroup sections
- SHA256 hash-based blocking
- Prometheus metrics endpoint
- Journald integration
- CLI commands: run, block, allow, policy, stats, metrics, health

[Unreleased]: https://github.com/aegisbpf/aegisbpf/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/aegisbpf/aegisbpf/releases/tag/v0.1.0
