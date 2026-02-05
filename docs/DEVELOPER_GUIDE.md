# AegisBPF Developer Guide

This guide covers development setup, code organization, contribution workflow, and extension patterns for AegisBPF.

## Table of Contents

- [Development Environment Setup](#development-environment-setup)
- [Build System](#build-system)
- [Code Organization](#code-organization)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Adding New Features](#adding-new-features)
- [BPF Development](#bpf-development)
- [Debugging](#debugging)
- [Performance Profiling](#performance-profiling)
- [Release Process](#release-process)

---

## Development Environment Setup

### Prerequisites

**Required:**
- Linux kernel 5.8+ with BTF support
- GCC 10+ or Clang 12+ (C++20 support)
- CMake 3.20+
- Ninja build system
- libbpf development headers
- bpftool
- Python 3.8+ (for test scripts)

**Optional:**
- libsystemd-dev (for journald integration)
- Docker (for containerized builds)
- lcov (for coverage reports)

### Ubuntu/Debian Setup

```bash
# Install build dependencies
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    clang \
    llvm \
    cmake \
    ninja-build \
    pkg-config \
    libbpf-dev \
    bpftool \
    libsystemd-dev \
    python3 \
    python3-jsonschema \
    lcov

# Verify kernel requirements
uname -r  # Should be 5.8+
cat /sys/kernel/btf/vmlinux | head -c 4  # Should show BTF header

# Verify BPF LSM (for enforce mode development)
cat /sys/kernel/security/lsm | grep bpf
```

### Fedora/RHEL Setup

```bash
sudo dnf install -y \
    clang \
    llvm \
    cmake \
    ninja-build \
    libbpf-devel \
    bpftool \
    systemd-devel \
    python3 \
    python3-jsonschema
```

### Clone and Build

```bash
git clone https://github.com/your-org/aegisbpf.git
cd aegisbpf

# Configure (Debug build with sanitizers)
cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DENABLE_ASAN=ON \
    -DENABLE_UBSAN=ON

# Build
cmake --build build

# Run tests
cd build && ctest --output-on-failure
```

---

## Build System

### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `CMAKE_BUILD_TYPE` | Debug | Build type: Debug, Release, RelWithDebInfo |
| `BUILD_TESTING` | ON | Build test targets |
| `ENABLE_ASAN` | OFF | Enable AddressSanitizer |
| `ENABLE_UBSAN` | OFF | Enable UndefinedBehaviorSanitizer |
| `ENABLE_TSAN` | OFF | Enable ThreadSanitizer |
| `ENABLE_COVERAGE` | OFF | Enable code coverage |
| `ENABLE_FUZZING` | OFF | Build fuzzing targets |
| `SKIP_BPF_BUILD` | OFF | Skip BPF compilation (cross-compile) |

### Build Configurations

```bash
# Debug build (development)
cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug

# Release build (production)
cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release

# Coverage build
cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DENABLE_COVERAGE=ON

# Fuzzing build (requires clang)
CC=clang CXX=clang++ cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DENABLE_FUZZING=ON
```

### Build Targets

```bash
# Main binary
cmake --build build --target aegisbpf

# Static library (for testing)
cmake --build build --target aegisbpf_lib

# Unit tests
cmake --build build --target aegisbpf_test

# E2E tests (require root)
cmake --build build --target aegisbpf_bypass_test

# Benchmarks
cmake --build build --target aegisbpf_bench

# Fuzzing targets
cmake --build build --target fuzz_policy fuzz_bundle fuzz_network
```

---

## Code Organization

### Directory Structure

```
aegisbpf/
+-- bpf/                    # BPF kernel code
|   +-- aegis.bpf.c         # Main BPF program
+-- src/                    # User-space C++ code
|   +-- main.cpp            # Entry point
|   +-- cli_*.cpp/hpp       # CLI command handlers
|   +-- commands_*.cpp/hpp  # Command implementations
|   +-- daemon.cpp/hpp      # Main daemon loop
|   +-- bpf_ops.cpp/hpp     # BPF operations
|   +-- policy.cpp/hpp      # Policy management
|   +-- network_ops.cpp/hpp # Network rule handling
|   +-- crypto.cpp/hpp      # Ed25519 signing
|   +-- events.cpp/hpp      # Event handling
|   +-- seccomp.cpp/hpp     # Seccomp filter
|   +-- sha256.cpp/hpp      # SHA256 implementation
|   +-- tweetnacl.c/h       # TweetNaCl crypto library
|   +-- utils.cpp/hpp       # Utility functions
|   +-- types.hpp           # Data structures
|   +-- result.hpp          # Error handling
|   +-- logging.hpp         # Logging infrastructure
+-- tests/                  # Test code
|   +-- test_*.cpp          # Unit tests
|   +-- e2e/                # End-to-end tests
|   +-- fuzz/               # Fuzzing harnesses
|   +-- fixtures/           # Test data
+-- docs/                   # Documentation
+-- config/                 # Configuration templates
+-- packaging/              # Systemd, AppArmor, SELinux
+-- scripts/                # Development and CI scripts
+-- helm/                   # Kubernetes Helm chart
+-- .github/workflows/      # CI/CD pipelines
```

### Source File Conventions

| Pattern | Purpose |
|---------|---------|
| `cli_*.cpp` | CLI argument parsing and validation |
| `commands_*.cpp` | Business logic for CLI commands |
| `*_ops.cpp` | Low-level operations (BPF, network) |
| `*.hpp` | Header files (declarations) |
| `test_*.cpp` | Unit test files |
| `fuzz_*.cpp` | Fuzzing harnesses |

### Header Dependencies

```
types.hpp         # Base types (no dependencies)
    +-- result.hpp    # Error handling (types.hpp)
        +-- logging.hpp   # Logging (result.hpp)
            +-- bpf_ops.hpp   # BPF operations
            +-- policy.hpp    # Policy management
            +-- crypto.hpp    # Cryptography
            +-- ...
```

---

## Coding Standards

### C++ Style

- **Standard:** C++20
- **Naming:**
  - Classes/Structs: `PascalCase`
  - Functions/Methods: `snake_case`
  - Variables: `snake_case`
  - Constants: `kCamelCase` or `SCREAMING_SNAKE_CASE`
  - Private members: `member_name_`
- **Formatting:** Use clang-format with project `.clang-format`

### Static Analysis

Run static analysis locally before opening a PR:

```bash
# clang-format
find src tests -name '*.cpp' -o -name '*.hpp' | xargs clang-format --dry-run --Werror

# cppcheck
cppcheck --std=c++20 --enable=all --error-exitcode=1 --inline-suppr \
  --suppress=missingIncludeSystem \
  --suppress=unmatchedSuppression \
  --suppress=syntaxError:tests/test_commands.cpp \
  --suppress=syntaxError:tests/test_tracing.cpp \
  --suppress=checkersReport \
  -I src \
  src/ tests/

# clang-tidy (changed C++ files only)
cmake -S . -B build-clang-tidy -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON -DSKIP_BPF_BUILD=ON
BASE_REF=main BUILD_DIR=build-clang-tidy scripts/run_clang_tidy_changed.sh

# semgrep (changed files only)
BASE_REF=main scripts/run_semgrep_changed.sh

# vendored dependency metadata/audit (TweetNaCl)
scripts/check_vendored_dependencies.sh

# required status-check definitions map to workflow job contexts
python3 scripts/validate_required_checks.py \
  --required config/required_checks.txt \
  --required config/required_checks_release.txt

# labels referenced by workflows/templates are defined in repo_labels.json
python3 scripts/validate_label_contract.py
```

### Error Handling

Always use `Result<T>` for functions that can fail:

```cpp
// Good: Explicit error handling
Result<InodeId> path_to_inode(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return Error::system(errno, "stat failed for " + path);
    }
    InodeId id{};
    id.ino = st.st_ino;
    id.dev = encode_dev(st.st_dev);
    return id;
}

// Usage with TRY macro
Result<void> add_block_rule(const std::string& path) {
    auto inode = TRY(path_to_inode(path));
    TRY(add_to_map(inode));
    return {};
}
```

### Logging

Use structured logging:

```cpp
// Good: Structured fields
logger().log(SLOG_INFO("Policy applied")
    .field("path", path)
    .field("rules", static_cast<int64_t>(count)));

// Good: Error with context
logger().log(SLOG_ERROR("BPF load failed")
    .field("path", obj_path)
    .field("errno", errno)
    .error_code(err));

// Bad: Unstructured message
logger().log(SLOG_INFO("Policy " + path + " applied with " + std::to_string(count) + " rules"));
```

For policy lifecycle troubleshooting, you can enable OpenTelemetry-style span
logs (start/end with duration and status):

```bash
AEGIS_OTEL_SPANS=1 ./build/aegisbpf policy apply config/policy.example
```

Span hierarchy is carried through thread-local trace/span context so nested
operations can be correlated in logs:

- CLI spans: `cli.policy_*`, `cli.network_*`, `cli.block_*`, `cli.metrics`, `cli.health`
- Daemon spans: `daemon.run`, `daemon.load_bpf`, `daemon.attach_programs`, `daemon.event_loop`
- BPF spans: `bpf.load`, `bpf.pin_maps`, `bpf.attach_all`

Each span emits:
- `otel_span_start` with `trace_id`, `span_id`, optional `parent_span_id`
- `otel_span_end` with `duration_ms` and `status` (`ok` or `error`)

### Memory Safety

- Use RAII for all resources
- Prefer `std::string`, `std::vector` over raw buffers
- Use `std::unique_ptr` for owned heap allocations
- Never use `new`/`delete` directly

```cpp
// Good: RAII wrapper
class RingBufferGuard {
    ring_buffer* rb_;
public:
    explicit RingBufferGuard(ring_buffer* rb) : rb_(rb) {}
    ~RingBufferGuard() { if (rb_) ring_buffer__free(rb_); }
    ring_buffer* get() { return rb_; }
};

// Usage
RingBufferGuard rb(ring_buffer__new(fd, callback, nullptr, nullptr));
if (!rb) return Error(...);
```

---

## Testing

### Unit Tests

Located in `tests/test_*.cpp`. Uses Google Test framework.

```cpp
#include <gtest/gtest.h>
#include "policy.hpp"

TEST(PolicyTest, ParseValidPolicy) {
    PolicyIssues issues;
    auto result = parse_policy_file("tests/fixtures/valid.conf", issues);

    ASSERT_TRUE(result.ok());
    EXPECT_EQ(result->version, 1);
    EXPECT_EQ(result->deny_paths.size(), 2);
    EXPECT_TRUE(issues.errors.empty());
}

TEST(PolicyTest, RejectInvalidVersion) {
    PolicyIssues issues;
    auto result = parse_policy_file("tests/fixtures/bad_version.conf", issues);

    EXPECT_FALSE(result.ok());
    EXPECT_FALSE(issues.errors.empty());
}
```

Run tests:

```bash
cd build
ctest --output-on-failure

# Run specific test
./aegisbpf_test --gtest_filter="PolicyTest.*"

# Run with verbose output
./aegisbpf_test --gtest_filter="*" --gtest_print_time=1
```

### E2E Tests

Require root privileges and real BPF:

```bash
sudo ./build/aegisbpf_bypass_test
```

### Fuzzing

Build and run fuzzers:

```bash
# Build
CC=clang CXX=clang++ cmake -S . -B build -G Ninja -DENABLE_FUZZING=ON
cmake --build build --target fuzz_policy

# Run fuzzer
mkdir -p corpus/policy
./build/fuzz_policy corpus/policy -max_total_time=60
```

### Coverage

Generate coverage report:

```bash
cmake -S . -B build -G Ninja -DENABLE_COVERAGE=ON
cmake --build build
cd build && ctest
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage_report
```

---

## Adding New Features

### Adding a New CLI Command

1. **Create command handler** in `src/commands_*.cpp`:

```cpp
// src/commands_myfeature.cpp
#include "commands_myfeature.hpp"
#include "bpf_ops.hpp"
#include "logging.hpp"

namespace aegis {

int cmd_myfeature_do(const std::string& arg) {
    TRY(bump_memlock_rlimit());

    BpfState state;
    TRY(load_bpf(true, false, state));

    // Implementation...

    logger().log(SLOG_INFO("Feature executed").field("arg", arg));
    return 0;
}

}  // namespace aegis
```

2. **Add CLI parser** in `src/cli_myfeature.cpp`:

```cpp
// src/cli_myfeature.cpp
#include "cli_myfeature.hpp"
#include "commands_myfeature.hpp"

namespace aegis {

int cli_myfeature(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: aegisbpf myfeature <arg>\n";
        return 1;
    }
    return cmd_myfeature_do(argv[1]);
}

}  // namespace aegis
```

3. **Register in dispatcher** (`src/cli_dispatch.cpp`):

```cpp
// Add to dispatch table
{"myfeature", cli_myfeature},
```

4. **Add to CMakeLists.txt**:

```cmake
set(AEGIS_SOURCES
    ...
    src/cli_myfeature.cpp
    src/commands_myfeature.cpp
)
```

5. **Write tests** in `tests/test_myfeature.cpp`

### Adding a New BPF Map

1. **Define in BPF code** (`bpf/aegis.bpf.c`):

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} my_new_map SEC(".maps");
```

2. **Add pin path** (`src/types.hpp`):

```cpp
inline constexpr const char* kMyNewMapPin = "/sys/fs/bpf/aegisbpf/my_new_map";
```

3. **Add to BpfState** (`src/bpf_ops.hpp`):

```cpp
struct BpfState {
    // ...
    bpf_map* my_new_map = nullptr;
    bool my_new_map_reused = false;
};
```

4. **Load and pin** in `load_bpf()`:

```cpp
state.my_new_map = bpf_object__find_map_by_name(state.obj, "my_new_map");
// Add to reuse and pin logic...
```

---

## BPF Development

### BPF Code Structure

```c
// bpf/aegis.bpf.c

// 1. Include headers
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// 2. Define types and constants
struct my_event { ... };

// 3. Define maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    ...
} my_map SEC(".maps");

// 4. Helper functions (static __always_inline)
static __always_inline int helper_func(...) { ... }

// 5. BPF programs with SEC() annotations
SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file) {
    ...
}

// 6. License
char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

### BPF Program Types

| SEC() | Hook | Can Block |
|-------|------|-----------|
| `lsm/file_open` | File open | Yes |
| `lsm/inode_permission` | Inode access | Yes |
| `lsm/socket_connect` | Outgoing connect | Yes |
| `lsm/socket_bind` | Socket bind | Yes |
| `tracepoint/syscalls/sys_enter_openat` | openat syscall | No (audit) |
| `tracepoint/sched/sched_process_exec` | Process exec | No (audit) |

### BPF Debugging

```bash
# View loaded programs
sudo bpftool prog list

# View program details
sudo bpftool prog show id <id>

# Dump program instructions
sudo bpftool prog dump xlated id <id>

# View maps
sudo bpftool map list
sudo bpftool map dump name deny_inode_map

# View pinned objects
ls -la /sys/fs/bpf/aegisbpf/
```

---

## Debugging

### Debug Build

```bash
cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DENABLE_ASAN=ON \
    -DENABLE_UBSAN=ON
```

### GDB Debugging

```bash
# Run under GDB
sudo gdb --args ./build/aegisbpf run --audit

# In GDB:
(gdb) break daemon_run
(gdb) run
(gdb) bt  # backtrace on crash
```

### Sanitizer Output

```bash
# ASAN will report memory errors
ASAN_OPTIONS=detect_leaks=1 sudo ./build/aegisbpf run --audit

# UBSAN reports undefined behavior
UBSAN_OPTIONS=print_stacktrace=1 sudo ./build/aegisbpf run --audit
```

### Logging Verbosity

```bash
# JSON output shows all structured fields
sudo ./build/aegisbpf run --audit --log-format=json 2>&1 | jq .
```

---

## Performance Profiling

### Using perf

```bash
# Record profile
sudo perf record -g ./build/aegisbpf run --audit &
# ... generate workload ...
sudo perf report

# Flame graph
sudo perf script | stackcollapse-perf.pl | flamegraph.pl > flame.svg
```

### Benchmarking

```bash
# Run policy parsing benchmark
./build/aegisbpf_bench --benchmark_filter="BM_Policy*"

# File open latency test
ITERATIONS=1000000 FILE=/etc/hosts scripts/perf_open_bench.sh

# Compare baseline vs. with agent
scripts/perf_compare.sh
```

---

## Release Process

### Pre-release Checklist

1. Run all tests:
   ```bash
   scripts/dev_check.sh
   ```

2. Update version in `CMakeLists.txt`

3. Update `docs/CHANGELOG.md`

4. Run release drill:
   ```bash
   gh workflow run release-drill.yml
   ```

5. Check production readiness:
   ```bash
   gh workflow run release-readiness.yml
   ```

### Creating a Release

```bash
# Tag the release
git tag -s v0.2.0 -m "Release v0.2.0"
git push origin v0.2.0

# GitHub Actions will:
# 1. Build for all architectures
# 2. Sign with Sigstore
# 3. Generate SBOM
# 4. Create GitHub Release
```

### Versioning

- **Major:** Breaking API/policy format changes
- **Minor:** New features, backward compatible
- **Patch:** Bug fixes only

---

## Resources

- [eBPF.io](https://ebpf.io/) - eBPF documentation
- [libbpf Documentation](https://libbpf.readthedocs.io/)
- [BPF CO-RE Guide](https://nakryiko.com/posts/bpf-portability-and-co-re/)
- [Linux BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html)

---

## See Also

- [API_REFERENCE.md](API_REFERENCE.md) - API documentation
- [ARCHITECTURE.md](ARCHITECTURE.md) - System design
- [THREAT_MODEL.md](THREAT_MODEL.md) - Security scope and blind spots
- [POLICY_SEMANTICS.md](POLICY_SEMANTICS.md) - Runtime policy behavior
- [QUALITY_GATES.md](QUALITY_GATES.md) - CI gate policy and coverage expectations
- [CI_EXECUTION_STRATEGY.md](CI_EXECUTION_STRATEGY.md) - Privileged CI execution model
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues
- [VENDORED_DEPENDENCIES.md](VENDORED_DEPENDENCIES.md) - Vendored dependency tracking
