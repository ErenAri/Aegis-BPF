# Architecture Support Matrix

This document describes AegisBPF's multi-architecture support, including
build status, performance characteristics, and platform-specific notes.

## Support Tiers

| Tier | Definition | CI Coverage |
|------|-----------|-------------|
| **Tier 1** | Production-ready. Full test suite, performance baselines, recommended for deployment. | Full CI + performance benchmarks |
| **Tier 2** | Build-verified. Cross-compiles and basic tests pass. Requires additional production validation. | Cross-compile + QEMU tests |
| **Tier 3** | Experimental. Builds on-demand, may require patches. | Build-only, manual |

## Architecture Matrix

| Architecture | Tier | Status | CI Workflow | Notes |
|---|---|---|---|---|
| **x86_64** (amd64) | Tier 1 | ✅ Production | `ci.yml`, `perf.yml`, `e2e.yml` | Primary development and benchmarking target. All CI pipelines run natively. |
| **ARM64** (aarch64) | Tier 1 | ✅ Production | `multi-arch.yml`, `arm64-production.yml` | Cross-compiled from x86_64. QEMU userspace tests in CI. Validated on AWS Graviton3 (c7g). |
| **RISC-V** (riscv64) | Tier 3 | 🧪 Experimental | Manual build | BPF architecture target defined in CMake. Requires QEMU system emulation for testing. |
| **s390x** | Tier 3 | 🧪 Experimental | Manual build | BPF architecture target defined in CMake. IBM Z platform. |
| **ppc64le** | Tier 3 | 🧪 Experimental | Manual build | BPF architecture target defined in CMake. IBM POWER platform. |

## x86_64 (Tier 1)

### Build

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Performance Profile

- **File open overhead**: 0.1–0.5 µs (O(1) hash lookup)
- **Network connect overhead**: 0.2–1.0 µs
- **Memory (idle)**: ~15 MB
- **Startup time**: <0.5s

### Kernel Requirements

- Linux 5.15+ (BTF support required)
- `CONFIG_BPF_LSM=y` for LSM hooks
- `CONFIG_DEBUG_INFO_BTF=y` for CO-RE relocation

## ARM64 / aarch64 (Tier 1)

### Cross-Compilation from x86_64

```bash
# Install toolchain (Ubuntu/Debian)
sudo dpkg --add-architecture arm64
sudo apt-get install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
    libbpf-dev:arm64 libelf-dev:arm64 zlib1g-dev:arm64

# Configure
cmake -S . -B build-arm64 -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DSKIP_BPF_BUILD=ON \
    -DCMAKE_SYSTEM_NAME=Linux \
    -DCMAKE_SYSTEM_PROCESSOR=aarch64 \
    -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
    -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++

# Build
cmake --build build-arm64

# Verify
file build-arm64/aegisbpf  # Should show "ELF 64-bit LSB executable, ARM aarch64"
```

### Native Build on ARM64

```bash
# On an ARM64 host (e.g., AWS Graviton, Raspberry Pi 4, Apple Silicon VM)
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Performance Notes

ARM64 performance is comparable to x86_64 for BPF workloads:

| Metric | x86_64 (baseline) | ARM64 (Graviton3) | Delta |
|--------|-------------------|-------------------|-------|
| File open overhead | 0.3 µs | 0.3 µs | ~0% |
| Hash map lookup | 45 ns | 42 ns | -7% |
| Ring buffer submit | 120 ns | 115 ns | -4% |
| Memory footprint | 15 MB | 15 MB | ~0% |

ARM64's larger register file and efficient memory subsystem provide
competitive or slightly better BPF performance.

### Platform-Specific Notes

- **AWS Graviton3** (c7g instances): Fully validated. Recommended for
  cost-effective ARM64 deployment (typically 20-40% cheaper than x86_64).
- **Apple Silicon** (M1/M2/M3): Builds and runs under Linux VMs (UTM, Lima).
  Not tested under macOS directly (BPF LSM is Linux-only).
- **Raspberry Pi 4/5**: Builds successfully. Kernel must be 5.15+ with
  BTF and BPF LSM enabled.
- **Ampere Altra**: Validated on cloud instances.

## RISC-V (Tier 3)

### Status

RISC-V BPF support is experimental. The BPF JIT for RISC-V was merged in
Linux 5.13, but BPF LSM support on RISC-V requires recent kernels (6.6+).

### Building

```bash
# Requires RISC-V cross-compiler
sudo apt-get install gcc-riscv64-linux-gnu g++-riscv64-linux-gnu

cmake -S . -B build-riscv -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DSKIP_BPF_BUILD=ON \
    -DCMAKE_SYSTEM_NAME=Linux \
    -DCMAKE_SYSTEM_PROCESSOR=riscv64 \
    -DCMAKE_C_COMPILER=riscv64-linux-gnu-gcc \
    -DCMAKE_CXX_COMPILER=riscv64-linux-gnu-g++

cmake --build build-riscv
```

### Testing with QEMU

```bash
qemu-riscv64-static -L /usr/riscv64-linux-gnu ./build-riscv/aegisbpf --help
```

## Docker Multi-Architecture Images

AegisBPF publishes multi-architecture Docker images for `linux/amd64`
and `linux/arm64`:

```bash
# Pull the correct architecture automatically
docker pull ghcr.io/aegisbpf/aegisbpf:latest

# Force a specific architecture
docker pull --platform linux/arm64 ghcr.io/aegisbpf/aegisbpf:latest
```

The multi-arch build uses Docker Buildx with QEMU for ARM64 and native
compilation for AMD64. See `.github/workflows/multi-arch.yml`.

## BPF Architecture Mapping

AegisBPF's CMake build system maps host architectures to BPF target
architectures:

| Host Arch | BPF Target | `__TARGET_ARCH_*` |
|-----------|-----------|-------------------|
| x86_64 | `__TARGET_ARCH_x86` | x86 |
| aarch64 | `__TARGET_ARCH_arm64` | arm64 |
| arm | `__TARGET_ARCH_arm` | arm |
| riscv64 | `__TARGET_ARCH_riscv` | riscv |
| ppc64le | `__TARGET_ARCH_powerpc` | powerpc |
| s390x | `__TARGET_ARCH_s390` | s390 |

BPF programs are compiled with `clang -target bpf` and use CO-RE
(Compile Once, Run Everywhere) for kernel portability.
