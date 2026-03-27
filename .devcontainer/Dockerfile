# AegisBPF Development Container
#
# Provides a complete build environment for AegisBPF development:
# - Clang/LLVM toolchain for BPF compilation
# - libbpf, libelf, zlib for BPF operations
# - CMake + Ninja build system
# - GTest for unit testing
# - bpftool for BPF program inspection
# - Python 3 for integration scripts
#
# Usage:
#   VS Code: Open in Dev Container (F1 → "Dev Containers: Reopen in Container")
#   GitHub Codespaces: Click "Code" → "Codespaces" → "Create codespace"
#   Manual: docker build -t aegisbpf-dev .devcontainer/ && docker run -it aegisbpf-dev

FROM mcr.microsoft.com/devcontainers/cpp:1-ubuntu-24.04

# Avoid interactive prompts during package install
ENV DEBIAN_FRONTEND=noninteractive

# Install AegisBPF build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # BPF toolchain
    clang \
    llvm \
    libbpf-dev \
    libelf-dev \
    # Build system
    cmake \
    ninja-build \
    pkg-config \
    # Runtime dependencies
    zlib1g-dev \
    libsystemd-dev \
    # Testing
    libgtest-dev \
    libgmock-dev \
    python3-jsonschema \
    # BPF tools
    linux-tools-common \
    bpftool \
    # Utilities
    jq \
    curl \
    git \
    # Kernel headers (for BPF compilation when not using SKIP_BPF_BUILD)
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages for integration testing
RUN pip3 install --no-cache-dir \
    requests \
    opentelemetry-api \
    opentelemetry-sdk \
    opentelemetry-exporter-otlp-proto-grpc \
    jsonschema

# Set up convenient aliases
RUN echo 'alias build="cmake --build build"' >> /etc/bash.bashrc && \
    echo 'alias test="ctest --test-dir build --output-on-failure"' >> /etc/bash.bashrc && \
    echo 'alias configure="cmake -S . -B build -G Ninja -DSKIP_BPF_BUILD=ON -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON"' >> /etc/bash.bashrc

# Pre-create build directory
RUN mkdir -p /workspaces/aegisbpf/build

WORKDIR /workspaces/aegisbpf
