# AegisBPF Multi-stage Dockerfile
# Build stage: compile the agent
# Runtime stage: minimal image with just the binary

# =============================================================================
# Build Stage
# =============================================================================
FROM ubuntu:24.04 AS builder

# Build argument: set to ON for zero-dependency static binary
ARG STATIC_LIBBPF=ON
ARG TARGETARCH
ARG BPFTOOL_VERSION=v7.7.0

# Install build dependencies
# Ubuntu 24.04 only provides bpftool through wrapper scripts. Use the official
# static bpftool release instead so Docker builds are deterministic across
# hosted-runner kernels and target architectures.
# When STATIC_LIBBPF=ON, libelf-dev is needed (libbpf builds from source)
# When STATIC_LIBBPF=OFF, libbpf-dev provides the shared library
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    libelf-dev \
    libsystemd-dev \
    pkg-config \
    cmake \
    ninja-build \
    make \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64|arm64) bpftool_arch="${TARGETARCH}" ;; \
        *) echo "Unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    bpftool_base="bpftool-${BPFTOOL_VERSION}-${bpftool_arch}.tar.gz"; \
    curl -fsSLo "/tmp/${bpftool_base}" \
        "https://github.com/libbpf/bpftool/releases/download/${BPFTOOL_VERSION}/${bpftool_base}"; \
    curl -fsSLo "/tmp/${bpftool_base}.sha256sum" \
        "https://github.com/libbpf/bpftool/releases/download/${BPFTOOL_VERSION}/${bpftool_base}.sha256sum"; \
    (cd /tmp && sha256sum -c "${bpftool_base}.sha256sum"); \
    tar -xzf "/tmp/${bpftool_base}" -C /usr/local/bin bpftool; \
    chmod +x /usr/local/bin/bpftool; \
    rm -f "/tmp/${bpftool_base}" "/tmp/${bpftool_base}.sha256sum"

WORKDIR /build

# Copy source files
COPY CMakeLists.txt ./
COPY cmake/ ./cmake/
COPY bpf/ ./bpf/
COPY src/ ./src/
COPY config/ ./config/
COPY packaging/ ./packaging/

# Build the agent
RUN cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=OFF \
    -DSTATIC_LIBBPF=${STATIC_LIBBPF} \
    && cmake --build build

# =============================================================================
# Runtime Stage
# =============================================================================
FROM ubuntu:24.04 AS runtime

# Install minimal runtime dependencies
# When built with STATIC_LIBBPF=ON (default), libbpf is statically linked
# and only libelf + zlib are needed at runtime (pulled in by libsystemd0).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1t64 \
    libsystemd0 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user (will still need capabilities)
RUN useradd -r -s /bin/false aegisbpf

# Create required directories
RUN mkdir -p /var/lib/aegisbpf /etc/aegisbpf \
    && chown aegisbpf:aegisbpf /var/lib/aegisbpf

# Copy binary and BPF object from builder
COPY --from=builder /build/build/aegisbpf /usr/bin/aegisbpf
COPY --from=builder /build/build/aegis.bpf.o /usr/lib/aegisbpf/aegis.bpf.o

# Copy example configuration
COPY --from=builder /build/config/policy.example /etc/aegisbpf/policy.example

# Set capabilities on the binary (requires --cap-add during build or runtime)
# These capabilities are required for BPF operations
# In production, use: docker run --cap-add=SYS_ADMIN --cap-add=BPF --cap-add=PERFMON
# Note: setcap doesn't work in Docker build, capabilities must be granted at runtime

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/bin/aegisbpf", "health"]

# Default command (can be overridden)
ENTRYPOINT ["/usr/bin/aegisbpf"]
CMD ["run", "--audit", "--log=stdout", "--log-format=json"]

# Metadata labels
LABEL org.opencontainers.image.title="AegisBPF"
LABEL org.opencontainers.image.description="eBPF-based runtime security agent"
LABEL org.opencontainers.image.vendor="AegisBPF"
LABEL org.opencontainers.image.source="https://github.com/aegisbpf/aegisbpf"
LABEL org.opencontainers.image.licenses="Apache-2.0"
