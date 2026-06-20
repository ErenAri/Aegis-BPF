# aegis-next multi-stage Dockerfile.
#
# Builds the full BPF stack (arena provenance + binary auth + sched_ext +
# self-protection + legacy fallback) and produces a minimal runtime image.
#
# Requirements:
#   - Build host with kernel >= 6.9 (for bpftool skeleton generation)
#   - clang-18+ and bpftool available
#
# Usage:
#   docker build -f prototype/aegis-next/Dockerfile -t aegisbpf-next .
#   docker run --privileged --pid=host --net=host aegisbpf-next

# =============================================================================
# Build Stage
# =============================================================================
FROM ubuntu:24.04@sha256:c4a8d5503dfb2a3eb8ab5f807da5bc69a85730fb49b5cfca2330194ebcc41c7b AS builder

ARG TARGETARCH
ARG BPFTOOL_VERSION=v7.7.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    pkg-config \
    cmake \
    ninja-build \
    make \
    curl \
    ca-certificates \
    libgtest-dev \
    && rm -rf /var/lib/apt/lists/*

# Install bpftool from official release (deterministic, no kernel dependency).
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
        amd64|arm64) bpftool_arch="${TARGETARCH:-amd64}" ;; \
        *) echo "Unsupported TARGETARCH" >&2; exit 1 ;; \
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

# Copy full source tree (CMakeLists.txt is at repo root).
COPY CMakeLists.txt ./
COPY cmake/ ./cmake/
COPY bpf/ ./bpf/
COPY src/ ./src/
COPY config/ ./config/
COPY prototype/aegis-next/ ./prototype/aegis-next/

# Configure: fetch libbpf (STATIC_LIBBPF) and set up build targets.
# SKIP_BPF_BUILD skips the mainline daemon's BPF objects; aegis-next
# compiles its own BPF programs independently.
RUN cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=OFF \
    -DBUILD_AEGIS_NEXT=ON \
    -DSTATIC_LIBBPF=ON \
    -DSKIP_BPF_BUILD=ON

# Provide vmlinux.h for BPF compilation.  Prefer host kernel BTF
# (available when building with --privileged on a 6.9+ host); fall
# back to the vmlinux.h bundled in the libbpf source tree that was
# just fetched by STATIC_LIBBPF above.
RUN if [ -f /sys/kernel/btf/vmlinux ]; then \
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > build/vmlinux.h; \
    else \
        cp build/_deps/libbpf_src-src/.github/actions/build-selftests/vmlinux.h \
           build/vmlinux.h; \
    fi

# Build aegis-next binary + BPF objects.
RUN cmake --build build --target aegisbpf-next

# =============================================================================
# Runtime Stage
# =============================================================================
FROM ubuntu:24.04@sha256:c4a8d5503dfb2a3eb8ab5f807da5bc69a85730fb49b5cfca2330194ebcc41c7b AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1t64 \
    zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Directories for policy, events, and BPF pin.
RUN mkdir -p /etc/aegisbpf /var/log/aegisbpf /sys/fs/bpf

# Copy binary.
COPY --from=builder /build/build/prototype/aegisbpf-next /usr/bin/aegisbpf-next

# Copy example rules.
COPY prototype/aegis-next/examples/ /etc/aegisbpf/examples/

# Copy systemd unit (useful when extracted from container).
COPY prototype/aegis-next/deploy/aegisbpf-next.service /usr/lib/systemd/system/

# Health check: verify BPF pin directory exists (programs loaded).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD test -d /sys/fs/bpf/aegis_next || exit 1

ENTRYPOINT ["/usr/bin/aegisbpf-next"]
CMD ["attach", "--events=/var/log/aegisbpf/events.jsonl"]

LABEL org.opencontainers.image.title="aegisbpf-next"
LABEL org.opencontainers.image.description="Next-gen BPF runtime security agent (arena + LSM + sched_ext)"
LABEL org.opencontainers.image.vendor="AegisBPF"
LABEL org.opencontainers.image.source="https://github.com/ErenAri/aegisbpf"
LABEL org.opencontainers.image.licenses="GPL-2.0"
