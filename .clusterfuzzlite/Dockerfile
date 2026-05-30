# ClusterFuzzLite / OSS-Fuzz build image for the AegisBPF userspace fuzzers.
# The userspace library (policy parser, event/JSON decoders, network rules,
# signed-bundle parser) is the attacker-influenced input boundary; BPF object
# compilation is skipped here (SKIP_BPF_BUILD=ON) since fuzzers target userspace.
FROM gcr.io/oss-fuzz-base/base-builder:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        ninja-build \
        pkg-config \
        zlib1g-dev \
        libelf-dev \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The base image's system libbpf-dev is too old: its <bpf/bpf.h> uses a forward
# enum reference that clang++ rejects under -std=gnu++20 ("ISO C++ forbids
# forward references to 'enum' types"). Pre-fetch the libbpf source the project
# pins for static builds; build.sh builds and statically links it (via
# -DSTATIC_LIBBPF=ON + FETCHCONTENT_SOURCE_DIR_LIBBPF_SRC) so the fuzzers get a
# modern, C++-clean, self-contained libbpf with no compile-step network needed.
ARG LIBBPF_VERSION=1.6.1
RUN git clone --depth 1 --branch "v${LIBBPF_VERSION}" \
        https://github.com/libbpf/libbpf /opt/libbpf-src

COPY . $SRC/aegisbpf
WORKDIR $SRC/aegisbpf
COPY .clusterfuzzlite/build.sh $SRC/build.sh
