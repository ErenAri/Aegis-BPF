# ClusterFuzzLite / OSS-Fuzz build image for the AegisBPF userspace fuzzers.
# The userspace library (policy parser, event/JSON decoders, network rules,
# signed-bundle parser) is the attacker-influenced input boundary; BPF object
# compilation is skipped here (SKIP_BPF_BUILD=ON) since fuzzers target userspace.
FROM gcr.io/oss-fuzz-base/base-builder:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        ninja-build \
        pkg-config \
        libbpf-dev \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . $SRC/aegisbpf
WORKDIR $SRC/aegisbpf
COPY .clusterfuzzlite/build.sh $SRC/build.sh
