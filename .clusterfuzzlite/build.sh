#!/bin/bash -eu
#
# OSS-Fuzz / ClusterFuzzLite build script for AegisBPF userspace fuzzers.
#
# The fuzzing engine and sanitizer come from the OSS-Fuzz/CFLite environment
# ($CC/$CXX/$CFLAGS/$CXXFLAGS/$LIB_FUZZING_ENGINE). CMake honors $LIB_FUZZING_ENGINE
# (see the ENABLE_FUZZING block in CMakeLists.txt) and links it instead of the
# local-only -fsanitize=fuzzer,address. We do not set CMAKE_BUILD_TYPE so the
# injected $CXXFLAGS fully control optimization/instrumentation.

cd "$SRC/aegisbpf"

# Build and statically link a modern libbpf (the base image's system libbpf-dev
# is too old for clang++ -std=gnu++20). The source is pre-fetched in the
# Dockerfile so no network is needed here.
cmake -S . -B build-fuzz -G Ninja \
    -DENABLE_FUZZING=ON \
    -DBUILD_TESTING=OFF \
    -DSKIP_BPF_BUILD=ON \
    -DSTATIC_LIBBPF=ON \
    -DFETCHCONTENT_SOURCE_DIR_LIBBPF_SRC=/opt/libbpf-src

FUZZERS="fuzz_policy fuzz_bundle fuzz_network fuzz_path fuzz_event"
cmake --build build-fuzz --target ${FUZZERS}

for f in ${FUZZERS}; do
    cp "build-fuzz/${f}" "${OUT}/"
    # Ship checked-in seed corpora as <fuzzer>_seed_corpus.zip when present.
    if [ -d "tests/fuzz/corpus/${f}" ]; then
        (cd "tests/fuzz/corpus/${f}" && zip -q -r "${OUT}/${f}_seed_corpus.zip" .)
    fi
done
