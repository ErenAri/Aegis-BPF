// SPDX-License-Identifier: GPL-2.0
//
// Fuzz harness for aegis-next userspace components.
//
// Targets: FNV-1a hash, HT lookup, lineage walk, kind_name, digest_to_hex.
// Build:  clang++ -fsanitize=fuzzer,address -g -O1 \
//           -I../include -I../src fuzz_prov.cpp ../src/prov_walk.cpp \
//           -o fuzz_prov
// Run:    ./fuzz_prov -max_len=4096

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "aegis_next_prov.hpp"
#include "prov_walk.hpp"

using namespace aegis_next;

// Fuzz the FNV-1a hash with arbitrary input strings.
static void fuzz_fnv1a(const uint8_t* data, size_t size)
{
    if (size == 0) return;

    // Ensure null-terminated for fnv1a.
    std::string s(reinterpret_cast<const char*>(data), size);
    volatile uint32_t h = fnv1a(s.c_str(), s.size());
    (void)h;
}

// Fuzz the HT lookup with arbitrary key values.
static void fuzz_ht_lookup(const uint8_t* data, size_t size)
{
    if (size < 8) return;

    uint64_t key;
    std::memcpy(&key, data, 8);

    // Small table to keep fuzzing fast.
    std::vector<HtEntry> table(kHtBuckets, HtEntry{0, 0});

    // Populate a few entries from the fuzz input.
    size_t entries = (size - 8) / 16;
    for (size_t i = 0; i < entries && i < 32; ++i) {
        uint64_t k, v;
        std::memcpy(&k, data + 8 + i * 16, 8);
        std::memcpy(&v, data + 8 + i * 16 + 8, 8);
        uint32_t idx = ht_hash(k);
        for (int j = 0; j < kHtMaxProbe; ++j) {
            uint32_t probe = (idx + j) & (kHtBuckets - 1);
            if (table[probe].key == 0) {
                table[probe].key = k;
                table[probe].value = v;
                break;
            }
        }
    }

    volatile uint64_t result = ht_lookup(table.data(), key);
    (void)result;
}

// Fuzz the lineage walker with a synthetic arena.
static void fuzz_lineage_walk(const uint8_t* data, size_t size)
{
    if (size < sizeof(ProvNode)) return;

    size_t num_nodes = size / sizeof(ProvNode);
    if (num_nodes > 256) num_nodes = 256;

    std::vector<ProvNode> nodes(num_nodes);
    std::memcpy(nodes.data(), data, num_nodes * sizeof(ProvNode));

    // Clamp prev_index values to avoid OOB.
    for (auto& n : nodes) {
        if (n.prev_index != kRootSentinel)
            n.prev_index %= num_nodes;
    }

    auto reader = [&](uint64_t s) -> ProvNode { return nodes[s % num_nodes]; };

    volatile size_t visited = walk_lineage(
        0, num_nodes, reader,
        [](const LineageEntry&) {},
        0);
    (void)visited;
}

// Fuzz kind_name and digest_to_hex.
static void fuzz_helpers(const uint8_t* data, size_t size)
{
    if (size == 0) return;

    volatile const char* kn = kind_name(data[0]);
    (void)kn;

    volatile const char* av = auth_verdict_name(data[0]);
    (void)av;

    if (size >= 2) {
        std::string hex = digest_to_hex(data, std::min(size, size_t(64)));
        (void)hex;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0) return 0;

    // Use first byte to select which target to fuzz.
    uint8_t selector = data[0] % 4;
    data++;
    size--;

    switch (selector) {
    case 0: fuzz_fnv1a(data, size); break;
    case 1: fuzz_ht_lookup(data, size); break;
    case 2: fuzz_lineage_walk(data, size); break;
    case 3: fuzz_helpers(data, size); break;
    }

    return 0;
}
