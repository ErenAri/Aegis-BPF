// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file missingInclude
// cppcheck-suppress-file unknownMacro
#include <benchmark/benchmark.h>
#include <arpa/inet.h>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <sys/sysmacros.h>
#include "network_ops.hpp"
#include "policy.hpp"
#include "sha256.hpp"
#include "utils.hpp"

namespace aegis {
namespace {

class PolicyBenchmark : public benchmark::Fixture {
  public:
    void SetUp(const benchmark::State&) override
    {
        test_dir_ = std::filesystem::temp_directory_path() / "aegisbpf_bench";
        std::filesystem::create_directories(test_dir_);

        // Create a sample policy file
        policy_path_ = test_dir_ / "policy.conf";
        std::ofstream out(policy_path_);
        out << "version=1\n\n[deny_path]\n";
        for (int i = 0; i < 100; i++) {
            out << "/usr/bin/test" << i << "\n";
        }
        out << "\n[allow_cgroup]\n";
        for (int i = 0; i < 50; i++) {
            out << "/sys/fs/cgroup/test" << i << "\n";
        }
    }

    void TearDown(const benchmark::State&) override
    {
        std::filesystem::remove_all(test_dir_);
    }

    std::filesystem::path test_dir_;
    std::string policy_path_;
};

BENCHMARK_DEFINE_F(PolicyBenchmark, ParsePolicy)
(benchmark::State& state)
{
    for (auto _ : state) {
        PolicyIssues issues;
        auto result = parse_policy_file(policy_path_, issues);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK_REGISTER_F(PolicyBenchmark, ParsePolicy);

static void BM_Sha256Short(benchmark::State& state)
{
    std::string input = "hello world";
    for (auto _ : state) {
        std::string hash = Sha256::hash_hex(input);
        benchmark::DoNotOptimize(hash);
    }
    state.SetBytesProcessed(state.iterations() * input.size());
}
BENCHMARK(BM_Sha256Short);

static void BM_Sha256Long(benchmark::State& state)
{
    std::string input(state.range(0), 'x');
    for (auto _ : state) {
        std::string hash = Sha256::hash_hex(input);
        benchmark::DoNotOptimize(hash);
    }
    state.SetBytesProcessed(state.iterations() * input.size());
}
BENCHMARK(BM_Sha256Long)->Range(64, 1 << 20);

static void BM_Trim(benchmark::State& state)
{
    std::string input = "   hello world   ";
    for (auto _ : state) {
        std::string result = trim(input);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Trim);

static void BM_JsonEscape(benchmark::State& state)
{
    std::string input = R"(path\to\"file")";
    for (auto _ : state) {
        std::string result = json_escape(input);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_JsonEscape);

static void BM_ParseInodeId(benchmark::State& state)
{
    std::string input = "259:12345678901234";
    for (auto _ : state) {
        InodeId id;
        bool result = parse_inode_id(input, id);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(id);
    }
}
BENCHMARK(BM_ParseInodeId);

// ============================================================================
// BPF-Specific Benchmarks
// These test userspace hot paths that interact with BPF maps
// ============================================================================

// InodeIdHash - Critical for deny_inode_map lookups
static void BM_InodeIdHash(benchmark::State& state)
{
    InodeIdHash hasher;
    InodeId id{.ino = 12345678901234ULL, .dev = 259, .pad = 0};
    for (auto _ : state) {
        size_t hash = hasher(id);
        benchmark::DoNotOptimize(hash);
    }
}
BENCHMARK(BM_InodeIdHash);

// InodeIdHash with varying inodes (simulates map iteration)
static void BM_InodeIdHashVarying(benchmark::State& state)
{
    InodeIdHash hasher;
    uint64_t ino = 1000000;
    for (auto _ : state) {
        InodeId id{.ino = ino++, .dev = 259, .pad = 0};
        size_t hash = hasher(id);
        benchmark::DoNotOptimize(hash);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_InodeIdHashVarying);

// fill_path_key - Used when adding paths to deny_path_map
static void BM_FillPathKeyShort(benchmark::State& state)
{
    std::string path = "/usr/bin/malware";
    PathKey key{};
    for (auto _ : state) {
        fill_path_key(path, key);
        benchmark::DoNotOptimize(key);
    }
    state.SetBytesProcessed(state.iterations() * path.size());
}
BENCHMARK(BM_FillPathKeyShort);

static void BM_FillPathKeyLong(benchmark::State& state)
{
    // Near-maximum length path
    std::string path = "/var/lib/containers/storage/overlay/abcdef1234567890/" +
                       std::string(150, 'x') + "/binary";
    PathKey key{};
    for (auto _ : state) {
        fill_path_key(path, key);
        benchmark::DoNotOptimize(key);
    }
    state.SetBytesProcessed(state.iterations() * path.size());
}
BENCHMARK(BM_FillPathKeyLong);

// encode_dev - Converts dev_t to BPF-compatible format
static void BM_EncodeDev(benchmark::State& state)
{
    dev_t dev = makedev(259, 1);  // Typical NVMe device
    for (auto _ : state) {
        uint32_t encoded = encode_dev(dev);
        benchmark::DoNotOptimize(encoded);
    }
}
BENCHMARK(BM_EncodeDev);

// DenyEntries map operations (unordered_map with InodeId keys)
static void BM_DenyEntriesInsert(benchmark::State& state)
{
    const size_t map_size = state.range(0);
    for (auto _ : state) {
        state.PauseTiming();
        DenyEntries entries;
        entries.reserve(map_size);
        state.ResumeTiming();

        for (size_t i = 0; i < map_size; ++i) {
            InodeId id{.ino = i + 1000000, .dev = 259, .pad = 0};
            entries.emplace(id, "/path/to/file" + std::to_string(i));
        }
        benchmark::DoNotOptimize(entries);
    }
    state.SetItemsProcessed(state.iterations() * map_size);
}
BENCHMARK(BM_DenyEntriesInsert)->Range(100, 10000);

static void BM_DenyEntriesLookup(benchmark::State& state)
{
    const size_t map_size = state.range(0);
    DenyEntries entries;
    entries.reserve(map_size);
    for (size_t i = 0; i < map_size; ++i) {
        InodeId id{.ino = i + 1000000, .dev = 259, .pad = 0};
        entries.emplace(id, "/path/to/file" + std::to_string(i));
    }

    size_t lookup_idx = 0;
    for (auto _ : state) {
        InodeId id{.ino = (lookup_idx % map_size) + 1000000, .dev = 259, .pad = 0};
        auto it = entries.find(id);
        benchmark::DoNotOptimize(it);
        ++lookup_idx;
    }
}
BENCHMARK(BM_DenyEntriesLookup)->Range(100, 10000);

// PortKey hash - For deny_port map lookups
static void BM_PortKeyHash(benchmark::State& state)
{
    PortKeyHash hasher;
    PortKey key{.port = 443, .protocol = 6, .direction = 0};
    for (auto _ : state) {
        size_t hash = hasher(key);
        benchmark::DoNotOptimize(hash);
    }
}
BENCHMARK(BM_PortKeyHash);

// IPv4 parsing - Hot path for network deny rules
static void BM_ParseIpv4(benchmark::State& state)
{
    std::string ip = "192.168.1.100";
    for (auto _ : state) {
        uint32_t ip_be;
        bool result = parse_ipv4(ip, ip_be);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(ip_be);
    }
}
BENCHMARK(BM_ParseIpv4);

// IPv6 parsing - For IPv6 deny rules
static void BM_ParseIpv6(benchmark::State& state)
{
    std::string ip = "2001:db8::8a2e:370:7334";
    for (auto _ : state) {
        Ipv6Key key{};
        bool result = parse_ipv6(ip, key);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(key);
    }
}
BENCHMARK(BM_ParseIpv6);

// IPv6 parsing - Full address
static void BM_ParseIpv6Full(benchmark::State& state)
{
    std::string ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    for (auto _ : state) {
        Ipv6Key key{};
        bool result = parse_ipv6(ip, key);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(key);
    }
}
BENCHMARK(BM_ParseIpv6Full);

// CIDR v4 parsing - For LPM trie operations
static void BM_ParseCidrV4(benchmark::State& state)
{
    std::string cidr = "10.0.0.0/8";
    for (auto _ : state) {
        uint32_t ip_be;
        uint8_t prefix_len;
        bool result = parse_cidr_v4(cidr, ip_be, prefix_len);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(ip_be);
        benchmark::DoNotOptimize(prefix_len);
    }
}
BENCHMARK(BM_ParseCidrV4);

// CIDR v6 parsing
static void BM_ParseCidrV6(benchmark::State& state)
{
    std::string cidr = "2001:db8::/32";
    for (auto _ : state) {
        Ipv6Key ip{};
        uint8_t prefix_len;
        bool result = parse_cidr_v6(cidr, ip, prefix_len);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(ip);
        benchmark::DoNotOptimize(prefix_len);
    }
}
BENCHMARK(BM_ParseCidrV6);

// LPM key construction - IPv4
static void BM_Ipv4LpmKeyConstruction(benchmark::State& state)
{
    uint32_t ip_be = htonl(0x0A000000);  // 10.0.0.0
    uint8_t prefix_len = 8;
    for (auto _ : state) {
        Ipv4LpmKey key = {
            .prefixlen = prefix_len,
            .addr = ip_be};
        benchmark::DoNotOptimize(key);
    }
}
BENCHMARK(BM_Ipv4LpmKeyConstruction);

// LPM key construction - IPv6
static void BM_Ipv6LpmKeyConstruction(benchmark::State& state)
{
    Ipv6Key ip{};
    parse_ipv6("2001:db8::", ip);
    uint8_t prefix_len = 32;
    for (auto _ : state) {
        Ipv6LpmKey key = {
            .prefixlen = prefix_len,
            .addr = {0}};
        std::memcpy(key.addr, ip.addr, sizeof(key.addr));
        benchmark::DoNotOptimize(key);
    }
}
BENCHMARK(BM_Ipv6LpmKeyConstruction);

// IP formatting (for logging/output)
static void BM_FormatIpv4(benchmark::State& state)
{
    uint32_t ip_be = htonl(0xC0A80164);  // 192.168.1.100
    for (auto _ : state) {
        std::string result = format_ipv4(ip_be);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_FormatIpv4);

static void BM_FormatIpv6(benchmark::State& state)
{
    Ipv6Key ip{};
    parse_ipv6("2001:db8::8a2e:370:7334", ip);
    for (auto _ : state) {
        std::string result = format_ipv6(ip);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_FormatIpv6);

// inode_to_string - Used in logging and output
static void BM_InodeToString(benchmark::State& state)
{
    InodeId id{.ino = 12345678901234ULL, .dev = 259, .pad = 0};
    for (auto _ : state) {
        std::string result = inode_to_string(id);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_InodeToString);

// build_exec_id - Used for event correlation
static void BM_BuildExecId(benchmark::State& state)
{
    uint32_t pid = 12345;
    uint64_t start_time = 1234567890123456789ULL;
    for (auto _ : state) {
        std::string result = build_exec_id(pid, start_time);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_BuildExecId);

// InodeId comparison (for equality checks in maps)
static void BM_InodeIdComparison(benchmark::State& state)
{
    InodeId id1{.ino = 12345678901234ULL, .dev = 259, .pad = 0};
    InodeId id2{.ino = 12345678901234ULL, .dev = 259, .pad = 0};
    InodeId id3{.ino = 12345678901235ULL, .dev = 259, .pad = 0};
    bool toggle = false;
    for (auto _ : state) {
        bool result = toggle ? (id1 == id2) : (id1 == id3);
        benchmark::DoNotOptimize(result);
        toggle = !toggle;
    }
}
BENCHMARK(BM_InodeIdComparison);

// Protocol name lookup (for output formatting)
static void BM_ProtocolName(benchmark::State& state)
{
    uint8_t protocols[] = {0, 6, 17, 99};
    size_t idx = 0;
    for (auto _ : state) {
        std::string name = protocol_name(protocols[idx % 4]);
        benchmark::DoNotOptimize(name);
        ++idx;
    }
}
BENCHMARK(BM_ProtocolName);

// Direction name lookup
static void BM_DirectionName(benchmark::State& state)
{
    uint8_t directions[] = {0, 1, 2, 255};
    size_t idx = 0;
    for (auto _ : state) {
        std::string name = direction_name(directions[idx % 4]);
        benchmark::DoNotOptimize(name);
        ++idx;
    }
}
BENCHMARK(BM_DirectionName);

}  // namespace
}  // namespace aegis

BENCHMARK_MAIN();
