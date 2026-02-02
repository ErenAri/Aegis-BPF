#include <benchmark/benchmark.h>
#include <fstream>
#include <filesystem>
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

BENCHMARK_DEFINE_F(PolicyBenchmark, ParsePolicy)(benchmark::State& state)
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

}  // namespace
}  // namespace aegis

BENCHMARK_MAIN();
