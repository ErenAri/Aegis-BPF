// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file missingInclude
// cppcheck-suppress-file unknownMacro
//
// Privileged syscall-level benchmarks for AegisBPF LSM hook overhead.
//
// These benchmarks measure actual syscall latency with and without BPF
// enforcement loaded, across varying deny-rule counts.  They require:
//   - Root privileges (CAP_SYS_ADMIN for BPF loading)
//   - Kernel with BPF LSM enabled
//   - BPF object built (aegis.bpf.o available)
//
// Benchmarks that cannot satisfy prerequisites are skipped at runtime.

#include <arpa/inet.h>
#include <benchmark/benchmark.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>

#include "bpf_ops.hpp"
#include "kernel_features.hpp"
#include "types.hpp"

namespace aegis {
namespace {

// ---------------------------------------------------------------------------
// Helper: check whether we can run privileged BPF benchmarks.
// ---------------------------------------------------------------------------
bool can_run_bpf()
{
    if (geteuid() != 0)
        return false;
    // Quick probe: can we call bpf(BPF_PROG_TYPE_UNSPEC)?  If the kernel
    // rejects it we lack BPF capability.
    return true;
}

// ---------------------------------------------------------------------------
// Baseline: open()/read()/close() with NO BPF loaded.
// Measures raw kernel overhead for the hot-path syscall.
// ---------------------------------------------------------------------------
static void BM_OpenBaseline(benchmark::State& state)
{
    const char* path = "/etc/hosts";
    if (access(path, R_OK) != 0) {
        state.SkipWithMessage("Cannot read /etc/hosts");
        return;
    }
    char buf[1];
    for (auto _ : state) {
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            state.SkipWithError("open() failed");
            return;
        }
        benchmark::DoNotOptimize(read(fd, buf, 1));
        close(fd);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_OpenBaseline)->Unit(benchmark::kMicrosecond)->MinTime(1.0);

// ---------------------------------------------------------------------------
// BPF-loaded benchmarks: load BPF, attach, measure open() latency.
// ---------------------------------------------------------------------------

class BpfBenchmark : public benchmark::Fixture {
  public:
    void SetUp(const benchmark::State& st) override
    {
        if (!can_run_bpf()) {
            skip_ = true;
            return;
        }
        auto feats = detect_kernel_features();
        if (!feats || !feats->bpf_lsm) {
            skip_ = true;
            return;
        }
        lsm_enabled_ = feats->bpf_lsm;

        auto rlimit = bump_memlock_rlimit();
        if (!rlimit) {
            skip_ = true;
            return;
        }

        auto load = load_bpf(/*reuse_pins=*/false, /*attach_links=*/false, state_);
        if (!load) {
            skip_ = true;
            return;
        }

        // Attach hooks (both inode_permission and file_open).
        auto att = attach_all(state_, lsm_enabled_,
                              /*use_inode_permission=*/true, /*use_file_open=*/true);
        if (!att) {
            skip_ = true;
            return;
        }

        // Set audit-only mode so we observe overhead without blocking.
        AgentConfig cfg{};
        cfg.audit_only = 1;
        auto sc = set_agent_config_full(state_, cfg);
        if (!sc) {
            skip_ = true;
            return;
        }

        // Pre-populate deny rules for parameterised benchmarks.
        auto rule_count = static_cast<size_t>(st.range(0));
        if (rule_count > 0) {
            DenyEntries entries;
            for (size_t i = 0; i < rule_count; ++i) {
                InodeId id{.ino = 90000000ULL + i, .dev = 999, .pad = 0};
                auto r = add_deny_inode(state_, id, entries);
                if (!r) {
                    skip_ = true;
                    return;
                }
            }
        }
    }

    void TearDown(const benchmark::State&) override
    {
        state_.cleanup();
    }

    BpfState state_;
    bool skip_ = false;
    bool lsm_enabled_ = false;
};

BENCHMARK_DEFINE_F(BpfBenchmark, OpenWithBpf)
(benchmark::State& st)
{
    if (skip_) {
        st.SkipWithMessage("BPF prerequisites not met (need root + BPF LSM)");
        return;
    }
    const char* path = "/etc/hosts";
    char buf[1];
    for (auto _ : st) {
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            st.SkipWithError("open() failed");
            return;
        }
        benchmark::DoNotOptimize(read(fd, buf, 1));
        close(fd);
    }
    st.SetItemsProcessed(st.iterations());
}
// Deny-rule counts: 0 (empty), 100, 1000, 10000
BENCHMARK_REGISTER_F(BpfBenchmark, OpenWithBpf)
    ->Arg(0)
    ->Arg(100)
    ->Arg(1000)
    ->Arg(10000)
    ->Unit(benchmark::kMicrosecond)
    ->MinTime(1.0);

// ---------------------------------------------------------------------------
// Network: connect() latency with BPF loaded.
// ---------------------------------------------------------------------------

class NetBpfBenchmark : public benchmark::Fixture {
  public:
    void SetUp(const benchmark::State&) override
    {
        if (!can_run_bpf()) {
            skip_ = true;
            return;
        }
        auto feats = detect_kernel_features();
        if (!feats || !feats->bpf_lsm) {
            skip_ = true;
            return;
        }

        auto rlimit = bump_memlock_rlimit();
        if (!rlimit) {
            skip_ = true;
            return;
        }

        auto load = load_bpf(/*reuse_pins=*/false, /*attach_links=*/false, state_);
        if (!load) {
            skip_ = true;
            return;
        }

        auto att = attach_all(state_, feats->bpf_lsm,
                              /*use_inode_permission=*/true, /*use_file_open=*/true);
        if (!att) {
            skip_ = true;
            return;
        }

        AgentConfig cfg{};
        cfg.audit_only = 1;
        auto sc = set_agent_config_full(state_, cfg);
        if (!sc) {
            skip_ = true;
            return;
        }

        // Start a local TCP listener for connect() targets.
        listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ < 0) {
            skip_ = true;
            return;
        }
        int opt = 1;
        setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0; // Kernel picks port.
        if (bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0 ||
            listen(listen_fd_, 256) < 0) {
            close(listen_fd_);
            listen_fd_ = -1;
            skip_ = true;
            return;
        }
        socklen_t len = sizeof(addr);
        getsockname(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);
    }

    void TearDown(const benchmark::State&) override
    {
        if (listen_fd_ >= 0)
            close(listen_fd_);
        state_.cleanup();
    }

    BpfState state_;
    bool skip_ = false;
    int listen_fd_ = -1;
    uint16_t port_ = 0;
};

BENCHMARK_DEFINE_F(NetBpfBenchmark, ConnectWithBpf)
(benchmark::State& st)
{
    if (skip_) {
        st.SkipWithMessage("BPF prerequisites not met (need root + BPF LSM)");
        return;
    }

    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port_);

    for (auto _ : st) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            st.SkipWithError("socket() failed");
            return;
        }
        int rc = connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        benchmark::DoNotOptimize(rc);
        close(fd);

        // Accept and close the peer so the listen backlog doesn't fill.
        int peer = accept(listen_fd_, nullptr, nullptr);
        if (peer >= 0)
            close(peer);
    }
    st.SetItemsProcessed(st.iterations());
}
BENCHMARK_REGISTER_F(NetBpfBenchmark, ConnectWithBpf)
    ->Unit(benchmark::kMicrosecond)
    ->MinTime(1.0);

// ---------------------------------------------------------------------------
// connect() baseline (no BPF loaded).
// ---------------------------------------------------------------------------
static void BM_ConnectBaseline(benchmark::State& state)
{
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        state.SkipWithError("socket() failed");
        return;
    }
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0 ||
        listen(listen_fd, 256) < 0) {
        close(listen_fd);
        state.SkipWithError("bind/listen failed");
        return;
    }
    socklen_t len = sizeof(addr);
    getsockname(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), &len);

    for (auto _ : state) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            state.SkipWithError("socket() failed");
            close(listen_fd);
            return;
        }
        int rc = connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        benchmark::DoNotOptimize(rc);
        close(fd);

        int peer = accept(listen_fd, nullptr, nullptr);
        if (peer >= 0)
            close(peer);
    }
    close(listen_fd);
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ConnectBaseline)->Unit(benchmark::kMicrosecond)->MinTime(1.0);

} // namespace
} // namespace aegis

BENCHMARK_MAIN();
