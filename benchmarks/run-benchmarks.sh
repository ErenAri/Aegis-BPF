#!/usr/bin/env bash
# AegisBPF Competitive Benchmark Suite
# Measures overhead of file, network, and process operations with/without agents.
#
# Usage:
#   sudo ./run-benchmarks.sh                    # Run all tests
#   sudo ./run-benchmarks.sh --test file-open   # Run specific test
#   sudo ./run-benchmarks.sh --iterations 50000 # Custom iteration count
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results/$(date +%Y%m%d-%H%M%S)"
ITERATIONS="${ITERATIONS:-100000}"
WARMUP=1000
TEST_FILTER="${1:-all}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --test)       TEST_FILTER="$2"; shift 2 ;;
            --iterations) ITERATIONS="$2"; shift 2 ;;
            --output)     RESULTS_DIR="$2"; shift 2 ;;
            --help|-h)
                echo "Usage: $0 [--test <name>] [--iterations <n>] [--output <dir>]"
                echo "Tests: file-open, network-connect, process-exec, memory, startup, all"
                exit 0
                ;;
            *) TEST_FILTER="$1"; shift ;;
        esac
    done
}

check_prereqs() {
    if [[ $EUID -ne 0 ]]; then
        error "Must run as root (BPF programs require CAP_BPF)"
        exit 1
    fi

    # Optional tools: script can run without these, but measurements may be limited.
    for cmd in taskset perf; do
        if ! command -v "$cmd" &>/dev/null; then
            warn "$cmd not found, some measurements will be limited"
        fi
    done

    # Required tools: benchmark compilation and JSON summarization depend on these.
    for cmd in gcc python3; do
        if ! command -v "$cmd" &>/dev/null; then
            error "$cmd is required but was not found in PATH. Please install $cmd before running benchmarks."
            exit 1
        fi
    done

    mkdir -p "$RESULTS_DIR"
    info "Results directory: $RESULTS_DIR"
}

collect_system_info() {
    local out="$RESULTS_DIR/system-info.json"
    cat > "$out" <<EOF
{
  "kernel": "$(uname -r)",
  "arch": "$(uname -m)",
  "cpu": "$(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)",
  "cpu_cores": $(nproc),
  "memory_mb": $(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo),
  "governor": "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo 'unknown')",
  "btf": $([ -f /sys/kernel/btf/vmlinux ] && echo true || echo false),
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "iterations": $ITERATIONS
}
EOF
    info "System: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"
    info "Kernel: $(uname -r), CPUs: $(nproc), Governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo 'unknown')"
}

# Benchmark: file open/close overhead
bench_file_open() {
    info "=== File Open Benchmark ($ITERATIONS iterations) ==="
    local testfile
    testfile=$(mktemp)
    echo "test" > "$testfile"

    local out="$RESULTS_DIR/file-open.json"

    # Generate the C benchmark inline
    local src
    src=$(mktemp --suffix=.c)
    cat > "$src" <<'CSRC'
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static inline long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int main(int argc, char *argv[]) {
    if (argc < 3) { fprintf(stderr, "Usage: %s <file> <iterations>\n", argv[0]); return 1; }

    const char *path = argv[1];
    int iters = atoi(argv[2]);
    int warmup = 1000;

    // Warmup
    for (int i = 0; i < warmup; i++) {
        int fd = open(path, O_RDONLY);
        if (fd >= 0) close(fd);
    }

    // Allocate results array
    long long *latencies = malloc(sizeof(long long) * iters);
    if (!latencies) { perror("malloc"); return 1; }

    for (int i = 0; i < iters; i++) {
        long long start = now_ns();
        int fd = open(path, O_RDONLY);
        if (fd >= 0) close(fd);
        latencies[i] = now_ns() - start;
    }

    // Sort for percentiles
    int cmp(const void *a, const void *b) {
        long long va = *(const long long *)a, vb = *(const long long *)b;
        return (va > vb) - (va < vb);
    }
    qsort(latencies, iters, sizeof(long long), cmp);

    long long total = 0;
    for (int i = 0; i < iters; i++) total += latencies[i];

    printf("{\"mean_ns\":%lld,\"p50_ns\":%lld,\"p95_ns\":%lld,\"p99_ns\":%lld,\"min_ns\":%lld,\"max_ns\":%lld,\"iterations\":%d}\n",
        total / iters,
        latencies[iters / 2],
        latencies[(int)(iters * 0.95)],
        latencies[(int)(iters * 0.99)],
        latencies[0],
        latencies[iters - 1],
        iters);

    free(latencies);
    return 0;
}
CSRC

    local bin
    bin=$(mktemp)
    gcc -O2 -o "$bin" "$src" 2>/dev/null

    info "  Baseline (no agent)..."
    local baseline
    baseline=$("$bin" "$testfile" "$ITERATIONS")

    echo "{\"test\":\"file-open\",\"baseline\":$baseline}" > "$out"

    # If aegisbpf is running, measure with it
    if pgrep -x aegisbpf &>/dev/null; then
        info "  With AegisBPF..."
        local with_agent
        with_agent=$("$bin" "$testfile" "$ITERATIONS")
        # Rewrite JSON with agent results
        python3 -c "
import json, sys
base = json.loads('$baseline')
agent = json.loads('$with_agent')
overhead = ((agent['mean_ns'] - base['mean_ns']) / base['mean_ns']) * 100
print(json.dumps({
    'test': 'file-open',
    'baseline': base,
    'aegisbpf': agent,
    'overhead_pct': round(overhead, 2)
}, indent=2))
" > "$out" 2>/dev/null || true
    fi

    rm -f "$src" "$bin" "$testfile"
    info "  Results: $(cat "$out")"
}

# Benchmark: TCP connect latency
bench_network_connect() {
    info "=== Network Connect Benchmark ($((ITERATIONS / 10)) iterations) ==="
    local iters=$((ITERATIONS / 10))
    local out="$RESULTS_DIR/network-connect.json"

    local src
    src=$(mktemp --suffix=.c)
    cat > "$src" <<'CSRC'
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static inline long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int main(int argc, char *argv[]) {
    int iters = argc > 1 ? atoi(argv[1]) : 10000;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1);  // Unlikely to be listening
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    long long *latencies = malloc(sizeof(long long) * iters);
    if (!latencies) { perror("malloc"); return 1; }

    for (int i = 0; i < iters; i++) {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (fd < 0) continue;
        long long start = now_ns();
        connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        latencies[i] = now_ns() - start;
        close(fd);
    }

    int cmp(const void *a, const void *b) {
        long long va = *(const long long *)a, vb = *(const long long *)b;
        return (va > vb) - (va < vb);
    }
    qsort(latencies, iters, sizeof(long long), cmp);

    long long total = 0;
    for (int i = 0; i < iters; i++) total += latencies[i];

    printf("{\"mean_ns\":%lld,\"p50_ns\":%lld,\"p95_ns\":%lld,\"p99_ns\":%lld,\"min_ns\":%lld,\"max_ns\":%lld,\"iterations\":%d}\n",
        total / iters,
        latencies[iters / 2],
        latencies[(int)(iters * 0.95)],
        latencies[(int)(iters * 0.99)],
        latencies[0],
        latencies[iters - 1],
        iters);

    free(latencies);
    return 0;
}
CSRC

    local bin
    bin=$(mktemp)
    gcc -O2 -o "$bin" "$src" 2>/dev/null

    info "  Baseline..."
    local baseline
    baseline=$("$bin" "$iters")
    echo "{\"test\":\"network-connect\",\"baseline\":$baseline}" > "$out"

    rm -f "$src" "$bin"
    info "  Results: $(cat "$out")"
}

# Benchmark: process exec overhead
bench_process_exec() {
    info "=== Process Exec Benchmark ($((ITERATIONS / 100)) iterations) ==="
    local iters=$((ITERATIONS / 100))
    local out="$RESULTS_DIR/process-exec.json"

    local total_ns=0
    local results=()

    for ((i = 0; i < iters; i++)); do
        local start end
        start=$(date +%s%N)
        /bin/true
        end=$(date +%s%N)
        results+=($((end - start)))
    done

    # Calculate stats in Python
    python3 -c "
import json, sys
data = [${results[*]// /,}]
data.sort()
n = len(data)
mean = sum(data) // n
print(json.dumps({
    'test': 'process-exec',
    'baseline': {
        'mean_ns': mean,
        'p50_ns': data[n // 2],
        'p95_ns': data[int(n * 0.95)],
        'p99_ns': data[int(n * 0.99)],
        'min_ns': data[0],
        'max_ns': data[-1],
        'iterations': n
    }
}, indent=2))
" > "$out" 2>/dev/null
    info "  Results: $(cat "$out")"
}

# Benchmark: memory footprint
bench_memory() {
    info "=== Memory Benchmark ==="
    local out="$RESULTS_DIR/memory.json"

    local result="{\"test\":\"memory\""
    if pgrep -x aegisbpf &>/dev/null; then
        local pid
        pid=$(pgrep -x aegisbpf | head -1)
        local rss vsz
        rss=$(awk '/VmRSS/ {print $2}' /proc/"$pid"/status 2>/dev/null || echo 0)
        vsz=$(awk '/VmSize/ {print $2}' /proc/"$pid"/status 2>/dev/null || echo 0)
        result+=",\"aegisbpf\":{\"rss_kb\":$rss,\"vsz_kb\":$vsz,\"pid\":$pid}"
    else
        result+=",\"aegisbpf\":null"
    fi
    result+="}"

    echo "$result" | python3 -m json.tool > "$out" 2>/dev/null || echo "$result" > "$out"
    info "  Results: $(cat "$out")"
}

# Benchmark: startup time
bench_startup() {
    info "=== Startup Time Benchmark ==="
    local out="$RESULTS_DIR/startup.json"
    local aegisbpf_bin

    # Find aegisbpf binary
    for candidate in ./build/aegisbpf ../build/aegisbpf /usr/local/bin/aegisbpf /usr/bin/aegisbpf; do
        if [[ -x "$candidate" ]]; then
            aegisbpf_bin="$candidate"
            break
        fi
    done

    if [[ -z "${aegisbpf_bin:-}" ]]; then
        warn "  aegisbpf binary not found, skipping startup benchmark"
        echo '{"test":"startup","error":"binary not found"}' > "$out"
        return
    fi

    # Measure time to --help (proxy for binary load time)
    local total=0
    local runs=10
    for ((i = 0; i < runs; i++)); do
        local start end
        start=$(date +%s%N)
        "$aegisbpf_bin" --help &>/dev/null || true
        end=$(date +%s%N)
        total=$((total + end - start))
    done

    local mean_ns=$((total / runs))
    local mean_ms=$((mean_ns / 1000000))
    echo "{\"test\":\"startup\",\"help_latency_ms\":$mean_ms,\"runs\":$runs}" > "$out"
    info "  Binary load time: ${mean_ms}ms (avg of $runs runs)"
}

generate_summary() {
    info "=== Generating Summary ==="
    python3 - "$RESULTS_DIR" <<'PYEOF'
import json, glob, sys, os

results_dir = sys.argv[1]
summary = {"system": {}, "benchmarks": {}}

# Load system info
sysinfo = os.path.join(results_dir, "system-info.json")
if os.path.exists(sysinfo):
    with open(sysinfo) as f:
        summary["system"] = json.load(f)

# Load all benchmark results
for path in sorted(glob.glob(os.path.join(results_dir, "*.json"))):
    name = os.path.basename(path).replace(".json", "")
    if name == "system-info" or name == "summary":
        continue
    try:
        with open(path) as f:
            summary["benchmarks"][name] = json.load(f)
    except json.JSONDecodeError:
        pass

out = os.path.join(results_dir, "summary.json")
with open(out, "w") as f:
    json.dump(summary, f, indent=2)

print(f"Summary written to {out}")

# Print table
print("\n" + "=" * 60)
print(f"{'Test':<20} {'Mean':>10} {'P50':>10} {'P99':>10}")
print("=" * 60)
for name, data in summary["benchmarks"].items():
    base = data.get("baseline", data)
    if isinstance(base, dict) and "mean_ns" in base:
        print(f"{name:<20} {base['mean_ns']:>8}ns {base.get('p50_ns', 'N/A'):>8}ns {base.get('p99_ns', 'N/A'):>8}ns")
print("=" * 60)
PYEOF
}

main() {
    parse_args "$@"
    check_prereqs
    collect_system_info

    case "$TEST_FILTER" in
        all)
            bench_file_open
            bench_network_connect
            bench_process_exec
            bench_memory
            bench_startup
            ;;
        file-open)       bench_file_open ;;
        network-connect) bench_network_connect ;;
        process-exec)    bench_process_exec ;;
        memory)          bench_memory ;;
        startup)         bench_startup ;;
        *)
            error "Unknown test: $TEST_FILTER"
            exit 1
            ;;
    esac

    generate_summary
    info "All results saved to $RESULTS_DIR"
}

main "$@"
