#!/usr/bin/env bash
# Compare AegisBPF performance against other eBPF security agents.
#
# Usage:
#   sudo ./compare.sh                              # Compare all installed tools
#   sudo ./compare.sh --tools aegisbpf,falco       # Compare specific tools
#   sudo ./compare.sh --test file-open             # Specific benchmark
#
# Prerequisites:
#   Each tool must be installed and accessible in PATH or standard locations.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results/compare-$(date +%Y%m%d-%H%M%S)"
ITERATIONS="${ITERATIONS:-50000}"
TOOLS="aegisbpf"
TEST_FILTER="file-open"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tools)      TOOLS="$2"; shift 2 ;;
            --test)       TEST_FILTER="$2"; shift 2 ;;
            --iterations) ITERATIONS="$2"; shift 2 ;;
            --help|-h)
                echo "Usage: $0 [--tools tool1,tool2] [--test name] [--iterations n]"
                echo "Tools: aegisbpf, falco, tetragon, tracee"
                echo "Tests: file-open, network-connect, process-exec"
                exit 0
                ;;
            *) shift ;;
        esac
    done
}

detect_tools() {
    info "Detecting installed security agents..."
    local detected=()

    # AegisBPF
    if command -v aegisbpf &>/dev/null || [[ -x ./build/aegisbpf ]]; then
        detected+=(aegisbpf)
        info "  Found: AegisBPF"
    fi

    # Falco
    if command -v falco &>/dev/null; then
        detected+=(falco)
        info "  Found: Falco $(falco --version 2>/dev/null | head -1)"
    fi

    # Tetragon
    if command -v tetragon &>/dev/null || command -v tetra &>/dev/null; then
        detected+=(tetragon)
        info "  Found: Tetragon"
    fi

    # Tracee
    if command -v tracee &>/dev/null; then
        detected+=(tracee)
        info "  Found: Tracee"
    fi

    if [[ ${#detected[@]} -eq 0 ]]; then
        warn "No agents detected. Running baseline only."
    fi

    echo "${detected[*]}"
}

# Run the file-open microbenchmark with a given agent running.
run_file_open_bench() {
    local agent_name="${1:-baseline}"
    local iters="$ITERATIONS"

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
    const char *path = argc > 1 ? argv[1] : "/dev/null";
    int iters = argc > 2 ? atoi(argv[2]) : 100000;

    for (int i = 0; i < 1000; i++) {
        int fd = open(path, O_RDONLY);
        if (fd >= 0) close(fd);
    }

    long long *lat = malloc(sizeof(long long) * iters);
    for (int i = 0; i < iters; i++) {
        long long s = now_ns();
        int fd = open(path, O_RDONLY);
        if (fd >= 0) close(fd);
        lat[i] = now_ns() - s;
    }

    int cmp(const void *a, const void *b) {
        long long va = *(const long long *)a, vb = *(const long long *)b;
        return (va > vb) - (va < vb);
    }
    qsort(lat, iters, sizeof(long long), cmp);

    long long total = 0;
    for (int i = 0; i < iters; i++) total += lat[i];

    printf("{\"agent\":\"%s\",\"mean_ns\":%lld,\"p50_ns\":%lld,\"p95_ns\":%lld,\"p99_ns\":%lld,\"min_ns\":%lld,\"max_ns\":%lld}\n",
        argv[3], total / iters, lat[iters/2], lat[(int)(iters*0.95)], lat[(int)(iters*0.99)], lat[0], lat[iters-1]);

    free(lat);
    return 0;
}
CSRC

    local bin
    bin=$(mktemp)
    gcc -O2 -o "$bin" "$src" 2>/dev/null

    local testfile
    testfile=$(mktemp)
    echo "benchmark" > "$testfile"

    "$bin" "$testfile" "$iters" "$agent_name"

    rm -f "$src" "$bin" "$testfile"
}

# Run the network-connect microbenchmark with a given agent running.
run_network_connect_bench() {
    local agent_name="${1:-baseline}"
    local iters=$((ITERATIONS / 10))

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

static int cmp_ll(const void *a, const void *b) {
    long long va = *(const long long *)a, vb = *(const long long *)b;
    return (va > vb) - (va < vb);
}

int main(int argc, char *argv[]) {
    int iters = argc > 1 ? atoi(argv[1]) : 10000;
    const char *agent = argc > 2 ? argv[2] : "baseline";

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    long long *lat = malloc(sizeof(long long) * iters);
    if (!lat) { perror("malloc"); return 1; }

    for (int i = 0; i < iters; i++) {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (fd < 0) { lat[i] = 0; continue; }
        long long s = now_ns();
        connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        lat[i] = now_ns() - s;
        close(fd);
    }

    qsort(lat, iters, sizeof(long long), cmp_ll);

    long long total = 0;
    for (int i = 0; i < iters; i++) total += lat[i];

    printf("{\"agent\":\"%s\",\"mean_ns\":%lld,\"p50_ns\":%lld,\"p95_ns\":%lld,\"p99_ns\":%lld,\"min_ns\":%lld,\"max_ns\":%lld}\n",
        agent, total / iters, lat[iters/2], lat[(int)(iters*0.95)], lat[(int)(iters*0.99)], lat[0], lat[iters-1]);

    free(lat);
    return 0;
}
CSRC

    local bin
    bin=$(mktemp)
    gcc -O2 -o "$bin" "$src" 2>/dev/null

    "$bin" "$iters" "$agent_name"

    rm -f "$src" "$bin"
}

# Run the process-exec microbenchmark with a given agent running.
run_process_exec_bench() {
    local agent_name="${1:-baseline}"
    local iters=$((ITERATIONS / 100))

    local results=()
    for ((i = 0; i < iters; i++)); do
        local start end
        start=$(date +%s%N)
        /bin/true
        end=$(date +%s%N)
        results+=($((end - start)))
    done

    python3 -c "
import json
data = [${results[*]// /,}]
data.sort()
n = len(data)
mean = sum(data) // n
print(json.dumps({
    'agent': '$agent_name',
    'mean_ns': mean,
    'p50_ns': data[n // 2],
    'p95_ns': data[int(n * 0.95)],
    'p99_ns': data[int(n * 0.99)],
    'min_ns': data[0],
    'max_ns': data[-1]
}))
"
}

generate_comparison() {
    local results_file="$1"
    info "=== Comparison Results ==="

    python3 - "$results_file" <<'PYEOF'
import json, sys

with open(sys.argv[1]) as f:
    results = [json.loads(line) for line in f if line.strip()]

if not results:
    print("No results to compare")
    sys.exit(0)

baseline = next((r for r in results if r["agent"] == "baseline"), results[0])
base_mean = baseline["mean_ns"]

print(f"\n{'Agent':<15} {'Mean':>10} {'P50':>10} {'P99':>10} {'Overhead':>10}")
print("=" * 60)

for r in sorted(results, key=lambda x: x["mean_ns"]):
    overhead = ((r["mean_ns"] - base_mean) / base_mean * 100) if base_mean > 0 else 0
    overhead_str = f"{overhead:+.1f}%" if r["agent"] != "baseline" else "---"
    print(f"{r['agent']:<15} {r['mean_ns']:>8}ns {r['p50_ns']:>8}ns {r['p99_ns']:>8}ns {overhead_str:>10}")

print("=" * 60)
print(f"\nBaseline: {base_mean}ns mean ({baseline.get('p99_ns', 'N/A')}ns p99)")
PYEOF
}

main() {
    parse_args "$@"
    mkdir -p "$RESULTS_DIR"

    if [[ $EUID -ne 0 ]]; then
        warn "Not running as root. Some benchmarks may be limited."
    fi

    local results_file="$RESULTS_DIR/comparison.jsonl"

    # Select the benchmark function based on TEST_FILTER
    local bench_fn
    case "$TEST_FILTER" in
        file-open)       bench_fn=run_file_open_bench ;;
        network-connect) bench_fn=run_network_connect_bench ;;
        process-exec)    bench_fn=run_process_exec_bench ;;
        *)
            error "Unknown test: $TEST_FILTER. Valid options: file-open, network-connect, process-exec"
            exit 1
            ;;
    esac

    info "Running baseline (no agent) [$TEST_FILTER]..."
    $bench_fn "baseline" >> "$results_file"

    # Run with each detected agent
    IFS=',' read -ra tools <<< "$TOOLS"
    for tool in "${tools[@]}"; do
        case "$tool" in
            aegisbpf)
                if pgrep -x aegisbpf &>/dev/null; then
                    info "Running with AegisBPF (already running)..."
                    $bench_fn "aegisbpf" >> "$results_file"
                else
                    info "AegisBPF not running, skipping live comparison"
                fi
                ;;
            falco)
                if pgrep -x falco &>/dev/null; then
                    info "Running with Falco (already running)..."
                    $bench_fn "falco" >> "$results_file"
                else
                    info "Falco not running, skipping live comparison"
                fi
                ;;
            tetragon)
                if pgrep -f tetragon &>/dev/null; then
                    info "Running with Tetragon (already running)..."
                    $bench_fn "tetragon" >> "$results_file"
                else
                    info "Tetragon not running, skipping live comparison"
                fi
                ;;
            tracee)
                if pgrep -x tracee &>/dev/null; then
                    info "Running with Tracee (already running)..."
                    $bench_fn "tracee" >> "$results_file"
                else
                    info "Tracee not running, skipping live comparison"
                fi
                ;;
        esac
    done

    generate_comparison "$results_file"
    info "Raw results: $results_file"
}

main "$@"
