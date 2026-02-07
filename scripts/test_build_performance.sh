#!/bin/bash
# AegisBPF Build Performance Test
# Measures compile time overhead on a C++ project

set -euo pipefail

BINARY="./build/aegisbpf"
PROJECT_DIR="${PROJECT_DIR:-$(pwd)}"

echo "╔═══════════════════════════════════════════════════╗"
echo "║  AegisBPF Build Performance Test                 ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""
echo "Project: $PROJECT_DIR"
echo "Cores: $(nproc)"
echo ""

# Check if we have a Makefile or CMakeLists.txt
if [ ! -f "$PROJECT_DIR/Makefile" ] && [ ! -f "$PROJECT_DIR/CMakeLists.txt" ]; then
    echo "ERROR: No Makefile or CMakeLists.txt found in $PROJECT_DIR"
    exit 1
fi

# Function to build project
run_build() {
    local label=$1
    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "Testing: $label"
    echo "═══════════════════════════════════════════════════"

    # Clean first
    make clean > /dev/null 2>&1 || (cd build && rm -rf * && cmake ..) > /dev/null 2>&1 || true

    # Time the build
    START=$(date +%s.%N)
    if [ -f "Makefile" ]; then
        make -j$(nproc) > /tmp/build-${label}.log 2>&1
    else
        cd build && cmake .. > /dev/null 2>&1 && make -j$(nproc) > /tmp/build-${label}.log 2>&1
        cd ..
    fi
    END=$(date +%s.%N)

    BUILD_TIME=$(echo "$END - $START" | bc)
    echo "Build time: ${BUILD_TIME}s"

    echo "$label,$BUILD_TIME" >> /tmp/build-performance.csv
}

# CSV header
echo "test,build_time_seconds" > /tmp/build-performance.csv

# Baseline
if pgrep -f "aegisbpf run" > /dev/null; then
    echo "⚠️  WARNING: AegisBPF is running. Stop it for baseline."
    exit 1
fi

echo "▶ Phase 1: Baseline (without AegisBPF)"
run_build "baseline"

# With AegisBPF
echo ""
echo "▶ Phase 2: Starting AegisBPF..."
sudo "$BINARY" run --audit > /tmp/aegisbpf-build-test.log 2>&1 &
DAEMON_PID=$!
sleep 3

if ! ps -p $DAEMON_PID > /dev/null; then
    echo "❌ ERROR: AegisBPF failed to start"
    exit 1
fi

sudo "$BINARY" policy apply ./config/policy-production.conf || true

run_build "with-aegisbpf"

# Check for false positives
echo ""
echo "Checking for blocked operations..."
sudo "$BINARY" stats --detailed | grep -A 20 "Top blocked" > /tmp/build-blocks.txt || true

# Stop daemon
sudo pkill -f "aegisbpf run"

# Results
echo ""
echo "╔═══════════════════════════════════════════════════╗"
echo "║  Results                                          ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""

python3 <<'PYTHON'
import csv

with open('/tmp/build-performance.csv') as f:
    reader = csv.DictReader(f)
    rows = list(reader)

baseline_time = float(rows[0]['build_time_seconds'])
with_aegis_time = float(rows[1]['build_time_seconds'])
overhead_pct = ((with_aegis_time - baseline_time) / baseline_time) * 100

print(f"Build Time:")
print(f"  Baseline:      {baseline_time:.1f}s")
print(f"  With AegisBPF: {with_aegis_time:.1f}s")
print(f"  Overhead:      {overhead_pct:+.1f}%")
print()

if overhead_pct < 10:
    print(f"✅ PASS: Overhead {overhead_pct:.1f}% is acceptable for builds")
elif overhead_pct < 20:
    print(f"⚠️  MARGINAL: Overhead {overhead_pct:.1f}% - review if acceptable")
else:
    print(f"❌ FAIL: Overhead {overhead_pct:.1f}% too high")
PYTHON

echo ""
echo "Blocked operations during build:"
cat /tmp/build-blocks.txt
