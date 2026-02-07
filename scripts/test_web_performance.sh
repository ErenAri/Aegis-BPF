#!/bin/bash
# AegisBPF Web Service Performance Test
# Tests HTTP service latency and throughput impact

set -euo pipefail

SERVICE_URL="${SERVICE_URL:-http://localhost:8080}"
DURATION=${DURATION:-60}
CONNECTIONS=${CONNECTIONS:-200}
THREADS=${THREADS:-8}
BINARY="./build/aegisbpf"

echo "╔═══════════════════════════════════════════════════╗"
echo "║  AegisBPF Web Service Performance Test           ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""
echo "Configuration:"
echo "  URL: $SERVICE_URL"
echo "  Duration: ${DURATION}s"
echo "  Connections: $CONNECTIONS"
echo "  Threads: $THREADS"
echo ""

# Check wrk is installed
if ! command -v wrk &> /dev/null; then
    echo "ERROR: wrk not installed. Install with:"
    echo "  sudo apt install wrk"
    exit 1
fi

# Check service is responding
if ! curl -sf "$SERVICE_URL" > /dev/null 2>&1; then
    echo "ERROR: Service not responding at $SERVICE_URL"
    echo "Start your web service first!"
    exit 1
fi

# Function to run load test
run_test() {
    local label=$1
    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "Testing: $label"
    echo "═══════════════════════════════════════════════════"

    wrk -t $THREADS -c $CONNECTIONS -d ${DURATION}s --latency "$SERVICE_URL" 2>&1 | tee /tmp/wrk-${label}.txt

    # Extract metrics
    RPS=$(grep "Requests/sec:" /tmp/wrk-${label}.txt | awk '{print $2}' || echo "0")
    P50=$(grep "50.000%" /tmp/wrk-${label}.txt | awk '{print $2}' || echo "0")
    P99=$(grep "99.000%" /tmp/wrk-${label}.txt | awk '{print $2}' || echo "0")

    echo "$label,$RPS,$P50,$P99" >> /tmp/performance-results.csv
}

# CSV header
echo "test,rps,p50,p99" > /tmp/performance-results.csv

# Baseline test (no AegisBPF)
if pgrep -f "aegisbpf run" > /dev/null; then
    echo ""
    echo "⚠️  WARNING: AegisBPF is running. Stop it for baseline test."
    echo "Run: sudo pkill -f 'aegisbpf run'"
    exit 1
fi

echo ""
echo "▶ Phase 1: Baseline (without AegisBPF)"
run_test "baseline"

# Start AegisBPF
echo ""
echo "▶ Phase 2: Starting AegisBPF..."
sudo "$BINARY" run --audit > /tmp/aegisbpf-perf-test.log 2>&1 &
DAEMON_PID=$!
sleep 3

if ! ps -p $DAEMON_PID > /dev/null; then
    echo "❌ ERROR: AegisBPF failed to start"
    cat /tmp/aegisbpf-perf-test.log | tail -20
    exit 1
fi

echo "✓ Daemon started (PID: $DAEMON_PID)"

# Apply policy
sudo "$BINARY" policy apply ./config/policy-production.conf || true

# Test with AegisBPF
run_test "with-aegisbpf"

# Stop daemon
sudo pkill -f "aegisbpf run"
sleep 1

# Calculate overhead
echo ""
echo "╔═══════════════════════════════════════════════════╗"
echo "║  Results                                          ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""

python3 <<'PYTHON'
import csv
import sys

try:
    with open('/tmp/performance-results.csv') as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    baseline = rows[0]
    with_aegis = rows[1]

    def calc_overhead(baseline_val, with_aegis_val):
        try:
            b = float(baseline_val.replace(',', ''))
            a = float(with_aegis_val.replace(',', ''))
            return ((a - b) / b) * 100
        except:
            return 0.0

    rps_overhead = calc_overhead(baseline['rps'], with_aegis['rps'])

    print(f"Throughput:")
    print(f"  Baseline RPS:      {baseline['rps']}")
    print(f"  With AegisBPF RPS: {with_aegis['rps']}")
    print(f"  Overhead:          {rps_overhead:+.2f}%")
    print()
    print(f"Latency:")
    print(f"  Baseline p50:      {baseline['p50']}")
    print(f"  With AegisBPF p50: {with_aegis['p50']}")
    print(f"  Baseline p99:      {baseline['p99']}")
    print(f"  With AegisBPF p99: {with_aegis['p99']}")
    print()

    # Pass/fail
    if abs(rps_overhead) < 5:
        print("✅ PASS: Overhead within acceptable range (<5%)")
        sys.exit(0)
    elif abs(rps_overhead) < 10:
        print("⚠️  MARGINAL: Overhead 5-10% - review if acceptable")
        sys.exit(0)
    else:
        print(f"❌ FAIL: Overhead too high ({rps_overhead:.2f}%)")
        sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}")
    sys.exit(1)
PYTHON
