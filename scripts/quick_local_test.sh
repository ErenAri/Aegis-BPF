#!/usr/bin/env bash
#
# AegisBPF Quick Local Test
# Simple validation on local PC (i9-13900H)

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

BINARY="${BINARY:-./build/aegisbpf}"
TEST_DURATION=${TEST_DURATION:-30}

log_section() {
    echo -e "\n${CYAN}═══ $1 ═══${NC}"
}

log_pass() { echo -e "${GREEN}✓${NC} $1"; }
log_fail() { echo -e "${RED}✗${NC} $1"; }
log_info() { echo -e "  $1"; }

cleanup() {
    log_section "Cleanup"
    sudo pkill -f "aegisbpf run" 2>/dev/null || true
    sleep 1
    sudo "$BINARY" block clear 2>/dev/null || true
    log_pass "Cleanup complete"
}

trap cleanup EXIT

echo "╔═══════════════════════════════════════════╗"
echo "║  AegisBPF Quick Test (i9-13900H)         ║"
echo "╚═══════════════════════════════════════════╝"
echo

# Test 1: Binary check
log_section "Binary Check"
if [ -f "$BINARY" ]; then
    SIZE=$(du -h "$BINARY" | cut -f1)
    log_pass "Binary found ($SIZE)"
else
    log_fail "Binary not found: $BINARY"
    exit 1
fi

# Test 2: Health check (needs sudo)
log_section "Health Check"
if sudo "$BINARY" health 2>&1 | grep -q "Health check passed"; then
    log_pass "System health check passed"
else
    log_info "Health check output:"
    sudo "$BINARY" health 2>&1 | head -10
fi

# Test 3: Create test policy
log_section "Test Policy"
TEST_POLICY="/tmp/aegis-test-policy.yml"
cat > "$TEST_POLICY" <<'EOF'
version: 1
deny:
  paths:
    - /tmp/aegis-blocked-file.txt
EOF
log_pass "Test policy created"

if "$BINARY" policy validate "$TEST_POLICY" 2>&1 | grep -q "valid"; then
    log_pass "Policy validation passed"
else
    log_fail "Policy validation failed"
fi

# Test 4: Start in audit mode
log_section "Audit Mode Test ($TEST_DURATION seconds)"
log_info "Starting daemon in audit mode..."

sudo "$BINARY" run --audit --log=stdout --log-level=info >/tmp/aegis-audit.log 2>&1 &
DAEMON_PID=$!

sleep 3

if ps -p $DAEMON_PID >/dev/null 2>&1; then
    log_pass "Daemon started (PID: $DAEMON_PID)"
else
    log_fail "Daemon failed to start"
    cat /tmp/aegis-audit.log | tail -20
    exit 1
fi

# Test 5: Apply policy
log_section "Apply Policy"
if sudo "$BINARY" policy apply "$TEST_POLICY" 2>&1; then
    log_pass "Policy applied successfully"
else
    log_fail "Policy application failed"
fi

# Test 6: Generate activity
log_section "Generate Test Activity"
log_info "Creating test file..."
echo "test content" > /tmp/aegis-blocked-file.txt

log_info "Accessing file (should be logged in audit mode)..."
for i in {1..5}; do
    cat /tmp/aegis-blocked-file.txt >/dev/null 2>&1 || true
    sleep 1
done

log_pass "Test activity generated"

# Test 7: Check statistics
log_section "Statistics"
if sudo "$BINARY" stats 2>&1 | tee /tmp/aegis-stats.txt; then
    log_pass "Statistics collected"

    BLOCKS=$(grep "Total blocks:" /tmp/aegis-stats.txt | awk '{print $3}' || echo "0")
    DROPS=$(grep "Ringbuf drops:" /tmp/aegis-stats.txt | awk '{print $3}' || echo "0")

    log_info "Total blocks: $BLOCKS"
    log_info "Ringbuf drops: $DROPS"

    if [ "${DROPS}" = "0" ]; then
        log_pass "No ring buffer drops"
    fi
else
    log_fail "Failed to get statistics"
fi

# Test 8: Check metrics
log_section "Metrics"
if sudo "$BINARY" metrics 2>&1 > /tmp/aegis-metrics.txt; then
    METRIC_COUNT=$(grep -c "^aegisbpf_" /tmp/aegis-metrics.txt || echo "0")
    log_pass "Metrics exported ($METRIC_COUNT metrics)"

    log_info "Sample metrics:"
    grep "aegisbpf_blocks_total\|aegisbpf_map_utilization" /tmp/aegis-metrics.txt | head -5 || true
else
    log_fail "Failed to export metrics"
fi

# Test 9: Resource usage
log_section "Resource Usage"
if ps -p $DAEMON_PID >/dev/null 2>&1; then
    CPU=$(ps -p $DAEMON_PID -o %cpu= | awk '{print $1}' || echo "0")
    MEM=$(ps -p $DAEMON_PID -o rss= | awk '{printf "%.1f", $1/1024}' || echo "0")

    log_info "CPU: ${CPU}%"
    log_info "Memory: ${MEM} MB"

    if (( $(echo "$CPU < 10" | bc -l) )); then
        log_pass "CPU usage acceptable"
    else
        log_fail "High CPU: ${CPU}%"
    fi

    if (( $(echo "$MEM < 100" | bc -l) )); then
        log_pass "Memory usage acceptable"
    else
        log_fail "High memory: ${MEM}MB"
    fi
else
    log_info "Daemon not running"
fi

# Summary
log_section "Test Complete"
echo
log_info "Logs saved to:"
log_info "  /tmp/aegis-audit.log     - Daemon log"
log_info "  /tmp/aegis-stats.txt     - Statistics"
log_info "  /tmp/aegis-metrics.txt   - Prometheus metrics"
echo
log_pass "Quick test completed successfully!"
echo
log_info "Next steps:"
log_info "  1. Review logs for any issues"
log_info "  2. Run extended test: sudo TEST_DURATION=600 $0"
log_info "  3. Try enforcement mode: sudo $BINARY run --enforce"
echo
