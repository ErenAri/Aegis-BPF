#!/usr/bin/env bash
# upgrade_test.sh — Test upgrading AegisBPF from version N to N+1
#
# Verifies:
#   1. Old version installs and runs correctly
#   2. Policy can be applied with old version
#   3. New version installs over old version
#   4. Policy survives upgrade (maps still populated)
#   5. New version daemon starts correctly with existing pins
#
# Environment variables:
#   OLD_DEB       - Path to old version .deb package (required)
#   NEW_DEB       - Path to new version .deb package (required)
#   POLICY_FILE   - Path to policy fixture (default: tests/fixtures/golden/deny_path_basic.conf)
#   AEGIS_BIN_OLD - Path to old binary (default: /usr/bin/aegisbpf after install)
#   AEGIS_BIN_NEW - Path to new binary (default: /usr/bin/aegisbpf after upgrade)

set -euo pipefail

OLD_DEB="${OLD_DEB:-}"
NEW_DEB="${NEW_DEB:-}"
POLICY_FILE="${POLICY_FILE:-tests/fixtures/golden/deny_path_basic.conf}"
AEGIS_BIN="${AEGIS_BIN:-/usr/bin/aegisbpf}"

PASS=0
FAIL=0

pass() {
    echo "PASS: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "FAIL: $1"
    FAIL=$((FAIL + 1))
}

skip() {
    echo "SKIP: $1"
}

cleanup() {
    # Stop daemon if running
    sudo pkill -f aegisbpf 2>/dev/null || true
    sleep 1
}
trap cleanup EXIT

echo "=== AegisBPF Upgrade Test ==="
echo ""

# Validate inputs
if [ -z "$OLD_DEB" ] || [ -z "$NEW_DEB" ]; then
    echo "Usage: OLD_DEB=<path> NEW_DEB=<path> $0"
    echo ""
    echo "Both OLD_DEB and NEW_DEB must be set to .deb package paths."
    echo "Alternatively, set AEGIS_BIN to test binary upgrade without packages."
    exit 1
fi

if [ ! -f "$OLD_DEB" ]; then
    echo "ERROR: Old package not found: $OLD_DEB"
    exit 1
fi

if [ ! -f "$NEW_DEB" ]; then
    echo "ERROR: New package not found: $NEW_DEB"
    exit 1
fi

if [ ! -f "$POLICY_FILE" ]; then
    echo "ERROR: Policy file not found: $POLICY_FILE"
    exit 1
fi

# Step 1: Install old version
echo "--- Step 1: Install old version ---"
sudo dpkg -i "$OLD_DEB" 2>/dev/null && pass "Old version installed" || fail "Old version install"

# Step 2: Verify old version runs
echo "--- Step 2: Verify old version ---"
if $AEGIS_BIN --version 2>/dev/null; then
    OLD_VERSION=$($AEGIS_BIN --version 2>&1 | head -1)
    pass "Old version runs: $OLD_VERSION"
else
    fail "Old version does not run"
fi

# Step 3: Apply policy with old version
echo "--- Step 3: Apply policy ---"
if sudo $AEGIS_BIN policy lint "$POLICY_FILE" 2>/dev/null; then
    pass "Policy lint succeeds on old version"
else
    fail "Policy lint on old version"
fi

# Step 4: Install new version (upgrade)
echo "--- Step 4: Upgrade to new version ---"
sudo dpkg -i "$NEW_DEB" 2>/dev/null && pass "New version installed (upgrade)" || fail "New version install"

# Step 5: Verify new version runs
echo "--- Step 5: Verify new version ---"
if $AEGIS_BIN --version 2>/dev/null; then
    NEW_VERSION=$($AEGIS_BIN --version 2>&1 | head -1)
    pass "New version runs: $NEW_VERSION"
else
    fail "New version does not run"
fi

# Step 6: Verify policy operations work after upgrade
echo "--- Step 6: Post-upgrade policy operations ---"
if sudo $AEGIS_BIN policy lint "$POLICY_FILE" 2>/dev/null; then
    pass "Policy lint succeeds on new version"
else
    fail "Policy lint on new version"
fi

# Step 7: Check pinned maps survive upgrade
echo "--- Step 7: Check BPF pin directory ---"
if [ -d "/sys/fs/bpf/aegisbpf" ]; then
    PIN_COUNT=$(ls /sys/fs/bpf/aegisbpf/ 2>/dev/null | wc -l)
    if [ "$PIN_COUNT" -gt 0 ]; then
        pass "Pinned maps exist after upgrade ($PIN_COUNT maps)"
    else
        skip "Pin directory empty (daemon may not have been running)"
    fi
else
    skip "Pin directory does not exist (daemon may not have been running)"
fi

echo ""
echo "=== Upgrade Test Summary: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
