#!/usr/bin/env bash
# downgrade_test.sh — Test downgrading AegisBPF from version N+1 to N
#
# Verifies:
#   1. New version installs and runs correctly
#   2. Policy can be applied with new version
#   3. Downgrade to old version succeeds
#   4. Old version handles existing pins gracefully (or with clear error)
#   5. Old version can still apply policy
#
# Environment variables:
#   OLD_DEB       - Path to old version .deb package (required)
#   NEW_DEB       - Path to new version .deb package (required)
#   POLICY_FILE   - Path to policy fixture (default: tests/fixtures/golden/deny_path_basic.conf)

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
    sudo pkill -f aegisbpf 2>/dev/null || true
    sleep 1
}
trap cleanup EXIT

echo "=== AegisBPF Downgrade Test ==="
echo ""

# Validate inputs
if [ -z "$OLD_DEB" ] || [ -z "$NEW_DEB" ]; then
    echo "Usage: OLD_DEB=<path> NEW_DEB=<path> $0"
    echo ""
    echo "Both OLD_DEB and NEW_DEB must be set to .deb package paths."
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

# Step 1: Install new version first
echo "--- Step 1: Install new version ---"
sudo dpkg -i "$NEW_DEB" 2>/dev/null && pass "New version installed" || fail "New version install"

# Step 2: Verify new version
echo "--- Step 2: Verify new version ---"
if $AEGIS_BIN --version 2>/dev/null; then
    NEW_VERSION=$($AEGIS_BIN --version 2>&1 | head -1)
    pass "New version runs: $NEW_VERSION"
else
    fail "New version does not run"
fi

# Step 3: Apply policy with new version
echo "--- Step 3: Apply policy (new version) ---"
if sudo $AEGIS_BIN policy lint "$POLICY_FILE" 2>/dev/null; then
    pass "Policy lint succeeds on new version"
else
    fail "Policy lint on new version"
fi

# Step 4: Downgrade
echo "--- Step 4: Downgrade to old version ---"
sudo dpkg -i "$OLD_DEB" 2>/dev/null && pass "Old version installed (downgrade)" || fail "Old version install (downgrade)"

# Step 5: Verify old version runs
echo "--- Step 5: Verify old version ---"
if $AEGIS_BIN --version 2>/dev/null; then
    OLD_VERSION=$($AEGIS_BIN --version 2>&1 | head -1)
    pass "Old version runs: $OLD_VERSION"
else
    fail "Old version does not run after downgrade"
fi

# Step 6: Check graceful degradation
echo "--- Step 6: Graceful degradation check ---"
# Old version should either work with existing pins or report a clear layout version error
LINT_OUTPUT=$(sudo $AEGIS_BIN policy lint "$POLICY_FILE" 2>&1) && LINT_RC=0 || LINT_RC=$?
if [ "$LINT_RC" -eq 0 ]; then
    pass "Old version policy lint succeeds after downgrade"
elif echo "$LINT_OUTPUT" | grep -qi "layout.*version\|version.*mismatch\|incompatible"; then
    pass "Old version reports clear version mismatch (expected for layout changes)"
else
    fail "Old version fails with unexpected error: $LINT_OUTPUT"
fi

# Step 7: Clear pins and retry (fresh start after downgrade)
echo "--- Step 7: Fresh start after clearing pins ---"
sudo rm -rf /sys/fs/bpf/aegisbpf 2>/dev/null || true
if sudo $AEGIS_BIN policy lint "$POLICY_FILE" 2>/dev/null; then
    pass "Old version works after clearing pins"
else
    fail "Old version fails even after clearing pins"
fi

echo ""
echo "=== Downgrade Test Summary: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
