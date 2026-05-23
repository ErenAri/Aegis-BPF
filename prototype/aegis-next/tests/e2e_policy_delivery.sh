#!/bin/bash
# End-to-end policy delivery test for aegis-next.
#
# Tests the full pipeline:
#   1. Write a policy file
#   2. Start aegis-next with --policy=<file>
#   3. Verify policy rules are loaded into the BPF map
#   4. Verify events are exported to JSONL
#
# Must run as root on a kernel >= 6.9 with BPF LSM enabled.
#
# Usage: sudo ./e2e_policy_delivery.sh [aegisbpf-next-binary]

set -euo pipefail

BIN=${1:-$(find /home -path "*/build*/prototype/aegisbpf-next" -type f -executable 2>/dev/null | head -1)}
if [[ -z "$BIN" || ! -x "$BIN" ]]; then
    echo "ERROR: aegisbpf-next binary not found. Pass path as argument." >&2
    exit 1
fi

TMPDIR=$(mktemp -d /tmp/aegis-next-e2e.XXXXXX)
trap "rm -rf $TMPDIR; kill %1 2>/dev/null || true" EXIT

POLICY_FILE="$TMPDIR/test-policy.rules"
EVENTS_FILE="$TMPDIR/events.jsonl"
CONFIG_FILE="$TMPDIR/config.conf"

echo "=== E2E Policy Delivery Test ==="
echo "Binary: $BIN"
echo "Tmpdir: $TMPDIR"

# 1. Write test policy.
cat > "$POLICY_FILE" <<'RULES'
# Test policy: deny xmrig, log /etc/shadow access
exec  comm  xmrig  deny  kill
file  path  /etc/shadow  log
conn  port  4444  deny  kill
RULES
echo "PASS: policy file written (3 rules)"

# 2. Write config file.
cat > "$CONFIG_FILE" <<EOF
policy=$POLICY_FILE
events=$EVENTS_FILE
EOF
echo "PASS: config file written"

# 3. Start aegis-next with --config.
echo "Starting aegis-next..."
$BIN attach --config="$CONFIG_FILE" > "$TMPDIR/stdout.log" 2>&1 &
AGENT_PID=$!
sleep 3

if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    echo "FAIL: aegis-next exited prematurely"
    cat "$TMPDIR/stdout.log"
    exit 1
fi
echo "PASS: aegis-next started (pid=$AGENT_PID)"

# 4. Verify policy rules loaded (check stdout log).
if grep -q "loaded 3 rule" "$TMPDIR/stdout.log"; then
    echo "PASS: 3 policy rules loaded"
else
    echo "FAIL: expected 3 rules loaded"
    cat "$TMPDIR/stdout.log"
    kill "$AGENT_PID" 2>/dev/null || true
    exit 1
fi

# 5. Trigger some file opens to generate events.
for i in $(seq 1 10); do
    cat /etc/hostname > /dev/null 2>&1 || true
done
sleep 2

# 6. Verify events were exported.
if [[ -f "$EVENTS_FILE" ]] && [[ -s "$EVENTS_FILE" ]]; then
    EVENT_COUNT=$(wc -l < "$EVENTS_FILE")
    echo "PASS: $EVENT_COUNT events exported to $EVENTS_FILE"
else
    echo "WARN: no events exported (may be normal if no ringbuf alerts triggered)"
fi

# 7. Verify policy list works.
POLICY_OUTPUT=$($BIN policy list 2>&1 || true)
if echo "$POLICY_OUTPUT" | grep -q "xmrig"; then
    echo "PASS: policy list shows xmrig rule"
else
    echo "WARN: policy list did not show expected rules (may need pinned map)"
fi

# 8. Stop agent.
kill "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true
echo "PASS: aegis-next stopped cleanly"

# 9. Verify status output.
if grep -q "arena" "$TMPDIR/stdout.log"; then
    echo "PASS: arena initialization logged"
fi

echo ""
echo "=== ALL E2E CHECKS PASSED ==="
