#!/usr/bin/env bash
# Concurrency stress test for atomic policy replacement.
#
# Design
# ------
# Two policies are swapped continuously while workers exercise enforcement.
# The policies are chosen so that some rules are IDENTICAL in both:
#
#   /tmp/aegis_always   denied in A and in B   -> must NEVER be readable
#   tcp/4444 egress     denied in A and in B   -> must NEVER connect
#   /tmp/aegis_onlyA    denied only in A
#   /tmp/aegis_onlyB    denied only in B
#
# The always-denied rules are the detector. There is no instant at which a
# correct implementation permits them: before the commit policy A denies them,
# after the commit policy B denies them, and the commit is a single active_slot
# write with no window in between.
#
# A permitted access to an always-denied target therefore means the reload
# exposed a state that is neither A nor B -- either a partially applied
# generation, or the old audit-only reload window. Either is a failure.
#
# /tmp/aegis_onlyA and /tmp/aegis_onlyB are NOT failure detectors: which of
# them is denied legitimately depends on which generation is live when the
# probe runs. They are recorded only to prove both generations really did
# become live during the run (a test where the policy never actually changed
# would prove nothing).
set -u

BIN="${BIN:-./build/aegisbpf}"
DIR="${WORKDIR:-$(mktemp -d)}"
mkdir -p "$DIR"
ITERATIONS="${ITERATIONS:-60}"
WORKERS="${WORKERS:-6}"
RESULTS="$DIR/results"
rm -rf "$RESULTS"; mkdir -p "$RESULTS"

for f in always onlyA onlyB; do echo "content-$f" > "/tmp/aegis_$f"; done

cat > "$DIR/A.conf" <<'PA'
version=6

[deny_path]
/tmp/aegis_always
/tmp/aegis_onlyA

[deny_port]
4444:tcp:egress
PA

cat > "$DIR/B.conf" <<'PB'
version=6

[deny_path]
/tmp/aegis_always
/tmp/aegis_onlyB

[deny_port]
4444:tcp:egress
PB

# --- workers ------------------------------------------------------------
# Each worker probes the always-denied targets in a tight loop and records
# any access that succeeded.
worker() {
    local id="$1"
    local out="$RESULTS/worker-$id"
    local reads=0 violations=0 conns=0 conn_violations=0
    local a_denied=0 b_denied=0
    local deadline=$(( $(date +%s) + ${DURATION:-60} ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        reads=$((reads+1))
        if cat /tmp/aegis_always >/dev/null 2>&1; then
            violations=$((violations+1))
            echo "VIOLATION read /tmp/aegis_always succeeded at $(date +%s.%N)" >> "$out.violations"
        fi
        conns=$((conns+1))
        if python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(1)
try:
    s.connect(('127.0.0.1',4444)); sys.exit(0)
except PermissionError: sys.exit(1)
except Exception: sys.exit(2)
" 2>/dev/null; then
            conn_violations=$((conn_violations+1))
            echo "VIOLATION connect tcp/4444 succeeded at $(date +%s.%N)" >> "$out.violations"
        fi
    done
    echo "$reads $violations $conns $conn_violations" > "$out.counts"
}

# --- observer: proves both generations actually went live ---------------
observer() {
    local out="$RESULTS/observer"
    local sawA=0 sawB=0
    local deadline=$(( $(date +%s) + ${DURATION:-60} ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        a_denied=0; b_denied=0
        cat /tmp/aegis_onlyA >/dev/null 2>&1 || a_denied=1
        cat /tmp/aegis_onlyB >/dev/null 2>&1 || b_denied=1
        [ "$a_denied" = 1 ] && [ "$b_denied" = 0 ] && sawA=$((sawA+1))
        [ "$b_denied" = 1 ] && [ "$a_denied" = 0 ] && sawB=$((sawB+1))
    done
    echo "$sawA $sawB" > "$out.counts"
}

# --- listener for the port probe ----------------------------------------
python3 -c "
import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',4444)); s.listen(64)
time.sleep(${DURATION:-60}+15)
" &
LISTENER=$!
sleep 1

# Establish a known generation BEFORE any worker starts.
#
# Without this the workers race the first `policy apply`: a daemon that has not
# been given a policy yet denies nothing, and every probe in that window looks
# like a violation. That is correct behaviour, not a torn generation, so the
# run must not begin until a policy is actually live.
if ! sudo "$BIN" policy apply "$DIR/A.conf" >/dev/null 2>>"$RESULTS/apply.err"; then
    echo "FATAL: could not apply the initial policy"; exit 2
fi
for _ in $(seq 1 50); do
    cat /tmp/aegis_always >/dev/null 2>&1 || break
    sleep 0.1
done
if cat /tmp/aegis_always >/dev/null 2>&1; then
    echo "FATAL: initial policy applied but /tmp/aegis_always is still readable;"
    echo "       is the agent running in enforce mode?"
    exit 2
fi

echo "starting $WORKERS workers + observer for ${DURATION:-60}s, reloading every iteration"
for i in $(seq 1 "$WORKERS"); do worker "$i" & done
observer &

# --- reloader: swap A <-> B as fast as apply allows ---------------------
applied=0; failed=0
deadline=$(( $(date +%s) + ${DURATION:-60} ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    for p in A B; do
        if sudo "$BIN" policy apply "$DIR/$p.conf" >/dev/null 2>>"$RESULTS/apply.err"; then
            applied=$((applied+1))
        else
            failed=$((failed+1))
        fi
    done
done
echo "$applied $failed" > "$RESULTS/reload.counts"

wait $(jobs -p | grep -v "$LISTENER") 2>/dev/null
kill $LISTENER 2>/dev/null
wait 2>/dev/null

# --- report --------------------------------------------------------------
tr=0; tv=0; tc=0; tcv=0
for f in "$RESULTS"/worker-*.counts; do
    read -r r v c cv < "$f"; tr=$((tr+r)); tv=$((tv+v)); tc=$((tc+c)); tcv=$((tcv+cv))
done
read -r applied failed < "$RESULTS/reload.counts"
read -r sawA sawB < "$RESULTS/observer.counts" 2>/dev/null || { sawA=0; sawB=0; }

echo
echo "===== ATOMIC POLICY SWAP STRESS RESULTS ====="
echo "policy reloads applied           : $applied  (failed: $failed)"
echo "generation A observed live       : $sawA"
echo "generation B observed live       : $sawB"
echo "always-denied file read attempts : $tr   VIOLATIONS: $tv"
echo "always-denied connect attempts   : $tc   VIOLATIONS: $tcv"
echo
if [ "$applied" -lt 4 ]; then echo "INCONCLUSIVE: too few reloads"; exit 2; fi
if [ "$sawA" -eq 0 ] || [ "$sawB" -eq 0 ]; then
    echo "INCONCLUSIVE: both generations were not observed live"; exit 2
fi
if [ $((tv+tcv)) -ne 0 ]; then
    echo "FAIL: $((tv+tcv)) accesses succeeded that BOTH policies deny"
    cat "$RESULTS"/worker-*.violations 2>/dev/null | head -20
    exit 1
fi
echo "PASS: no access to an always-denied target succeeded across $applied reloads"
