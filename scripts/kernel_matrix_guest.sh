#!/bin/bash
# Atomic-swap validation, executed INSIDE a kernel-matrix VM.
#
# Every phase runs under its own watchdog. A phase that stalls is recorded as
# TIMEOUT with the diagnostics needed to say where, rather than hanging the
# run: the previous version of this harness produced hangs that could only be
# ended by killing the VM, which destroyed the evidence along with the stall.
#
# Writes human output to $OUT/log.txt and a machine-readable summary to
# $OUT/result.json.
set -uo pipefail

OUT="${1:?usage: kernel_matrix_guest.sh <output-dir>}"
REPO="${AEGIS_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
mkdir -p "$OUT"
exec > "$OUT/log.txt" 2>&1

# Per-phase budgets. Generous enough for a slow VM, short enough that a stall
# is reported the same day.
T_VALIDATE="${T_VALIDATE:-600}"
T_STRESS="${T_STRESS:-300}"
T_CRASH="${T_CRASH:-300}"
T_LEAK="${T_LEAK:-600}"
STRESS_DURATION="${STRESS_DURATION:-30}"
CRASH_ROUNDS="${CRASH_ROUNDS:-20}"
LEAK_RELOADS="${LEAK_RELOADS:-150}"

PINDIR=/sys/fs/bpf/aegisbpf
DAEMON_PID=""

# --- diagnostics ----------------------------------------------------------
# Captured before teardown so a TIMEOUT says what the system was doing, not
# merely that it stopped responding.
capture_diagnostics() {
    local stage="$1"
    local dest="$OUT/diag-$stage"
    mkdir -p "$dest"
    ps -efH             > "$dest/process-tree.txt"    2>&1
    dmesg | tail -100   > "$dest/kernel-log.txt"      2>&1
    cp /tmp/daemon.log    "$dest/daemon.log"          2>/dev/null
    cp /tmp/apply.err     "$dest/apply.err"           2>/dev/null
    "$PROBE" active-slot  > "$dest/active-slot.txt"   2>&1
    "$PROBE" generations  > "$dest/generations.txt"   2>&1
    "$PROBE" map-count    > "$dest/map-count.txt"     2>&1
    ls -la "$PINDIR"      > "$dest/pins.txt"          2>&1
    # What each of our processes is blocked on, which is the difference
    # between a deadlock and a slow loop.
    for p in $(pgrep -x aegisbpf) $(pgrep -f policy_swap) ; do
        {
            echo "== pid $p =="
            cat "/proc/$p/cmdline" 2>/dev/null | tr '\0' ' '; echo
            cat "/proc/$p/stack"   2>/dev/null
            cat "/proc/$p/wchan"   2>/dev/null; echo
            cat "/proc/$p/status"  2>/dev/null | grep -E "State|Threads"
        } >> "$dest/blocked.txt" 2>&1
    done
    echo "  diagnostics: $dest"
}

# Only ever stops what this script started.
cleanup() {
    [ -n "$DAEMON_PID" ] && kill -9 "$DAEMON_PID" 2>/dev/null
    pkill -9 -f "policy_swap_" 2>/dev/null
    return 0
}
trap cleanup EXIT INT TERM

run_phase() {   # run_phase <name> <timeout> <command...>
    local name="$1" budget="$2"; shift 2
    local start=$SECONDS
    echo "=== SECTION:$name ==="
    timeout --signal=TERM --kill-after=20 "$budget" "$@"
    local rc=$?
    local elapsed=$(( SECONDS - start ))
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        echo "TIMEOUT(stage=$name, kernel=$(uname -r), budget=${budget}s)"
        capture_diagnostics "$name"
        rc=124
    fi
    echo "${name}_rc=$rc"
    echo "${name}_seconds=$elapsed"
    return $rc
}

start_daemon() {
    rm -rf "$PINDIR"
    rm -f /var/lib/aegisbpf/policy.applied* /var/lib/aegisbpf/deny.db \
          /var/lib/aegisbpf/runtime_rules.*
    "$REPO/build/aegisbpf" run --enforce --enforce-signal=none \
        --allow-unsigned-bpf --log-level=info > /tmp/daemon.log 2>&1 &
    DAEMON_PID=$!
    for _ in $(seq 1 120); do
        grep -q "Agent started" /tmp/daemon.log 2>/dev/null && return 0
        kill -0 "$DAEMON_PID" 2>/dev/null || return 1
        sleep 0.5
    done
    return 1
}

# --- environment ----------------------------------------------------------
mount -t securityfs none /sys/kernel/security 2>/dev/null
mount -t bpf bpffs /sys/fs/bpf 2>/dev/null
mkdir -p /var/lib/aegisbpf
cd "$REPO" || exit 1

KERNEL="$(uname -r)"
DISTRO="$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")"
LSM="$(cat /sys/kernel/security/lsm 2>/dev/null)"
echo "kernel=$KERNEL"
echo "uname_a=$(uname -a)"
echo "distro=$DISTRO"
echo "lsm=$LSM"
echo "uid=$(id -u)"

PROBE=/tmp/slot_probe
cc -O2 -o "$PROBE" "$REPO/tools/slot_probe.c" -lbpf 2>/dev/null || PROBE=/bin/false

# --- phases ---------------------------------------------------------------
AEGIS_VALIDATE_DESTRUCTIVE=1 BIN="$REPO/build/aegisbpf" OBJ="$REPO/build/aegis.bpf.o" \
    run_phase validate "$T_VALIDATE" bash scripts/validate_atomic_swap.sh
VALIDATE_RC=$?

echo "=== SECTION:verifier ==="
if cc -O2 -o /tmp/vstat "$REPO/tools/verifier_stats.c" -lbpf 2>/dev/null; then
    /tmp/vstat "$REPO/build/aegis.bpf.o" 2>/dev/null > "$OUT/verifier.csv"
    echo "verifier_worst=$(grep -v '^TOTAL\|^program' "$OUT/verifier.csv" | sort -t, -k2 -rn | head -1)"
    grep '^TOTAL' "$OUT/verifier.csv"
fi

STRESS_RC=99; CRASH_RC=99
if start_daemon; then
    # The env(1) prefix is what the test actually reads; a shell-level prefix on
    # run_phase would only reach run_phase itself, not the command it execs.
    run_phase stress "$T_STRESS" \
        env DURATION="$STRESS_DURATION" WORKERS=4 WORKDIR=/tmp/swap \
        bash scripts/policy_swap_stress.sh
    STRESS_RC=$?
    run_phase crash "$T_CRASH" \
        env ROUNDS="$CRASH_ROUNDS" WORKDIR=/tmp/swap bash scripts/policy_swap_crash.sh
    CRASH_RC=$?
else
    echo "=== SECTION:stress ==="
    echo "stress_rc=98  # daemon did not start"
    tail -20 /tmp/daemon.log
fi

run_phase leak "$T_LEAK" env RELOADS="$LEAK_RELOADS" WORKDIR=/tmp/leak \
    bash scripts/policy_swap_leak.sh
LEAK_RC=$?

cleanup

# --- machine-readable summary --------------------------------------------
L="$OUT/log.txt"
rel() { grep -aoE "$1" "$L" | tail -1; }
RELOADS=$(grep -aoE "policy reloads applied *: *[0-9]+" "$L" | grep -oE "[0-9]+$" | tail -1)
PROBES=$(grep -aoE "always-denied file read attempts *: *[0-9]+" "$L" | grep -oE "[0-9]+" | tail -1)
VIOL=$(grep -aoE "VIOLATIONS: [0-9]+" "$L" | awk '{s+=$2} END{print s+0}')
COH=$(grep -aoE "coherent generations: [0-9]+/[0-9]+" "$L" | tail -1 | awk '{print $3}')
TORN=$(grep -aoE "torn: [0-9]+" "$L" | tail -1 | grep -oE "[0-9]+")
VTOTAL=$(grep -a '^TOTAL' "$OUT/verifier.csv" 2>/dev/null | cut -d, -f2)
VPEAK=$(grep -a '^TOTAL' "$OUT/verifier.csv" 2>/dev/null | cut -d, -f4)
st() { [ "$1" = 0 ] && echo pass || { [ "$1" = 124 ] && echo timeout || echo fail; }; }

cat > "$OUT/result.json" <<JSON
{
  "kernel": "$KERNEL",
  "uname": "$(uname -a)",
  "distro": "$DISTRO",
  "bpf_lsm": $(echo "$LSM" | grep -qw bpf && echo true || echo false),
  "lsm": "$LSM",
  "validation": "$(st $VALIDATE_RC)",
  "stress": { "status": "$(st $STRESS_RC)", "reloads": ${RELOADS:-0}, "probes": ${PROBES:-0}, "violations": ${VIOL:-0} },
  "crash": { "status": "$(st $CRASH_RC)", "rounds": "${COH:-n/a}", "torn": ${TORN:-0} },
  "leak": "$(st $LEAK_RC)",
  "verifier": { "processed_insns": ${VTOTAL:-0}, "peak_states": ${VPEAK:-0} }
}
JSON
echo "=== SECTION:end ==="
cat "$OUT/result.json"
echo "ALL_DONE"
sync
