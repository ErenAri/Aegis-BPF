#!/usr/bin/env bash
#
# backpressure_saturation.sh — prove AegisBPF enforcement stays SYNCHRONOUS when the
# telemetry channel is saturated. The thesis of an enforcement agent's backpressure
# design: *losing telemetry is acceptable; losing a decision is not.*
#
# The enforcement decision (return -EPERM from the LSM hook) runs in-kernel and must be
# independent of whether the event can be delivered to userspace. This harness forces
# real, sustained telemetry loss and asserts that every access to a denied inode is still
# blocked while the events describing those denials are being dropped.
#
# Mechanism. Under a pure high-rate firehose the userspace consumer keeps up and nothing
# drops (a good robustness signal, but it proves nothing about decoupling because no
# telemetry is lost). So we induce the worst-case operational stall directly: SIGSTOP the
# agent's userspace. Its BPF programs remain attached in-kernel and keep returning -EPERM,
# but the ring buffers stop draining -> they overflow -> aegisbpf_ringbuf_drops_total
# climbs. A separate canary process reads the denied inode throughout and must be denied
# every time. `aegisbpf metrics` reads the pinned maps directly, so drop counters stay
# observable while the daemon is frozen.
#
# PASS iff:
#   * saturation was actually achieved   (drops delta >= MIN_DROPS  -> teeth; else INCONCLUSIVE)
#   * zero canary misses across all phases (no denied read ever succeeded)
#   * the agent survives SIGCONT          (recovers, no crash)
#
# Needs root + BPF-LSM. Self-cleans (always SIGCONT before teardown so a stopped daemon
# can be reaped). Env: BIN, WORKERS, FREEZE_SECONDS, RINGBUF_BYTES, MIN_DROPS,
# CANARY_READS_PER_SAMPLE, OUT_JSON.

set -uo pipefail

BIN="${BIN:-./build/aegisbpf}"
WORKERS="${WORKERS:-48}"
FREEZE_SECONDS="${FREEZE_SECONDS:-6}"
RINGBUF_BYTES="${RINGBUF_BYTES:-4096}"
MIN_DROPS="${MIN_DROPS:-1000}"
CANARY_READS_PER_SAMPLE="${CANARY_READS_PER_SAMPLE:-200}"
OUT_JSON="${OUT_JSON:-}"

die() { echo "[!] $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "must run as root (needs BPF-LSM)"
[[ -x "$BIN" ]] || die "agent not found at $BIN (build first)"
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null || die "BPF-LSM not enabled"

WORK="$(mktemp -d /var/tmp/aegis-bp.XXXXXX)"
TARGET="$WORK/target"
DLOG="$WORK/daemon.log"
echo "backpressure canary target payload" > "$TARGET"
DPID=""
WPIDS=()

cleanup() {
    # A SIGSTOP'd process ignores SIGINT until continued — always CONT first.
    [[ -n "$DPID" ]] && kill -CONT "$DPID" 2>/dev/null || true
    for p in "${WPIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    "$BIN" block del "$TARGET" >/dev/null 2>&1 || true
    [[ -n "$DPID" ]] && { kill -INT "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; } || true
    rm -rf "$WORK"
}
trap cleanup EXIT

m() { "$BIN" metrics 2>/dev/null | awk -v k="$1" '$1==k{print $2; f=1} END{if(!f)print 0}'; }
drops() { m aegisbpf_ringbuf_drops_total; }
blocks() { m aegisbpf_blocks_total; }

# canary_batch <n>: issue n reads of the denied target; echo the count that SUCCEEDED
# (i.e. missed enforcement). 0 == enforcement held for every read.
canary_batch() {
    local n="$1" misses=0 i=0
    while [[ $i -lt $n ]]; do
        if dd if="$TARGET" bs=1 count=1 status=none >/dev/null 2>&1; then misses=$((misses+1)); fi
        i=$((i+1))
    done
    echo "$misses"
}

# --- bring up enforcement --------------------------------------------------
"$BIN" block clear >/dev/null 2>&1 || true
"$BIN" run --enforce --enforce-signal=none --ringbuf-bytes="$RINGBUF_BYTES" >"$DLOG" 2>&1 &
DPID=$!
sleep 2
kill -0 "$DPID" 2>/dev/null || { echo "[!] daemon failed to start:" >&2; cat "$DLOG" >&2; exit 1; }
"$BIN" block add "$TARGET" >/dev/null 2>&1 || die "block add failed"

# --- workload: many processes hammering the denied inode -------------------
for _ in $(seq 1 "$WORKERS"); do
    ( while kill -0 "$DPID" 2>/dev/null; do dd if="$TARGET" bs=1 count=1 status=none >/dev/null 2>&1; done ) &
    WPIDS+=("$!")
done

TOTAL_CANARY_READS=0
TOTAL_CANARY_MISSES=0
add_canary() { TOTAL_CANARY_READS=$((TOTAL_CANARY_READS + $1)); TOTAL_CANARY_MISSES=$((TOTAL_CANARY_MISSES + $2)); }

echo "== backpressure saturation: workers=$WORKERS ringbuf=$RINGBUF_BYTES freeze=${FREEZE_SECONDS}s =="

# Phase A — consumer live: baseline (expect ~no drops, all denied).
sleep 2
DROPS_BASELINE="$(drops)"; BLOCKS_BASELINE="$(blocks)"
MISS_A="$(canary_batch "$CANARY_READS_PER_SAMPLE")"; add_canary "$CANARY_READS_PER_SAMPLE" "$MISS_A"
printf 'A live    drops=%-9s blocks=%-12s canary_misses=%s/%s\n' \
    "$DROPS_BASELINE" "$BLOCKS_BASELINE" "$MISS_A" "$CANARY_READS_PER_SAMPLE"

# Phase B — freeze the consumer: telemetry must be lost, decisions must not.
kill -STOP "$DPID"
METRICS_REACHABLE_FROZEN=0
"$BIN" metrics >/dev/null 2>&1 && METRICS_REACHABLE_FROZEN=1
DROPS_FROZEN_END="$DROPS_BASELINE"
for t in $(seq 1 "$FREEZE_SECONDS"); do
    sleep 1
    DROPS_FROZEN_END="$(drops)"
    MISS_B="$(canary_batch "$CANARY_READS_PER_SAMPLE")"; add_canary "$CANARY_READS_PER_SAMPLE" "$MISS_B"
    printf 'B frozen  drops=%-9s blocks=%-12s canary_misses=%s/%s  (+%ds)\n' \
        "$DROPS_FROZEN_END" "$(blocks)" "$MISS_B" "$CANARY_READS_PER_SAMPLE" "$t"
done

# Phase C — resume: agent must recover, decisions still hold.
kill -CONT "$DPID"
sleep 2
DAEMON_ALIVE=0; kill -0 "$DPID" 2>/dev/null && DAEMON_ALIVE=1
MISS_C="$(canary_batch "$CANARY_READS_PER_SAMPLE")"; add_canary "$CANARY_READS_PER_SAMPLE" "$MISS_C"
DROPS_FINAL="$(drops)"
printf 'C resume  drops=%-9s blocks=%-12s canary_misses=%s/%s  daemon_alive=%s\n' \
    "$DROPS_FINAL" "$(blocks)" "$MISS_C" "$CANARY_READS_PER_SAMPLE" "$DAEMON_ALIVE"

DROPS_DELTA=$((DROPS_FROZEN_END - DROPS_BASELINE))
[[ $DROPS_DELTA -lt 0 ]] && DROPS_DELTA=0
SATURATED=0; [[ $DROPS_DELTA -ge $MIN_DROPS ]] && SATURATED=1

echo
echo "telemetry dropped while frozen (delta): $DROPS_DELTA   canary: $TOTAL_CANARY_MISSES miss / $TOTAL_CANARY_READS reads"

PASS=0
if [[ $SATURATED -eq 1 && $TOTAL_CANARY_MISSES -eq 0 && $DAEMON_ALIVE -eq 1 && $METRICS_REACHABLE_FROZEN -eq 1 ]]; then
    PASS=1
fi

if [[ -n "$OUT_JSON" ]]; then
    python3 - "$OUT_JSON" <<PY
import json, sys
payload = {
    "workers": $WORKERS,
    "ringbuf_bytes": $RINGBUF_BYTES,
    "freeze_seconds": $FREEZE_SECONDS,
    "drops_baseline": $DROPS_BASELINE,
    "drops_frozen_end": $DROPS_FROZEN_END,
    "drops_delta_frozen": $DROPS_DELTA,
    "min_drops_required": $MIN_DROPS,
    "saturation_achieved": bool($SATURATED),
    "metrics_reachable_while_frozen": bool($METRICS_REACHABLE_FROZEN),
    "canary_reads_total": $TOTAL_CANARY_READS,
    "canary_misses_total": $TOTAL_CANARY_MISSES,
    "daemon_survived_resume": bool($DAEMON_ALIVE),
    "pass": bool($PASS),
}
with open(sys.argv[1], "w") as f:
    json.dump(payload, f, separators=(",", ":"))
print("wrote", sys.argv[1])
PY
fi

echo
if [[ $PASS -eq 1 ]]; then
    echo "RESULT: PASS — telemetry saturated ($DROPS_DELTA events dropped), 0/$TOTAL_CANARY_READS decisions lost, agent recovered"
    exit 0
else
    echo "RESULT: FAIL"
    [[ $SATURATED -ne 1 ]] && echo "  - saturation NOT achieved (drops delta $DROPS_DELTA < $MIN_DROPS) — INCONCLUSIVE"
    [[ $TOTAL_CANARY_MISSES -ne 0 ]] && echo "  - $TOTAL_CANARY_MISSES enforcement MISS(es): a denied read succeeded under backpressure"
    [[ $DAEMON_ALIVE -ne 1 ]] && echo "  - agent did NOT survive resume"
    [[ $METRICS_REACHABLE_FROZEN -ne 1 ]] && echo "  - metrics unreadable while frozen"
    exit 1
fi
