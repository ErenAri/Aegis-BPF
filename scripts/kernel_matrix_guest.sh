#!/bin/bash
# Runs the full atomic-swap validation inside a virtme-ng guest.
# $1 = output directory on the shared rwdir
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$1"
mkdir -p "$OUT"
exec > "$OUT/log.txt" 2>&1

echo "kernel=$(uname -r)"
echo "uid=$(id -u)"
mount -t securityfs none /sys/kernel/security 2>/dev/null
echo "lsm=$(cat /sys/kernel/security/lsm 2>/dev/null)"
mount -t bpf bpffs /sys/fs/bpf 2>/dev/null
mkdir -p /var/lib/aegisbpf
rm -rf /sys/fs/bpf/aegisbpf
rm -f /var/lib/aegisbpf/policy.applied* /var/lib/aegisbpf/deny.db /var/lib/aegisbpf/runtime_rules.*

cd "$REPO" || exit 1

echo "=== SECTION:validate ==="
AEGIS_VALIDATE_DESTRUCTIVE=1 BIN=$REPO/build/aegisbpf OBJ=$REPO/build/aegis.bpf.o \
    timeout 300 bash scripts/validate_atomic_swap.sh
echo "validate_rc=$?"

echo "=== SECTION:verifier ==="
if cc -O2 -o /tmp/vstat "$REPO/tools/verifier_stats.c" -lbpf 2>/dev/null; then
    /tmp/vstat "$REPO/build/aegis.bpf.o" 2>/dev/null | tail -3
else
    echo "verifier_stats_build=failed"
fi

echo "=== SECTION:stress ==="
rm -rf /sys/fs/bpf/aegisbpf
rm -f /var/lib/aegisbpf/policy.applied* /var/lib/aegisbpf/deny.db /var/lib/aegisbpf/runtime_rules.*
"$REPO/build/aegisbpf" run --enforce --enforce-signal=none --allow-unsigned-bpf \
    --log-level=warn > /tmp/daemon.log 2>&1 &
for _ in $(seq 1 60); do grep -q "Agent started" /tmp/daemon.log 2>/dev/null && break; sleep 0.5; done
if grep -q "Agent started" /tmp/daemon.log 2>/dev/null; then
    WORKDIR=/tmp/swap DURATION="${STRESS_DURATION:-30}" WORKERS=4 \
        timeout 400 bash scripts/policy_swap_stress.sh
    echo "stress_rc=$?"
    echo "=== SECTION:crash ==="
    WORKDIR=/tmp/swap ROUNDS="${CRASH_ROUNDS:-20}" timeout 400 bash scripts/policy_swap_crash.sh 2>&1 \
        | grep -vE "Killed"
    echo "crash_rc=$?"
else
    echo "stress_rc=SKIP_daemon_did_not_start"
    tail -20 /tmp/daemon.log
    echo "crash_rc=SKIP"
fi

echo "=== SECTION:leak ==="
RELOADS="${LEAK_RELOADS:-150}" WORKDIR=/tmp/leak timeout 600 bash scripts/policy_swap_leak.sh
echo "leak_rc=$?"

pkill -9 -x aegisbpf 2>/dev/null
echo "=== SECTION:end ==="
echo "ALL_DONE"
sync
