#!/usr/bin/env bash
# Run the atomic-swap validation across supported kernel families, each in its
# own virtme-ng VM booted with BPF-LSM enabled.
#
# Every invocation gets a fresh run directory. Nothing is shared between runs
# and nothing is reused from a previous one: an earlier version of this harness
# shared one output directory across concurrent VMs, which interleaved their
# results and produced rows that looked like product failures.
#
# Needs only KVM, so the same command runs on a laptop and on any runner that
# can nest virtualization.
#
# Env:
#   KERNELS    space-separated labels to run (default: all)
#   RUNS       repetitions per kernel (default: 1)
#   RUN_ROOT   base directory (default: /tmp/aegis-kernel-matrix)
#   BOOT_TIMEOUT  seconds to allow for a VM (default: 1800)
#
# Exit: 0 if every requested run passed, 1 otherwise, 2 on missing prereqs.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ROOT="${RUN_ROOT:-/tmp/aegis-kernel-matrix}"
RUN_ID="$(date +%Y%m%dT%H%M%S)-$$"
RUN_DIR="$RUN_ROOT/$RUN_ID"
KCACHE="$RUN_ROOT/kernels"          # images are immutable; cache is safe to share
LOCK="$RUN_ROOT/.vm.lock"
LOCK_TIMEOUT="${LOCK_TIMEOUT:-2400}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-1800}"
RUNS="${RUNS:-1}"
mkdir -p "$RUN_DIR" "$KCACHE"

command -v vng  >/dev/null 2>&1 || { echo "virtme-ng (vng) not installed"; exit 2; }
command -v script >/dev/null 2>&1 || { echo "util-linux 'script' not installed"; exit 2; }
[ -e /dev/kvm ] || { echo "/dev/kvm not available"; exit 2; }
[ -x "$REPO/build/aegisbpf" ] || { echo "build/aegisbpf missing; build first"; exit 2; }

# Only ever tear down VMs this run started.
OUR_VMS=()
cleanup() {
    for p in "${OUR_VMS[@]:-}"; do
        [ -n "$p" ] && kill -9 "$p" 2>/dev/null
    done
    return 0
}
trap cleanup EXIT INT TERM

# label|kernel-image-url|modules-url|vmlinuz-path-within
# Ubuntu/Debian ship 9p, which virtme-ng needs to share the host rootfs.
# RHEL-family kernels build no 9p at all and cannot be run this way; they are
# covered by scripts/rhel_matrix_vm.sh instead.
read -r -d '' KERNEL_TABLE <<'TABLE'
mainline-5.14|https://kernel.ubuntu.com/mainline/v5.14.21/amd64/linux-image-unsigned-5.14.21-051421-generic_5.14.21-051421.202111210831_amd64.deb|https://kernel.ubuntu.com/mainline/v5.14.21/amd64/linux-modules-5.14.21-051421-generic_5.14.21-051421.202111210831_amd64.deb|boot/vmlinuz-5.14.21-051421-generic
ubuntu-22.04-5.15|http://archive.ubuntu.com/ubuntu/pool/main/l/linux-signed/linux-image-5.15.0-131-generic_5.15.0-131.141_amd64.deb|http://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-modules-5.15.0-131-generic_5.15.0-131.141_amd64.deb|boot/vmlinuz-5.15.0-131-generic
debian-12-6.1|http://deb.debian.org/debian/pool/main/l/linux/linux-image-6.1.0-50-amd64-unsigned_6.1.176-1_amd64.deb||boot/vmlinuz-6.1.0-50-amd64
mainline-6.5|https://kernel.ubuntu.com/mainline/v6.5/amd64/linux-image-unsigned-6.5.0-060500-generic_6.5.0-060500.202308271831_amd64.deb|https://kernel.ubuntu.com/mainline/v6.5/amd64/linux-modules-6.5.0-060500-generic_6.5.0-060500.202308271831_amd64.deb|boot/vmlinuz-6.5.0-060500-generic
ubuntu-24.04-6.8|http://archive.ubuntu.com/ubuntu/pool/main/l/linux-signed/linux-image-6.8.0-71-generic_6.8.0-71.71_amd64.deb|http://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-modules-6.8.0-71-generic_6.8.0-71.71_amd64.deb|boot/vmlinuz-6.8.0-71-generic
TABLE

fetch_kernel() {
    local label="$1" img="$2" mods="$3" rel="$4" dir="$KCACHE/$label"
    [ -f "$dir/$rel" ] && { echo "$dir/$rel"; return 0; }
    mkdir -p "$dir"
    curl -fsSL -o "$dir/img.deb" "$img" >/dev/null 2>&1 || return 1
    dpkg-deb -x "$dir/img.deb" "$dir" || return 1
    if [ -n "$mods" ]; then
        curl -fsSL -o "$dir/mods.deb" "$mods" >/dev/null 2>&1 || return 1
        dpkg-deb -x "$dir/mods.deb" "$dir" || return 1
    fi
    [ -f "$dir/$rel" ] || return 1
    echo "$dir/$rel"
}

run_one() {   # run_one <label> <kernel-image> <attempt>
    local label="$1" kimg="$2" attempt="$3"
    local out="$RUN_DIR/${label}-run${attempt}"
    mkdir -p "$out"

    # One VM at a time. virtme-ng shares the invoking user's rootfs, so two
    # concurrent guests writing /var/lib/aegisbpf would corrupt each other's
    # results. Fail loudly rather than wait forever.
    exec {lockfd}>"$LOCK"
    if ! flock -w "$LOCK_TIMEOUT" "$lockfd"; then
        echo "  $label run$attempt: LOCK-TIMEOUT after ${LOCK_TIMEOUT}s (held by: $(cat "$LOCK.owner" 2>/dev/null || echo unknown))"
        exec {lockfd}>&-
        return 1
    fi
    echo "$$ $label run$attempt $(date -Is)" > "$LOCK.owner"

    # </dev/null is load-bearing. script(1) and qemu both read stdin, and the
    # caller's stdin is the kernel table this loop is reading: without it the
    # first VM swallows every remaining line and the matrix silently runs one
    # kernel and reports success for the whole selection.
    local start=$SECONDS
    script -qec "vng --rwdir=$out --memory 4G --cpus 4 --run $kimg \
        --append 'lsm=capability,bpf' \
        -- env AEGIS_REPO=$REPO $REPO/scripts/kernel_matrix_guest.sh $out" \
        /dev/null < /dev/null > "$out/console.txt" 2>&1 &
    local vm=$!
    OUR_VMS+=("$vm")

    # Watchdog: a VM that never finishes must not hang the matrix.
    local waited=0
    while kill -0 "$vm" 2>/dev/null; do
        sleep 5; waited=$((waited+5))
        if [ "$waited" -ge "$BOOT_TIMEOUT" ]; then
            echo "  $label run$attempt: VM-TIMEOUT after ${waited}s; console tail:"
            tail -5 "$out/console.txt" 2>/dev/null | sed 's/^/      /'
            kill -9 "$vm" 2>/dev/null
            break
        fi
    done
    wait "$vm" 2>/dev/null
    rm -f "$LOCK.owner"
    exec {lockfd}>&-

    local elapsed=$(( SECONDS - start ))
    if [ -f "$out/result.json" ] && grep -q ALL_DONE "$out/log.txt" 2>/dev/null; then
        local v s c l
        v=$(grep -oE '"validation": "[a-z]+"' "$out/result.json" | cut -d'"' -f4)
        s=$(grep -oE '"status": "[a-z]+"' "$out/result.json" | head -1 | cut -d'"' -f4)
        c=$(grep -oE '"status": "[a-z]+"' "$out/result.json" | tail -1 | cut -d'"' -f4)
        l=$(grep -oE '"leak": "[a-z]+"' "$out/result.json" | cut -d'"' -f4)
        local verdict=PASS
        for r in "$v" "$s" "$c" "$l"; do [ "$r" = pass ] || verdict=FAIL; done
        printf '  %-20s run%-2s %-5s validate=%-7s stress=%-7s crash=%-7s leak=%-7s %ss\n' \
            "$label" "$attempt" "$verdict" "$v" "$s" "$c" "$l" "$elapsed"
        [ "$verdict" = PASS ]
        return $?
    fi
    printf '  %-20s run%-2s %-5s (no result.json; see %s)\n' "$label" "$attempt" "INCOMPLETE" "$out"
    return 1
}

echo "run id: $RUN_ID"
echo "results: $RUN_DIR"
failures=0; total=0
selected=0
while IFS='|' read -r -u 3 label img mods rel; do
    [ -z "$label" ] && continue
    if [ -n "${KERNELS:-}" ] && ! printf '%s\n' ${KERNELS} | grep -qx "$label"; then continue; fi
    selected=$((selected+1))
    kimg="$(fetch_kernel "$label" "$img" "$mods" "$rel")" || {
        printf '  %-20s %s\n' "$label" "FETCH-FAILED"; failures=$((failures+1)); total=$((total+1)); continue; }
    for attempt in $(seq 1 "$RUNS"); do
        total=$((total+1))
        run_one "$label" "$kimg" "$attempt" || failures=$((failures+1))
    done
done 3<<< "$KERNEL_TABLE"

# One combined machine-readable summary for the whole matrix.
{
    echo "["
    first=1
    for f in "$RUN_DIR"/*/result.json; do
        [ -f "$f" ] || continue
        [ "$first" = 1 ] || echo ","
        cat "$f"; first=0
    done
    echo "]"
} > "$RUN_DIR/matrix.json" 2>/dev/null

# A selection that quietly runs fewer kernels than asked for is the failure
# mode this harness exists to prevent: it prints PASS for a matrix that never
# covered the kernel in question.
requested=0
for _ in ${KERNELS:-}; do requested=$((requested+1)); done
if [ -n "${KERNELS:-}" ] && [ "$selected" -ne "$requested" ]; then
    echo
    echo "SELECTION-MISMATCH: asked for $requested kernels, matched $selected"
    echo "  requested: ${KERNELS}"
    echo "  labels in the table: $(printf '%s\n' "$KERNEL_TABLE" | cut -d'|' -f1 | tr '\n' ' ')"
    failures=$((failures+1))
fi
expected=$(( selected * RUNS ))
if [ "$total" -ne "$expected" ]; then
    echo
    echo "RUN-COUNT-MISMATCH: expected $expected runs, executed $total"
    failures=$((failures+1))
fi

echo
echo "runs: $total   failures: $failures"
echo "summary: $RUN_DIR/matrix.json"
[ "$failures" -eq 0 ]
