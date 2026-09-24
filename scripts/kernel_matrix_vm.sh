#!/usr/bin/env bash
# Run the atomic-swap validation across the supported kernel families, each in
# a virtme-ng VM booted with BPF-LSM enabled.
#
# Why VMs rather than one runner per kernel: the kernel-<version> runner labels
# the older workflows target do not exist on this repository, so those jobs
# queue forever instead of failing -- a matrix that silently never runs. This
# needs only KVM, so the same command works on a developer laptop and on any
# runner that can nest virtualization.
#
# The kernels are the families docs/SUPPORT_POLICY.md lists, taken from the
# distributions Aegis targets rather than from version numbers alone, because
# vendors backport BPF behaviour differently.
#
# Env:
#   KERNELS   space-separated subset of labels to run (default: all)
#   WORKDIR   where kernels and results live (default: ~/aegis-kmatrix)
#   KEEP      set to 1 to keep downloaded kernels
#
# Exit: 0 if every requested kernel passed, 1 otherwise, 2 on missing prereqs.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${WORKDIR:-$HOME/aegis-kmatrix}"
K="$WORKDIR/kernels"
OUT="$WORKDIR/out"
mkdir -p "$K" "$OUT"

command -v vng >/dev/null 2>&1 || { echo "virtme-ng (vng) not installed"; exit 2; }
[ -e /dev/kvm ] || { echo "/dev/kvm not available"; exit 2; }
[ -x "$REPO/build/aegisbpf" ] || { echo "build/aegisbpf missing; build first"; exit 2; }

# label|url-of-kernel-image-package|url-of-modules-package|path-to-vmlinuz-within
# Ubuntu/Debian ship 9p; RHEL-family kernels do not build 9p at all, which is
# why the AlmaLinux image cannot be booted this way -- see docs.
read -r -d '' KERNEL_TABLE <<'TABLE'
mainline-5.14|https://kernel.ubuntu.com/mainline/v5.14.21/amd64/linux-image-unsigned-5.14.21-051421-generic_5.14.21-051421.202111210831_amd64.deb|https://kernel.ubuntu.com/mainline/v5.14.21/amd64/linux-modules-5.14.21-051421-generic_5.14.21-051421.202111210831_amd64.deb|boot/vmlinuz-5.14.21-051421-generic
ubuntu-22.04-5.15|http://archive.ubuntu.com/ubuntu/pool/main/l/linux-signed/linux-image-5.15.0-131-generic_5.15.0-131.141_amd64.deb|http://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-modules-5.15.0-131-generic_5.15.0-131.141_amd64.deb|boot/vmlinuz-5.15.0-131-generic
debian-12-6.1|http://deb.debian.org/debian/pool/main/l/linux/linux-image-6.1.0-50-amd64-unsigned_6.1.176-1_amd64.deb||boot/vmlinuz-6.1.0-50-amd64
ubuntu-24.04-6.8|http://archive.ubuntu.com/ubuntu/pool/main/l/linux-signed/linux-image-6.8.0-71-generic_6.8.0-71.71_amd64.deb|http://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-modules-6.8.0-71-generic_6.8.0-71.71_amd64.deb|boot/vmlinuz-6.8.0-71-generic
TABLE

fetch_kernel() {
    local label="$1" img="$2" mods="$3" rel="$4"
    local dir="$K/$label"
    [ -f "$dir/$rel" ] && { echo "$dir/$rel"; return 0; }
    mkdir -p "$dir"
    curl -fsSL -o "$dir/img.deb" "$img" || return 1
    dpkg-deb -x "$dir/img.deb" "$dir" || return 1
    if [ -n "$mods" ]; then
        curl -fsSL -o "$dir/mods.deb" "$mods" || return 1
        dpkg-deb -x "$dir/mods.deb" "$dir" || return 1
    fi
    [ -f "$dir/$rel" ] || return 1
    echo "$dir/$rel"
}

failures=0
ran=0
printf '%-20s %-10s %-8s %-8s %-8s %s\n' KERNEL VALIDATE STRESS CRASH LEAK RESULT
while IFS='|' read -r label img mods rel; do
    [ -z "$label" ] && continue
    if [ -n "${KERNELS:-}" ] && ! printf '%s\n' ${KERNELS} | grep -qx "$label"; then
        continue
    fi
    kimg="$(fetch_kernel "$label" "$img" "$mods" "$rel")" || {
        printf '%-20s %-10s %-8s %-8s %-8s %s\n' "$label" - - - - "FETCH-FAILED"
        failures=$((failures+1)); continue; }

    rm -rf "${OUT:?}/$label"; mkdir -p "$OUT/$label"
    # script(1) provides the pty vng needs; output must go to a file because
    # piping the guest console loses lines.
    script -qec "vng --rwdir=$OUT --memory 4G --cpus 4 --run $kimg \
        --append 'lsm=capability,bpf' -- $REPO/scripts/kernel_matrix_guest.sh $OUT/$label" \
        /dev/null > "$OUT/$label/console.txt" 2>&1

    log="$OUT/$label/log.txt"
    if [ ! -f "$log" ] || ! grep -q ALL_DONE "$log"; then
        printf '%-20s %-10s %-8s %-8s %-8s %s\n' "$label" - - - - "DID-NOT-BOOT"
        failures=$((failures+1)); continue
    fi
    ran=$((ran+1))
    g() { grep -aoE "$1=[0-9A-Za-z_]+" "$log" | tail -1 | cut -d= -f2; }
    v=$(g validate_rc); s=$(g stress_rc); c=$(g crash_rc); l=$(g leak_rc)
    verdict=PASS
    for rc in "$v" "$s" "$c" "$l"; do [ "$rc" = "0" ] || verdict=FAIL; done
    [ "$verdict" = PASS ] || failures=$((failures+1))
    printf '%-20s %-10s %-8s %-8s %-8s %s\n' "$label" "${v:-?}" "${s:-?}" "${c:-?}" "${l:-?}" "$verdict"
done <<< "$KERNEL_TABLE"

echo
echo "kernels run: $ran   failures: $failures"
[ "${KEEP:-0}" = 1 ] || rm -f "$K"/*/img.deb "$K"/*/mods.deb
[ "$failures" -eq 0 ]
