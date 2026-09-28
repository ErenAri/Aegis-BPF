#!/usr/bin/env bash
# Boots each cached kernel in virtme-ng and runs the guest check.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KC=/tmp/aegis-kernel-matrix/kernels
RUN=/tmp/aegis-kernel-matrix/flowexp-$(date +%H%M%S)
mkdir -p "$RUN"
for label in mainline-5.14 ubuntu-22.04-5.15 debian-12-6.1 mainline-6.5 ubuntu-24.04-6.8; do
  k=$(ls "$KC/$label"/boot/vmlinuz-* 2>/dev/null | head -1)
  [ -n "$k" ] || { printf "%-20s no cached kernel\n" "$label"; continue; }
  out="$RUN/$label"; mkdir -p "$out"
  timeout 420 script -qec "vng --rwdir=$out --memory 4G --cpus 4 --run $k \
     --append 'lsm=capability,bpf' -- env AEGIS_EXP=$HERE $HERE/kernel_matrix_guest.sh $out" \
     /dev/null </dev/null > "$out/console.txt" 2>&1
  if grep -aq ALL_DONE "$out/log.txt" 2>/dev/null; then
    kv=$(grep -a '^kernel=' "$out/log.txt" | cut -d= -f2)
    chk=$(grep -a 'check_rc=' "$out/log.txt" | cut -d= -f2)
    idm=$(grep -a 'identity_match=' "$out/log.txt" | cut -d= -f2)
    ing=$(grep -a 'ingress_match=' "$out/log.txt" | cut -d= -f2)
    egr=$(grep -a 'egress_match=' "$out/log.txt" | cut -d= -f2)
    pk=$(grep -aoP 'packets observed\s*:\s*\K[0-9]+' "$out/log.txt")
    su=$(grep -aoP 'summaries exported\s*:\s*\K[0-9]+' "$out/log.txt")
    printf "%-20s %-24s verifier_rc=%-3s identity=%-8s ing=%-7s egr=%-7s pkts=%-6s summaries=%s\n" \
      "$label" "${kv:-?}" "${chk:-?}" "${idm:-none}" "${ing:-–}" "${egr:-–}" "${pk:-0}" "${su:-0}"
  else
    printf "%-20s INCOMPLETE (see %s)\n" "$label" "$out"
  fi
done
echo "results: $RUN"
