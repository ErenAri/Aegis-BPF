#!/usr/bin/env bash
# One-shot snapshot of the running 168h AegisBPF soak.
# Usage: sudo scripts/soak_status.sh   (sudo lets it read live daemon metrics)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/evidence/soak-168h-laptop"
BIN="${AEGIS_BIN:-${ROOT}/build/aegisbpf}"
CANARY="/var/tmp/aegis-soak-canary"
DURATION="${DURATION_SECONDS:-604800}"   # 168h

pid="$(pgrep -x aegisbpf | head -1)"
if [ -z "$pid" ]; then
  echo "soak daemon: NOT RUNNING"
  [ -f "${OUT}/exit_code.txt" ] && echo "  finished, exit=$(cat "${OUT}/exit_code.txt"); see ${OUT}/soak_summary.json"
  exit 1
fi

start="$(cat "${OUT}/start_utc.txt" 2>/dev/null)"
start_h="$(sed -E 's/(....)(..)(..)T(..)(..)(..)Z/\1-\2-\3 \4:\5:\6/' <<<"${start}")"
start_epoch="$(date -u -d "${start_h}" +%s 2>/dev/null || echo 0)"
now_epoch="$(date -u +%s)"
elapsed=$(( now_epoch - start_epoch ))
remain=$(( DURATION - elapsed ))
fmt() { printf '%dd %02dh %02dm' $(($1/86400)) $(($1%86400/3600)) $(($1%3600/60)); }

rss_kb="$(awk '/VmRSS:/{print $2}' "/proc/${pid}/status" 2>/dev/null)"
if cat "${CANARY}" >/dev/null 2>&1; then enf="ALLOWED ⚠️  (enforcement NOT active!)"; else enf="DENIED ✓ (enforcing)"; fi

m="$(${BIN} metrics 2>/dev/null || true)"
sum() { awk -v k="$1" '$1==k || index($1,k"{")==1 {s+=$2} END{printf "%.0f",s+0}' <<<"$m"; }
file_blocks="$(sum aegisbpf_blocks_total)"
net_blocks=$(( $(sum aegisbpf_net_connect_blocks_total) + $(sum aegisbpf_net_bind_blocks_total) ))
rb_drops="$(sum aegisbpf_ringbuf_drops_total)"
bp_drops="$(sum aegisbpf_backpressure_priority_drops_total)"

echo "=== AegisBPF 168h soak status ==="
printf '  daemon        pid %s, RSS %s MiB (start 51 MiB, budget +128)\n' "${pid}" "$(( ${rss_kb:-0} / 1024 ))"
printf '  enforcement   %s\n' "${enf}"
printf '  elapsed       %s  of 7d 00h 00m\n' "$(fmt ${elapsed})"
printf '  remaining     %s   (ETA %s)\n' "$(fmt ${remain})" "$(date -u -d "@$(( start_epoch + DURATION ))" '+%Y-%m-%d %H:%MZ' 2>/dev/null)"
printf '  decisions     file_blocks=%s  net_blocks=%s\n' "${file_blocks:-?}" "${net_blocks:-?}"
printf '  telemetry     ringbuf_drops=%s  backpressure_prio_drops=%s  (expected; enforcement is decoupled)\n' "${rb_drops:-?}" "${bp_drops:-?}"
lid="$(systemctl show systemd-logind -p HandleLidSwitch --value 2>/dev/null)"
glid="$(sudo -u "${SUDO_USER:-$USER}" gsettings get org.gnome.settings-daemon.plugins.power lid-close-ac-action 2>/dev/null | tr -d \')"
printf '  suspend       lid=%s gnome-lid=%s gnome-idle=%s\n' "${lid:-?}" "${glid:-?}" \
  "$(sudo -u "${SUDO_USER:-$USER}" gsettings get org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type 2>/dev/null | tr -d \')"
