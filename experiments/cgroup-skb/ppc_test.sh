#!/usr/bin/env bash
# B11, take 3: per-packet cost with the packet count held EXACTLY fixed.
#
# The earlier TCP-throughput approach was measuring the wrong thing. Loopback
# TCP coalesces with GSO, so the number of packets per MiB moves with load --
# the hook fires a variable number of times per sample, and the noise swamped
# the effect (baseline spanned 6x; "emit=0" came out 29% FASTER than baseline,
# which is impossible).
#
# Fixed-count UDP removes that: N sendto() calls produce exactly N egress
# packets through the hook, every run. What is measured is therefore the cost
# of N hook invocations, not the kernel's framing decisions.
set -uo pipefail
CG=/sys/fs/cgroup/aegis_skb_ppc
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${OUT:-$HERE/results}"; mkdir -p "$OUT"
N="${N:-200000}"; ROUNDS="${ROUNDS:-9}"

cleanup(){ pkill -9 -x skb_probe 2>/dev/null
  if [ -f "$CG/cgroup.procs" ]; then while read -r p; do echo "$p" > /sys/fs/cgroup/cgroup.procs 2>/dev/null; done < "$CG/cgroup.procs"; fi
  rmdir "$CG" 2>/dev/null; }
trap cleanup EXIT
rmdir "$CG" 2>/dev/null; mkdir -p "$CG"

# Exactly N UDP packets to a discard port. No server, no accept, no GSO.
burst() {
  python3 - "$CG" "$N" <<'PY'
import socket,os,sys,time
cg=sys.argv[1]; n=int(sys.argv[2])
open(cg+"/cgroup.procs","w").write(str(os.getpid()))
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('127.0.0.1', 9))          # discard-ish; nothing listening
payload=b'x'*64
t0=time.perf_counter()
for _ in range(n):
    try: s.send(payload)
    except Exception: pass
dt=time.perf_counter()-t0
print(f"{dt*1e9/n:.1f}")             # nanoseconds per packet
PY
}

attach() {
  ( cd "$HERE" && ./skb_probe "$CG" --seconds 600 --emit "$1" > "$OUT/ppc_emit$1.txt" 2>&1 ) >/dev/null 2>&1 &
  echo $! > /tmp/.ppc_pid
}

declare -A R; for c in baseline emit0 emit1; do R[$c]=""; done
echo "warmup ($N packets)"; burst >/dev/null

for r in $(seq 1 "$ROUNDS"); do
  for cond in baseline emit0 emit1; do
    P=""
    case "$cond" in
      emit0) attach 0; P=$(cat /tmp/.ppc_pid); sleep 1;;
      emit1) attach 1; P=$(cat /tmp/.ppc_pid); sleep 1;;
    esac
    R[$cond]="${R[$cond]} $(burst)"
    [ -n "$P" ] && { kill -TERM "$P" 2>/dev/null; wait "$P" 2>/dev/null; }
  done
  echo "  round $r"
done

echo
python3 - <<PY
import statistics as st
d={"baseline":"${R[baseline]}","emit=0":"${R[emit0]}","emit=1":"${R[emit1]}"}
print(f"{'condition':<10}{'ns/packet median':>19}{'min':>9}{'max':>9}{'vs baseline':>14}")
base=None
for k,v in d.items():
    x=sorted(float(t) for t in v.split())
    if not x: continue
    m=st.median(x)
    if base is None: base=m
    print(f"{k:<10}{m:>19.0f}{x[0]:>9.0f}{x[-1]:>9.0f}{m-base:>+11.0f} ns")
    print(f"{'':10}  samples: {[int(t) for t in x]}")
print()
print("spread check (max/min per condition):")
for k,v in d.items():
    x=sorted(float(t) for t in v.split())
    if x: print(f"  {k:<10} {x[-1]/x[0]:.2f}x")
PY
for e in 0 1; do grep -E "packets observed|events emitted|ringbuf drops" "$OUT/ppc_emit$e.txt" 2>/dev/null | sed "s/^/  emit=$e /"; done
