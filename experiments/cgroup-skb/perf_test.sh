#!/usr/bin/env bash
# B11/B12: separate hook cost from observability cost.
#
# Loopback is noisy, so this warms up, takes medians (never means -- a connect()
# mean is dominated by a few scheduler outliers), and INTERLEAVES the three
# conditions round-robin so drift cannot masquerade as an effect.
#
# Two ports on purpose: the bulk server would otherwise try to push the whole
# transfer to each of the 300 latency probes, turning one sample into gigabytes.
set -uo pipefail
CG=/sys/fs/cgroup/aegis_skb_experiment
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${OUT:-$HERE/results}"; mkdir -p "$OUT"
BULK_PORT=19111; ECHO_PORT=19112; MB="${MB:-32}"; ROUNDS="${ROUNDS:-5}"

cleanup(){
  [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null
  [ -n "${ESRV:-}" ] && kill "$ESRV" 2>/dev/null
  pkill -9 -x skb_probe 2>/dev/null
  if [ -f "$CG/cgroup.procs" ]; then while read -r p; do echo "$p" > /sys/fs/cgroup/cgroup.procs 2>/dev/null; done < "$CG/cgroup.procs"; fi
  rmdir "$CG" 2>/dev/null
}
trap cleanup EXIT
rmdir "$CG" 2>/dev/null; mkdir -p "$CG"

# Bulk server: one large transfer per connection.
python3 - "$BULK_PORT" "$MB" <<'PY' &
import socket,sys
port=int(sys.argv[1]); mb=int(sys.argv[2])
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',port)); s.listen(16)
buf=b'x'*65536
while True:
    try: c,_=s.accept()
    except Exception: break
    try:
        for _ in range(mb*16): c.sendall(buf)
    except Exception: pass
    c.close()
PY
SRV=$!
# Latency server: accept and close immediately.
python3 - "$ECHO_PORT" <<'PY' &
import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',int(sys.argv[1]))); s.listen(512)
while True:
    try: c,_=s.accept(); c.close()
    except Exception: break
PY
ESRV=$!
sleep 1

sample() {   # "MiB/s connect_p50_us connect_p95_us"
  python3 - "$BULK_PORT" "$ECHO_PORT" "$CG" <<'PY'
import socket,sys,os,time
bulk=int(sys.argv[1]); echo=int(sys.argv[2]); cg=sys.argv[3]
open(cg+"/cgroup.procs","w").write(str(os.getpid()))
s=socket.socket(); s.connect(('127.0.0.1',bulk))
t0=time.perf_counter(); n=0
while True:
    b=s.recv(262144)
    if not b: break
    n+=len(b)
s.close(); dt=time.perf_counter()-t0
ds=[]
for _ in range(300):
    c=socket.socket(); a=time.perf_counter()
    try: c.connect(('127.0.0.1',echo))
    except Exception: pass
    ds.append((time.perf_counter()-a)*1e6); c.close()
ds.sort()
print(f"{n/1048576/dt:.1f} {ds[len(ds)//2]:.1f} {ds[int(len(ds)*0.95)]:.1f}")
PY
}

# The PID goes through a file, not command substitution. A backgrounded job
# inherits the $( ) pipe and holds it open, so `P=$(attach 0)` blocks until the
# probe exits -- 600 seconds later, which looks exactly like a hang.
attach() {
    ( cd "$HERE" && ./skb_probe "$CG" --seconds 600 --emit "$1" > "$OUT/perf_emit$1.txt" 2>&1 ) >/dev/null 2>&1 &
    echo $! > /tmp/.skb_probe_pid
}

declare -A TP LAT
for c in baseline emit0 emit1; do TP[$c]=""; LAT[$c]=""; done
echo "warmup"; sample >/dev/null

for r in $(seq 1 "$ROUNDS"); do
  for cond in baseline emit0 emit1; do
    P=""
    case "$cond" in
      emit0) attach 0; P=$(cat /tmp/.skb_probe_pid); sleep 1;;
      emit1) attach 1; P=$(cat /tmp/.skb_probe_pid); sleep 1;;
    esac
    read -r tp p50 p95 <<< "$(sample)"
    TP[$cond]="${TP[$cond]} $tp"; LAT[$cond]="${LAT[$cond]} $p50"
    [ -n "$P" ] && { kill -TERM "$P" 2>/dev/null; wait "$P" 2>/dev/null; }
  done
  echo "  round $r"
done

echo
python3 - <<PY
import statistics as st
d={"baseline":("${TP[baseline]}","${LAT[baseline]}"),
   "emit=0":("${TP[emit0]}","${LAT[emit0]}"),
   "emit=1":("${TP[emit1]}","${LAT[emit1]}")}
print(f"{'condition':<10}{'throughput MiB/s':>20}{'vs base':>10}{'connect p50 us':>17}{'vs base':>10}")
base=None
for k,(tp,lat) in d.items():
    t=sorted(float(x) for x in tp.split()); l=sorted(float(x) for x in lat.split())
    if not t: continue
    mt,ml=st.median(t),st.median(l)
    if base is None: base=(mt,ml)
    print(f"{k:<10}{mt:>20.1f}{(mt-base[0])/base[0]*100:>9.1f}%{ml:>17.1f}{(ml-base[1])/base[1]*100:>9.1f}%")
    print(f"{'':10}  tp samples: {['%.0f'%x for x in t]}   lat: {['%.1f'%x for x in l]}")
PY
for e in 0 1; do grep -E "packets observed|events emitted|ringbuf drops" "$OUT/perf_emit$e.txt" 2>/dev/null | sed "s/^/  emit=$e /"; done
