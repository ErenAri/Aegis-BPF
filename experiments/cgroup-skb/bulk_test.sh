#!/usr/bin/env bash
# Real bidirectional volume: a server OUTSIDE the test cgroup, a client inside.
# Ingress packets therefore arrive for the cgroup from a task that is not in it,
# which is the case that decides whether current-task identity is usable.
set -uo pipefail
CG=/sys/fs/cgroup/aegis_skb_experiment
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${OUT:-$HERE/results}"; mkdir -p "$OUT"
PORT=19099
MB="${MB:-32}"

cleanup() {
  [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null
  if [ -f "$CG/cgroup.procs" ]; then
    while read -r p; do echo "$p" > /sys/fs/cgroup/cgroup.procs 2>/dev/null; done < "$CG/cgroup.procs"
  fi
  rmdir "$CG" 2>/dev/null
}
trap cleanup EXIT
rmdir "$CG" 2>/dev/null; mkdir -p "$CG"

# Server stays in the root cgroup.
python3 - "$PORT" "$MB" <<'PY' &
import socket,sys
port=int(sys.argv[1]); mb=int(sys.argv[2])
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',port)); s.listen(4)
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
sleep 1

echo "=== ${MB} MiB download into the test cgroup, emit=$1 ==="
( cd "$HERE" && ./skb_probe "$CG" --seconds 25 --emit "$1" --json "$OUT/bulk_emit$1.jsonl" \
    > "$OUT/bulk_emit$1.txt" 2>&1 ) &
PROBE=$!
sleep 2

# Client runs inside the cgroup.
python3 - "$PORT" "$CG" <<'PY'
import socket,sys,os,time
port=int(sys.argv[1]); cg=sys.argv[2]
open(cg+"/cgroup.procs","w").write(str(os.getpid()))
t0=time.time(); n=0
s=socket.socket(); s.connect(('127.0.0.1',port))
while True:
    b=s.recv(262144)
    if not b: break
    n+=len(b)
s.close()
print(f"    client received {n/1048576:.1f} MiB in {time.time()-t0:.2f}s")
PY

wait $PROBE
grep -E "packets observed|events emitted|events read|skb_cgid|current_cgid|unparsed|ringbuf|^ok |^unsup|^truncated" "$OUT/bulk_emit$1.txt" | sed 's/^/    /'
