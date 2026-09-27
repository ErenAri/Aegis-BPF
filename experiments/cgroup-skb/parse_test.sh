#!/usr/bin/env bash
# B6/B15: feed the parser packets it must refuse to guess about.
#
# The point is not "does the verifier accept it" -- it did -- but "does it
# report unparsed instead of inventing fields". Each case below has a known
# right answer in the parse_status column.
set -uo pipefail
CG=/sys/fs/cgroup/aegis_skb_parse
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${OUT:-$HERE/results}"; mkdir -p "$OUT"
cleanup(){ if [ -f "$CG/cgroup.procs" ]; then while read -r p; do echo "$p" > /sys/fs/cgroup/cgroup.procs 2>/dev/null; done < "$CG/cgroup.procs"; fi; rmdir "$CG" 2>/dev/null; }
trap cleanup EXIT
rmdir "$CG" 2>/dev/null; mkdir -p "$CG"

( cd "$HERE" && ./skb_probe "$CG" --seconds 22 --emit 1 --json "$OUT/parse.jsonl" > "$OUT/parse.txt" 2>&1 ) &
PROBE=$!
sleep 2

python3 - "$CG" <<'PY'
import socket, os, sys, struct, time
os.write(os.open(sys.argv[1]+"/cgroup.procs", os.O_WRONLY), str(os.getpid()).encode())

def quiet(fn):
    try: fn()
    except Exception: pass

# 1. ordinary TCP + UDP -> must parse
quiet(lambda: socket.create_connection(("127.0.0.1", 9), timeout=1))
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
quiet(lambda: s.sendto(b"x"*32, ("127.0.0.1", 9)))

# 2. ICMP -> not TCP/UDP, must be unsup_l4 (needs root)
quiet(lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        .sendto(struct.pack("!BBHHH", 8, 0, 0, 1, 1)+b"ping", ("127.0.0.1", 0)))

# 3. IPv4 fragments -> non-first fragment carries no L4 header
r=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
def frag(off, mf, payload):
    flags_off = (0x2000 if mf else 0) | off
    ihl_ver=0x45; tot=20+len(payload)
    hdr=struct.pack("!BBHHHBBH4s4s", ihl_ver,0,tot,0x1234,flags_off,64,socket.IPPROTO_UDP,0,
                    socket.inet_aton("127.0.0.1"), socket.inet_aton("127.0.0.1"))
    quiet(lambda: r.sendto(hdr+payload, ("127.0.0.1",0)))
frag(0, True, struct.pack("!HHHH", 1111, 9, 8+16, 0)+b"A"*16)   # first frag: has UDP hdr
frag(4, False, b"B"*32)                                          # later frag: no L4 hdr

# 4. IPv6 with an extension header -> chain deliberately not walked
quiet(lambda: socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).sendto(b"x"*16, ("::1", 9)))

# 5. truncated / tiny IPv4 (total length lies)
hdr=struct.pack("!BBHHHBBH4s4s", 0x45,0,20,0x4321,0,64,socket.IPPROTO_TCP,0,
                socket.inet_aton("127.0.0.1"), socket.inet_aton("127.0.0.1"))
quiet(lambda: r.sendto(hdr, ("127.0.0.1",0)))   # no L4 bytes at all

# 6. bogus ihl (claims a 60-byte header that is not there)
bad=struct.pack("!BBHHHBBH4s4s", 0x4f,0,20,0x5555,0,64,socket.IPPROTO_TCP,0,
                socket.inet_aton("127.0.0.1"), socket.inet_aton("127.0.0.1"))
quiet(lambda: r.sendto(bad, ("127.0.0.1",0)))
time.sleep(1)
PY

wait $PROBE
echo "=== parse outcomes ==="
grep -E "^ok |^unsup|^truncated|^fragment|^v6|unparsed" "$OUT/parse.txt" | sed 's/^/    /'
echo "=== distinct (proto, parse) pairs seen ==="
python3 - "$OUT/parse.jsonl" <<'PY'
import json,sys
from collections import Counter
c=Counter()
for l in open(sys.argv[1]):
    if not l.strip(): continue
    r=json.loads(l); c[(r["family"], r["proto"], r["parse"])]+=1
for (f,p,s),n in sorted(c.items()):
    print(f"    family={f} proto={p:<3} parse={s:<14} count={n}")
PY
