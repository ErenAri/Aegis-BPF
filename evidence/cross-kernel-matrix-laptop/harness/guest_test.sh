#!/usr/bin/env bash
# Runs INSIDE a guest after a successful build. Executes the enforcement smoke +
# the three red-team/backpressure batteries against the guest's own kernel and
# emits ~/km_result.json plus per-battery logs in ~/km_logs.
set -uo pipefail
cd ~/aegis
LOGDIR=~/km_logs; mkdir -p "$LOGDIR"
KV="$(uname -r)"; LSM="$(cat /sys/kernel/security/lsm)"
OSN="$(. /etc/os-release; echo "$PRETTY_NAME")"

echo "== battery run: kernel $KV / $OSN =="

# Each battery brings up its own daemon; reset between them so a lingering daemon /
# pinned map from the previous battery can't collide with the next one's startup.
reset() { sudo pkill -x aegisbpf 2>/dev/null; sleep 1; sudo ./build/aegisbpf block clear >/dev/null 2>&1; }

reset; sudo BIN=./build/aegisbpf bash scripts/smoke_enforce.sh                                     >"$LOGDIR/smoke.log" 2>&1;             RC_SMOKE=$?
reset; sudo BIN=./build/aegisbpf bash scripts/redteam_bypass.sh                                    >"$LOGDIR/redteam_bypass.log" 2>&1;   RC_BYPASS=$?
reset; sudo BIN=./build/aegisbpf bash scripts/redteam_altread.sh                                   >"$LOGDIR/redteam_altread.log" 2>&1;  RC_ALTREAD=$?
reset; sudo BIN=./build/aegisbpf OUT_JSON="$LOGDIR/backpressure.json" bash scripts/backpressure_saturation.sh >"$LOGDIR/backpressure.log" 2>&1; RC_BP=$?

# Pull human-readable headline lines for the log.
echo "--- headlines ---"
grep -h "RESULT:" "$LOGDIR/redteam_bypass.log" "$LOGDIR/redteam_altread.log" "$LOGDIR/backpressure.log" 2>/dev/null || true
tail -1 "$LOGDIR/smoke.log" 2>/dev/null

python3 - "$KV" "$LSM" "$OSN" "$RC_SMOKE" "$RC_BYPASS" "$RC_ALTREAD" "$RC_BP" >~/km_result.json <<'PY'
import json, sys, re, pathlib
kv, lsm, osn, s, b, a, bp = sys.argv[1], sys.argv[2], sys.argv[3], *map(int, sys.argv[4:8])
def bypass_counts(p):
    try:
        t = pathlib.Path(p).read_text()
        m = re.search(r"RESULT:\s*(\d+)\s*passed,\s*(\d+)\s*failed", t)
        return {"passed": int(m.group(1)), "failed": int(m.group(2))} if m else None
    except Exception:
        return None
ld = pathlib.Path.home()/"km_logs"
out = {
    "kernel": kv, "lsm": lsm, "os": osn,
    "bpf_lsm_active": "bpf" in lsm.split(","),
    "batteries": {
        "smoke_enforce":       {"exit": s,  "pass": s == 0},
        "redteam_bypass":      {"exit": b,  "pass": b == 0, "counts": bypass_counts(ld/"redteam_bypass.log")},
        "redteam_altread":     {"exit": a,  "pass": a == 0, "counts": bypass_counts(ld/"redteam_altread.log")},
        "backpressure_saturation": {"exit": bp, "pass": bp == 0},
    },
}
try:
    out["batteries"]["backpressure_saturation"]["detail"] = json.loads((ld/"backpressure.json").read_text())
except Exception:
    pass
out["all_pass"] = all(v["pass"] for v in out["batteries"].values())
print(json.dumps(out, indent=2))
PY
echo "--- km_result.json ---"
cat ~/km_result.json
echo "ALL_PASS=$(python3 -c 'import json;print(json.load(open("/home/km/km_result.json"))["all_pass"])')"
