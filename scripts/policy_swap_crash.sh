#!/usr/bin/env bash
# Crash-during-reload test: kill `policy apply` at random points and assert the
# live policy is always exactly one coherent generation, never a mixture.
# Reuses the policy files written by policy_swap_stress.sh.
S="${WORKDIR:?set WORKDIR to the directory holding A.conf and B.conf}"
BIN="${BIN:-./build/aegisbpf}"
torn=0; ok=0; rounds=${ROUNDS:-40}
probe() { cat "/tmp/aegis_$1" >/dev/null 2>&1 && echo allow || echo deny; }
for i in $(seq 1 "$rounds"); do
    if [ $((i % 2)) -eq 0 ]; then p=A; else p=B; fi
    sudo "$BIN" policy apply "$S/$p.conf" >/dev/null 2>&1 &
    pid=$!
    sleep "0.$(( (RANDOM % 9) + 1 ))"
    sudo pkill -9 -f "[a]egisbpf policy apply" >/dev/null 2>&1 || true
    wait "$pid" 2>/dev/null || true
    al=$(probe always); a=$(probe onlyA); b=$(probe onlyB)
    if [ "$al" != deny ]; then
        torn=$((torn+1)); echo "  TORN round $i: always-denied file was ALLOWED"; continue
    fi
    if { [ "$a" = deny ] && [ "$b" = allow ]; } || { [ "$a" = allow ] && [ "$b" = deny ]; }; then
        ok=$((ok+1))
    else
        torn=$((torn+1)); echo "  TORN round $i: onlyA=$a onlyB=$b (neither generation A nor B)"
    fi
done
echo
echo "coherent generations: $ok/$rounds   torn: $torn"
[ "$torn" -eq 0 ] && echo "PASS: no torn policy observed after a mid-reload crash" || echo "FAIL"
