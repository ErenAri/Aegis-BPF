#!/usr/bin/env bash
# Per-kernel validation of the atomic policy-swap machinery.
#
# One script so the same checks run locally and in CI, on every kernel family
# docs/SUPPORT_POLICY.md lists (5.14, 5.15, 6.1, 6.5+). Each check is a thing
# that can fail differently on an older kernel, not a restatement of the unit
# tests.
#
# Requires root and a BPF-LSM-capable kernel. Exits non-zero on the first
# failure, printing what was expected.
set -uo pipefail

BIN="${BIN:-./build/aegisbpf}"
OBJ="${OBJ:-./build/aegis.bpf.o}"
WORK="${WORK:-$(mktemp -d)}"
PINDIR=/sys/fs/bpf/aegisbpf
failures=0

say()  { printf '\n=== %s ===\n' "$*"; }
ok()   { printf '  ok    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; failures=$((failures+1)); }

need_root() { [ "$(id -u)" -eq 0 ] || { echo "must run as root"; exit 2; }; }
need_root

# This script stops agents, wipes /sys/fs/bpf/aegisbpf and clears
# /var/lib/aegisbpf. On a machine where Aegis is actually running that is
# destructive, and a leftover agent also silently invalidates the results:
# every map looks "reused", pinning is skipped, and checks then measure the
# previous run's state rather than this build's. Refuse rather than guess, and
# never kill someone's agent automatically.
if pgrep -x aegisbpf >/dev/null 2>&1; then
    cat >&2 <<'MSG'
An aegisbpf agent is already running on this host.

This script needs exclusive use of /sys/fs/bpf/aegisbpf and /var/lib/aegisbpf,
and it will stop agents and delete that state. It will not do that to an agent
it did not start.

Leaving it running does not merely risk the host: every pinned map would be
reused, pinning would be skipped, and the results would describe the running
agent instead of this build.

If this host is a test environment, stop the agent and re-run:

    sudo pkill -x aegisbpf && sudo rm -rf /sys/fs/bpf/aegisbpf

Then set AEGIS_VALIDATE_DESTRUCTIVE=1 to confirm.
MSG
    exit 2
fi
if [ -d /sys/fs/bpf/aegisbpf ] && [ "${AEGIS_VALIDATE_DESTRUCTIVE:-0}" != "1" ]; then
    cat >&2 <<'MSG'
/sys/fs/bpf/aegisbpf already exists but no agent is running.

That is either a crashed agent's pins or another test's leftovers. Removing
them is safe in a test environment and wrong on a production host, so this
script will not decide for you.

    sudo rm -rf /sys/fs/bpf/aegisbpf

or re-run with AEGIS_VALIDATE_DESTRUCTIVE=1 to let this script clear it.
MSG
    exit 2
fi

say "environment"
printf '  kernel: %s\n' "$(uname -r)"
if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
    ok "BPF-LSM enabled"
else
    bad "BPF-LSM not in /sys/kernel/security/lsm -- enforcement cannot be tested"
    echo "  (add lsm=...,bpf to the kernel command line)"
    exit 1
fi

# --- kernel primitives the slot design depends on ------------------------
# Checked directly rather than inferred from a successful daemon start, so a
# kernel that lacks one is reported precisely instead of as "agent failed".
# bpftool is built per kernel release, so the host's copy is unusable inside a
# VM running an older kernel: every query returns nothing and checks built on
# it report the product as broken when only the tool is missing. Read the state
# through libbpf instead.
PROBE="$WORK/slot_probe"
if ! cc -O2 -o "$PROBE" "$(dirname "$0")/../tools/slot_probe.c" -lbpf 2>"$WORK/probe_build.err"; then
    bad "could not build tools/slot_probe.c (needs libbpf headers)"
    sed -n '1,5p' "$WORK/probe_build.err"
    exit 1
fi
VSTAT="$WORK/verifier_stats"
cc -O2 -o "$VSTAT" "$(dirname "$0")/../tools/verifier_stats.c" -lbpf 2>/dev/null

say "map primitives"
cat > "$WORK/probe.c" <<'EOF'
#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
struct lpm_key { __u32 prefixlen; __u32 data; };
struct composite { __u64 a; __u32 b; __u32 c; };
static int outer_with(int inner, const char *what) {
    LIBBPF_OPTS(bpf_map_create_opts, o, .inner_map_fd = inner);
    int outer = bpf_map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS, NULL, 4, 4, 2, &o);
    if (outer < 0) { printf("FAIL %s: outer create: %s\n", what, strerror(errno)); return -1; }
    __u32 slot = 0; __u32 v = inner;
    if (bpf_map_update_elem(outer, &slot, &v, 0)) {
        printf("FAIL %s: stage into slot: %s\n", what, strerror(errno)); return -1; }
    printf("OK %s\n", what);
    return outer;
}
int main(void) {
    int rc = 0;
    int h = bpf_map_create(BPF_MAP_TYPE_HASH, NULL, sizeof(struct composite), 1, 64, NULL);
    if (h < 0 || outer_with(h, "hash inner (struct key)") < 0) rc = 1;
    LIBBPF_OPTS(bpf_map_create_opts, np, .map_flags = BPF_F_NO_PREALLOC);
    int l = bpf_map_create(BPF_MAP_TYPE_LPM_TRIE, NULL, sizeof(struct lpm_key), 1, 64, &np);
    if (l < 0 || outer_with(l, "lpm_trie inner") < 0) rc = 1;
    /* Right-sizing: since 5.11 bpf_map_meta_equal() ignores max_entries, so a
     * replacement inner may be a different size. Aegis sizes each generation
     * to its rule count and falls back to the template size otherwise. */
    int small = bpf_map_create(BPF_MAP_TYPE_HASH, NULL, sizeof(struct composite), 1, 8, NULL);
    LIBBPF_OPTS(bpf_map_create_opts, o2, .inner_map_fd = h);
    int outer = bpf_map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS, NULL, 4, 4, 2, &o2);
    __u32 s1 = 1; __u32 v2 = small;
    if (outer < 0 || small < 0 || bpf_map_update_elem(outer, &s1, &v2, 0))
        printf("INFO variable inner max_entries unsupported (pre-5.11 semantics); template sizing used\n");
    else
        printf("OK variable inner max_entries (right-sizing available)\n");
    return rc;
}
EOF
if cc -O1 -o "$WORK/probe" "$WORK/probe.c" -lbpf 2>"$WORK/cc.err"; then
    if "$WORK/probe"; then ok "ARRAY_OF_MAPS accepts every inner type Aegis uses"
    else bad "a required map primitive is unavailable on this kernel"; fi
else
    bad "probe failed to build"; sed -n '1,5p' "$WORK/cc.err"
fi

# --- object load + verifier ---------------------------------------------
say "BPF object load"
rm -rf "$PINDIR" 2>/dev/null
if [ -x "$VSTAT" ]; then
    # verifier_stats loads every program through libbpf and reports the
    # verifier's own per-program numbers, so a rejection shows up as missing
    # output rather than as a tool failure.
    if "$VSTAT" "$OBJ" > "$WORK/verifier.csv" 2>"$WORK/verifier.err"; then
        progs=$(grep -c ',' "$WORK/verifier.csv")
        if [ "$progs" -gt 1 ]; then
            ok "all programs pass the verifier ($((progs - 2)) programs measured)"
        else
            bad "verifier produced no per-program data -- object likely rejected"
            tail -5 "$WORK/verifier.err"
        fi
    else
        bad "verifier rejected the object"
        tail -20 "$WORK/verifier.err"
    fi
else
    bad "could not build tools/verifier_stats.c; verifier acceptance NOT checked"
fi

# --- daemon lifecycle ----------------------------------------------------
say "daemon + policy lifecycle"
rm -rf "$PINDIR"
rm -f /var/lib/aegisbpf/policy.applied* /var/lib/aegisbpf/deny.db \
      /var/lib/aegisbpf/runtime_rules.db /var/lib/aegisbpf/runtime_rules.migrated
"$BIN" run --enforce --enforce-signal=none --allow-unsigned-bpf --log-level=info \
    > "$WORK/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 40); do grep -q "Agent started" "$WORK/daemon.log" && break; sleep 0.5; done
if grep -q "Agent started" "$WORK/daemon.log"; then ok "daemon reached ENFORCE"
else bad "daemon did not start"; tail -20 "$WORK/daemon.log"; kill $DPID 2>/dev/null; exit 1; fi

grep -q "Policy slots bootstrapped" "$WORK/daemon.log" \
    && ok "policy slots bootstrapped" || bad "slots were not bootstrapped"

echo victim > /tmp/aegis_validate_target
printf 'version=6\n\n[deny_path]\n/tmp/aegis_validate_target\n\n[deny_port]\n4444:tcp:egress\n' > "$WORK/p1.conf"
printf 'version=6\n\n[deny_path]\n/tmp/aegis_validate_target\n\n[deny_port]\n5555:tcp:egress\n' > "$WORK/p2.conf"

"$BIN" policy apply "$WORK/p1.conf" >"$WORK/apply1.log" 2>&1 \
    && ok "policy apply succeeded" || { bad "policy apply failed"; tail -5 "$WORK/apply1.log"; }
grep -q "committed atomically" "$WORK/apply1.log" \
    && ok "commit took the atomic path" || bad "commit did not report an atomic commit"

cat /tmp/aegis_validate_target >/dev/null 2>&1 \
    && bad "denied file was readable -- enforcement not active" \
    || ok "kernel enforces the applied generation"

before=$("$PROBE" active-slot 2>/dev/null)
gen_before=$("$PROBE" generation 2>/dev/null)
"$BIN" policy apply "$WORK/p2.conf" >/dev/null 2>&1
after=$("$PROBE" active-slot 2>/dev/null)
gen_after=$("$PROBE" generation 2>/dev/null)
if [ -z "$before" ] || [ -z "$after" ]; then
    bad "could not read active_slot -- state unreadable, NOT a pass"
elif [ "$before" != "$after" ]; then
    ok "reload flipped active_slot ($before -> $after)"
else
    bad "active_slot did not change across a reload"
fi
if [ -z "$gen_after" ]; then
    bad "could not read slot_generation -- oracle unreadable, NOT a pass"
elif [ "${gen_after:-0}" -gt "${gen_before:-0}" ]; then
    ok "generation oracle advanced ($gen_before -> $gen_after)"
else
    bad "generation oracle did not advance ($gen_before -> $gen_after)"
fi

# Rule-count sweep across the inner-map sizing floor.
#
# deny_inode is right-sized per reload from a hint; everything else uses its
# template maximum. When the hint was wrong the map was pinned at the 64-entry
# floor and any policy above it failed to apply. 64 and 65 are the exact
# boundary, so they are tested explicitly rather than assumed from a round
# number, and each count is applied twice to cover reload as well as first
# apply.
mkdir -p "$WORK/sweep"
sweep_failed=0
for count in 1 64 65 256; do
    conf="$WORK/sweep/p$count.conf"
    printf 'version=6\n\n[deny_path]\n' > "$conf"
    for i in $(seq 1 "$count"); do
        f="$WORK/sweep/f${count}_$i"
        echo body > "$f"
        echo "$f" >> "$conf"
    done
    if ! "$BIN" policy apply "$conf" >"$WORK/sweep/apply_$count.log" 2>&1; then
        bad "$count-rule policy failed on first apply"
        grep -iE "error|fail" "$WORK/sweep/apply_$count.log" | tail -2
        sweep_failed=1
        continue
    fi
    if ! "$BIN" policy apply "$conf" >>"$WORK/sweep/apply_$count.log" 2>&1; then
        bad "$count-rule policy failed on reload"
        sweep_failed=1
        continue
    fi
    if cat "$WORK/sweep/f${count}_1" >/dev/null 2>&1; then
        bad "$count-rule policy applied but is not enforced"
        sweep_failed=1
    fi
done
[ "$sweep_failed" -eq 0 ] && ok "rule-count sweep 1/64/65/256 applies, reloads and enforces"

# A policy larger than the inner-map floor.
#
# deny_inode is the one slotted map right-sized per reload, so its size hint
# must cover every inode-producing rule. When it did not, inserts failed with
# E2BIG partway through and any policy with more than ~64 file rules could
# never be applied -- safely (the old generation stayed live) but fatally for
# real use. 200 rules is comfortably past that floor.
mkdir -p "$WORK/many"
: > "$WORK/big.conf"
printf 'version=6\n\n[deny_path]\n' >> "$WORK/big.conf"
for i in $(seq 1 200); do
    echo body > "$WORK/many/f$i"
    echo "$WORK/many/f$i" >> "$WORK/big.conf"
done
if "$BIN" policy apply "$WORK/big.conf" >"$WORK/big.log" 2>&1; then
    ok "policy with 200 file rules applied"
else
    bad "policy with 200 file rules failed to apply (inner-map sizing?)"
    grep -iE "error|fail" "$WORK/big.log" | tail -3
fi
cat "$WORK/many/f1" >/dev/null 2>&1 && bad "large policy not enforced" \
                                    || ok "large policy enforced"

# Restore the small policy: the checks below assert on its target, and the
# large policy above does not contain it.
"$BIN" policy apply "$WORK/p1.conf" >/dev/null 2>&1

# Staging failure must not disturb the live generation.
"$BIN" policy apply /nonexistent/policy.conf >/dev/null 2>&1
cat /tmp/aegis_validate_target >/dev/null 2>&1 \
    && bad "a failed reload dropped enforcement" \
    || ok "failed reload left the previous generation enforcing"

# Restart adoption.
kill -9 $DPID 2>/dev/null; wait $DPID 2>/dev/null
"$BIN" run --enforce --enforce-signal=none --allow-unsigned-bpf --log-level=info \
    > "$WORK/daemon2.log" 2>&1 &
DPID2=$!
for _ in $(seq 1 40); do grep -q "Agent started" "$WORK/daemon2.log" && break; sleep 0.5; done
if grep -qE "Policy slots bootstrapped \{active_slot=[01], inner_maps_created=0\}" "$WORK/daemon2.log"; then
    ok "restart adopted the committed generation without rebuilding it"
else
    bad "restart did not adopt the existing generation"
    grep -i bootstrapped "$WORK/daemon2.log" | tail -2
fi
cat /tmp/aegis_validate_target >/dev/null 2>&1 \
    && bad "policy not enforced after restart" || ok "policy still enforced after restart"

kill -9 $DPID2 2>/dev/null; wait $DPID2 2>/dev/null
rm -rf "$PINDIR"; rm -f /tmp/aegis_validate_target

say "result"
if [ "$failures" -eq 0 ]; then
    echo "PASS: atomic policy swap validated on $(uname -r)"
    exit 0
fi
echo "FAIL: $failures check(s) failed on $(uname -r)"
exit 1
