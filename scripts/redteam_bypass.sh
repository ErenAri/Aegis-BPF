#!/usr/bin/env bash
#
# redteam_bypass.sh — adversarial bypass harness for AegisBPF file-deny enforcement.
#
# Unlike the e2e_*_matrix / smoke_* scripts (which prove the agent BLOCKS what it
# should), this script actively tries to DEFEAT a block on a live kernel: it denies
# one file, then reaches that same inode through a battery of path-aliasing and TOCTOU
# tricks. Enforcement is inode-keyed (the LSM hook reads {i_ino, i_sb->s_dev} after all
# path resolution), so every aliasing attack SHOULD still be blocked. A "copy" control
# targets a *different* inode and SHOULD remain readable — that is identity enforcement,
# not content enforcement, and we assert it explicitly so the honest limit is visible.
#
# Verdict semantics per test:
#   expected BLOCKED  -> enforcement must deny the access (a success = real bypass = FAIL)
#   expected ALLOWED  -> access must succeed (a control; a denial = over-block = FAIL)
#
# Exit 0 iff every test matched its expectation. Needs root + BPF-LSM. Self-cleans.
#
# Env: BIN (agent path), AGGRESSIVE=1 (also run write-access probes on the denied inode).

set -uo pipefail # NOT -e: blocked accesses fail commands on purpose.

BIN="${BIN:-./build/aegisbpf}"
AGGRESSIVE="${AGGRESSIVE:-0}"

die() {
    echo "[!] $*" >&2
    exit 1
}

[[ $EUID -eq 0 ]] || die "must run as root (needs BPF-LSM)"
[[ -x "$BIN" ]] || die "agent not found at $BIN (build first)"
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null || die "BPF-LSM not enabled"
command -v python3 >/dev/null 2>&1 || die "python3 required for the /proc/self/fd probe"

WORK="$(mktemp -d /tmp/aegis-redteam.XXXXXX)"
LOG="$(mktemp)"
AGENT_PID=""

cleanup() {
    if [[ -n "$AGENT_PID" ]]; then
        kill "$AGENT_PID" 2>/dev/null || true
        wait "$AGENT_PID" 2>/dev/null || true
    fi
    "$BIN" block clear >/dev/null 2>&1 || true
    mountpoint -q "$WORK/bindmnt" 2>/dev/null && umount "$WORK/bindmnt" 2>/dev/null || true
    rm -rf "$WORK" "$LOG"
}
trap cleanup EXIT

# --- bring up enforcement (signal=none => deny with EACCES, do NOT kill the test proc) ---
"$BIN" block clear >/dev/null 2>&1 || true
"$BIN" run --enforce --enforce-signal=none >"$LOG" 2>&1 &
AGENT_PID=$!
sleep 2
kill -0 "$AGENT_PID" 2>/dev/null || {
    echo "[!] agent failed to start; log:" >&2
    cat "$LOG" >&2
    exit 1
}

# read_ok <path>: 0 if we managed to read a byte (access went through), nonzero if denied.
read_ok() { dd if="$1" bs=1 count=1 status=none >/dev/null 2>&1; }

PASS=0
FAIL=0
printf '\n%-22s %-10s %-10s %s\n' "TEST" "EXPECT" "ACTUAL" "VERDICT"
printf '%s\n' "-------------------------------------------------------------"

# attempt <name> <BLOCKED|ALLOWED> <cmd...>
# <cmd> must return 0 iff the access SUCCEEDED (data reached the attacker).
attempt() {
    local name="$1" expect="$2"
    shift 2
    local actual
    if "$@"; then actual="ALLOWED"; else actual="BLOCKED"; fi
    local verdict
    if [[ "$actual" == "$expect" ]]; then
        verdict="PASS"
        PASS=$((PASS + 1))
    else
        verdict="*** FAIL ***"
        FAIL=$((FAIL + 1))
    fi
    printf '%-22s %-10s %-10s %s\n' "$name" "$expect" "$actual" "$verdict"
}

# ---------------------------------------------------------------------------
# Primary denied target.
SECRET="$WORK/secret"
echo "TOPSECRET" >"$SECRET"
# Independent copy taken BEFORE the block: same bytes, a different inode. Used by the
# copy-new-inode control to show enforcement is by file identity, not content pattern.
# (Made before the block because once denied, even reading-to-copy the original fails —
# which is itself correct, and is exercised by the read tests below.)
cp "$SECRET" "$WORK/copy"
"$BIN" block add "$SECRET" >/dev/null 2>&1 || die "block add failed"

# 1. Baseline: the denied path itself must be blocked (sanity that the gate is live).
attempt "direct" BLOCKED read_ok "$SECRET"

# 2. Hardlink: same inode under a new name. Path-based blockers miss this; inode-keying must not.
ln "$SECRET" "$WORK/hardlink"
attempt "hardlink" BLOCKED read_ok "$WORK/hardlink"

# 3. Symlink: resolves to the denied inode.
ln -s "$SECRET" "$WORK/symlink"
attempt "symlink" BLOCKED read_ok "$WORK/symlink"

# 4. /proc/self/fd reopen via O_PATH (O_PATH skips MAY_READ; reopen must re-trigger the hook).
proc_self_fd() {
    python3 - "$SECRET" <<'PY'
import os, sys
try:
    pfd = os.open(sys.argv[1], os.O_PATH)
    rfd = os.open("/proc/self/fd/%d" % pfd, os.O_RDONLY)  # real read open -> hook fires
    os.read(rfd, 1)
    sys.exit(0)   # got data == bypass
except OSError:
    sys.exit(1)   # denied == held
PY
}
attempt "proc-self-fd" BLOCKED proc_self_fd

# 5. /proc/self/cwd magic link.
proc_cwd() { ( cd "$WORK" && read_ok "/proc/self/cwd/secret" ); }
attempt "proc-self-cwd" BLOCKED proc_cwd

# 6. Non-canonical relative path with .. traversal.
mkdir -p "$WORK/sub"
attempt "relative-dotdot" BLOCKED read_ok "$WORK/sub/../secret"

# 7. Bind mount: same superblock => same s_dev => same key. Read via a different mount path.
mkdir -p "$WORK/bindmnt"
if mount --bind "$WORK" "$WORK/bindmnt" 2>/dev/null; then
    attempt "bind-mount" BLOCKED read_ok "$WORK/bindmnt/secret"
    umount "$WORK/bindmnt" 2>/dev/null || true
else
    printf '%-22s %-10s %-10s %s\n' "bind-mount" "BLOCKED" "SKIP" "(mount --bind unavailable)"
fi

# 8. Hardlink created BEFORE the block, accessed after — the inode is what's denied.
PRELINK="$WORK/prelink_src"
echo "PRE" >"$PRELINK"
ln "$PRELINK" "$WORK/prelink_alias"
"$BIN" block add "$PRELINK" >/dev/null 2>&1
attempt "hardlink-pre-block" BLOCKED read_ok "$WORK/prelink_alias"

# 9. Rename the denied file, then read the new name (inode survives rename).
REN="$WORK/rename_src"
echo "REN" >"$REN"
"$BIN" block add "$REN" >/dev/null 2>&1
mv "$REN" "$WORK/rename_dst"
attempt "rename-then-read" BLOCKED read_ok "$WORK/rename_dst"

# 10. TOCTOU rename race: flip the name under a tight read loop; any single read win = bypass.
RACE="$WORK/race"
echo "RACE" >"$RACE"
"$BIN" block add "$RACE" >/dev/null 2>&1
race_bypass() {
    ( for _ in $(seq 1 200); do mv "$WORK/race" "$WORK/race2" 2>/dev/null; mv "$WORK/race2" "$WORK/race" 2>/dev/null; done ) &
    local mover=$!
    local won=1
    for _ in $(seq 1 200); do
        if read_ok "$WORK/race" || read_ok "$WORK/race2"; then won=0; break; fi
    done
    kill "$mover" 2>/dev/null; wait "$mover" 2>/dev/null
    return $won # 0 == a read won the race (bypass)
}
attempt "rename-race-toctou" BLOCKED race_bypass

# 11. CONTROL — the pre-block copy is a NEW inode with identical bytes. It must remain
#     readable: this is identity enforcement, not content enforcement (the honest limit).
attempt "copy-new-inode" ALLOWED read_ok "$WORK/copy"

# --- AGGRESSIVE: write-access probes on the denied inode (default off) -------
if [[ "$AGGRESSIVE" == "1" ]]; then
    # Truncate-open: O_WRONLY|O_TRUNC must hit file_open on the denied inode.
    # Subshell with stderr muted so the shell's own redirect-failure line stays quiet.
    trunc() { ( exec 2>/dev/null; : >"$SECRET" ); }
    attempt "write-trunc" BLOCKED trunc
    # Append write.
    appnd() { ( exec 2>/dev/null; printf x >>"$SECRET" ); }
    attempt "write-append" BLOCKED appnd
fi

# ---------------------------------------------------------------------------
echo
echo "block events logged by agent: $(grep -c '"type":"block"' "$LOG" 2>/dev/null || echo '?')"
echo "ringbuf drops: $(grep -oE 'Ringbuf drops: [0-9]+' "$LOG" 2>/dev/null | tail -1 || echo 'n/a')"
echo
echo "RESULT: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
