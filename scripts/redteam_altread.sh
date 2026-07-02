#!/usr/bin/env bash
#
# redteam_altread.sh — adversarial "alternate read-path" harness for AegisBPF
# file-deny enforcement.
#
# redteam_bypass.sh proves the deny survives *path aliasing* (hardlink/symlink/
# bind-mount/rename/TOCTOU). This harness attacks a different axis: reaching a
# denied file's CONTENT through read paths that do not look like a plain open() —
# the places where an LSM file gate most plausibly has a hole:
#
#   * io_uring IORING_OP_OPENAT + IORING_OP_READ  (async / io-wq kernel-worker
#     context — historically the richest source of LSM-bypass CVEs)
#   * open_by_handle_at()  (reopen by NFS-style file handle, skipping path lookup)
#   * openat2()            (the newer open syscall with RESOLVE_* flags)
#
# AegisBPF gates the read path with TWO inode-keyed LSM hooks — lsm/file_open AND
# lsm/inode_permission — both reading {i_ino, i_sb->s_dev}. Every VFS open,
# however it is issued, funnels through may_open()->inode_permission and
# security_file_open, so all three attacks above SHOULD be denied. A success is a
# real enforcement hole.
#
# It also documents, as EXPECTED-ALLOWED controls, the honest boundaries of any
# open-time inode LSM (these are NOT bugs — they are the shape of the mechanism):
#
#   * pre-block fd survives  — an fd opened BEFORE the rule keeps working; read()
#     on an open fd re-triggers neither hook. Deny is not retroactive.
#   * raw block-device read  — reading the backing block device bypasses the VFS
#     entirely; the target inode's hooks never fire. Defense is block-level
#     (dm-verity / encryption), not a file LSM's job.
#
# Verdict semantics per test:
#   expected BLOCKED  -> access must be denied (a success = real bypass = FAIL)
#   expected ALLOWED  -> access must succeed (a control; denial = over-block = FAIL)
#
# Exit 0 iff every test matched expectation. Needs root + BPF-LSM + a C compiler.
# Self-cleans (agent, loop mount, temp dir).
#
# Env: BIN (agent path, default ./build/aegisbpf)

set -uo pipefail  # NOT -e: denied accesses fail commands on purpose.

BIN="${BIN:-./build/aegisbpf}"
MARKER="AEGIS_ALTREAD_TOPSECRET_7f3a91"

die() { echo "[!] $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root (needs BPF-LSM)"
[[ -x "$BIN" ]] || die "agent not found at $BIN (build first)"
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null || die "BPF-LSM not enabled"
command -v cc >/dev/null 2>&1 || die "cc (C compiler) required"
command -v python3 >/dev/null 2>&1 || die "python3 required for openat2 probe"

WORK="$(mktemp -d /tmp/aegis-altread.XXXXXX)"
LOG="$(mktemp)"
AGENT_PID=""
LOOPDEV=""
MNT=""

cleanup() {
    [[ -n "$AGENT_PID" ]] && { kill "$AGENT_PID" 2>/dev/null; wait "$AGENT_PID" 2>/dev/null; }
    "$BIN" block clear >/dev/null 2>&1 || true
    [[ -n "$MNT" ]] && mountpoint -q "$MNT" 2>/dev/null && umount "$MNT" 2>/dev/null || true
    [[ -n "$LOOPDEV" ]] && losetup -d "$LOOPDEV" 2>/dev/null || true
    rm -rf "$WORK" "$LOG"
}
trap cleanup EXIT

# --------------------------------------------------------------------------
# Build the C helper (io_uring OPENAT+READ and open_by_handle_at).
# --------------------------------------------------------------------------
cat >"$WORK/altread.c" <<'CEOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <linux/io_uring.h>

static int sys_io_uring_setup(unsigned e, struct io_uring_params *p) {
    return (int)syscall(__NR_io_uring_setup, e, p);
}
static int sys_io_uring_enter(int fd, unsigned s, unsigned c, unsigned f) {
    return (int)syscall(__NR_io_uring_enter, fd, s, c, f, NULL, 0);
}

/* Submit one SQE (already filled) and reap one CQE; returns cqe.res. */
static int submit_reap(int ring, struct io_uring_sqe *sqes,
                       unsigned *sring_tail, unsigned *sring_mask, unsigned *sring_arr,
                       unsigned *cring_head, unsigned *cring_mask,
                       struct io_uring_cqe *cqes, struct io_uring_sqe *tmpl) {
    unsigned tail = *sring_tail, idx = tail & *sring_mask;
    memcpy(&sqes[idx], tmpl, sizeof(*tmpl));
    sring_arr[idx] = idx;
    __sync_synchronize();
    *sring_tail = tail + 1;
    __sync_synchronize();
    int r = sys_io_uring_enter(ring, 1, 1, IORING_ENTER_GETEVENTS);
    if (r < 0) return -errno;
    unsigned head = *cring_head;
    int res = cqes[head & *cring_mask].res;
    *cring_head = head + 1;
    __sync_synchronize();
    return res;
}

static int do_iouring(const char *path) {
    struct io_uring_params p;
    memset(&p, 0, sizeof(p));
    int ring = sys_io_uring_setup(8, &p);
    if (ring < 0) { fprintf(stderr, "io_uring_setup: %s\n", strerror(errno)); return 2; }

    size_t sqsz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    size_t cqsz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    if (p.features & IORING_FEAT_SINGLE_MMAP) { if (cqsz > sqsz) sqsz = cqsz; cqsz = sqsz; }

    void *sq = mmap(0, sqsz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_SQ_RING);
    if (sq == MAP_FAILED) { perror("mmap sq"); return 2; }
    void *cq = (p.features & IORING_FEAT_SINGLE_MMAP) ? sq
             : mmap(0, cqsz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_CQ_RING);
    if (cq == MAP_FAILED) { perror("mmap cq"); return 2; }
    struct io_uring_sqe *sqes = mmap(0, p.sq_entries * sizeof(struct io_uring_sqe),
                                     PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_SQES);
    if (sqes == MAP_FAILED) { perror("mmap sqes"); return 2; }

    unsigned *sring_tail = (unsigned *)((char *)sq + p.sq_off.tail);
    unsigned *sring_mask = (unsigned *)((char *)sq + p.sq_off.ring_mask);
    unsigned *sring_arr  = (unsigned *)((char *)sq + p.sq_off.array);
    unsigned *cring_head = (unsigned *)((char *)cq + p.cq_off.head);
    unsigned *cring_mask = (unsigned *)((char *)cq + p.cq_off.ring_mask);
    struct io_uring_cqe *cqes = (struct io_uring_cqe *)((char *)cq + p.cq_off.cqes);

    struct io_uring_sqe t;
    memset(&t, 0, sizeof(t));
    t.opcode = IORING_OP_OPENAT;
    t.fd = AT_FDCWD;
    t.addr = (uint64_t)(uintptr_t)path;
    t.open_flags = O_RDONLY;
    t.user_data = 1;
    int openres = submit_reap(ring, sqes, sring_tail, sring_mask, sring_arr,
                              cring_head, cring_mask, cqes, &t);
    printf("iouring OPENAT res=%d (%s)\n", openres, openres < 0 ? strerror(-openres) : "opened");
    if (openres < 0) return 1;  /* denied — enforcement held on the async open */

    char buf[64];
    memset(buf, 0, sizeof(buf));
    memset(&t, 0, sizeof(t));
    t.opcode = IORING_OP_READ;
    t.fd = openres;
    t.addr = (uint64_t)(uintptr_t)buf;
    t.len = sizeof(buf) - 1;
    t.user_data = 2;
    int readres = submit_reap(ring, sqes, sring_tail, sring_mask, sring_arr,
                              cring_head, cring_mask, cqes, &t);
    printf("iouring READ res=%d\n", readres);
    if (readres > 0) { printf("iouring DATA=[%.*s]\n", readres, buf); return 0; }  /* BYPASS */
    return 1;
}

static int do_handle(const char *path, const char *mountpath) {
    unsigned char fhbuf[sizeof(struct file_handle) + 128];
    struct file_handle *fh = (struct file_handle *)fhbuf;
    fh->handle_bytes = 128;
    int mid;
    if (name_to_handle_at(AT_FDCWD, path, fh, &mid, 0) < 0) {
        fprintf(stderr, "name_to_handle_at: %s\n", strerror(errno));
        return 2;  /* setup issue, not a verdict */
    }
    int mfd = open(mountpath, O_RDONLY | O_DIRECTORY);
    if (mfd < 0) { perror("open mount"); return 2; }
    int fd = open_by_handle_at(mfd, fh, O_RDONLY);
    if (fd < 0) { printf("open_by_handle_at res=-errno (%s)\n", strerror(errno)); return 1; }  /* denied */
    char b[8];
    int n = (int)read(fd, b, sizeof(b));
    printf("open_by_handle_at OPENED, read=%d\n", n);
    return n > 0 ? 0 : 1;  /* 0 => data exfiltrated == BYPASS */
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s iouring|handle <path> [mount]\n", argv[0]); return 2; }
    if (!strcmp(argv[1], "iouring")) return do_iouring(argv[2]);
    if (!strcmp(argv[1], "handle"))  return do_handle(argv[2], argc > 3 ? argv[3] : "/");
    fprintf(stderr, "unknown mode %s\n", argv[1]);
    return 2;
}
CEOF

cc -O2 -o "$WORK/altread" "$WORK/altread.c" 2>"$WORK/ccerr" || {
    echo "[!] failed to compile altread.c:" >&2; cat "$WORK/ccerr" >&2; exit 1;
}

# --------------------------------------------------------------------------
# Prefer a loopback ext4 fs: gives a real block device for the raw-read test
# and a normal inode for the VFS tests. Fall back to tmpfs if loop is unusable.
# --------------------------------------------------------------------------
BASE="$WORK"
RAW_ENABLED=0
if command -v mkfs.ext4 >/dev/null 2>&1 && command -v losetup >/dev/null 2>&1; then
    IMG="$WORK/fs.img"
    MNT="$WORK/mnt"
    if dd if=/dev/zero of="$IMG" bs=1M count=16 status=none 2>/dev/null \
       && mkfs.ext4 -q -F "$IMG" >/dev/null 2>&1 \
       && mkdir -p "$MNT" \
       && LOOPDEV="$(losetup --find --show "$IMG" 2>/dev/null)" \
       && mount "$LOOPDEV" "$MNT" 2>/dev/null; then
        BASE="$MNT"
        RAW_ENABLED=1
    else
        [[ -n "$LOOPDEV" ]] && losetup -d "$LOOPDEV" 2>/dev/null || true
        LOOPDEV=""; MNT=""
    fi
fi

# --- bring up enforcement (signal=none => deny with EPERM, do NOT kill us) ---
"$BIN" block clear >/dev/null 2>&1 || true
"$BIN" run --enforce --enforce-signal=none >"$LOG" 2>&1 &
AGENT_PID=$!
sleep 2
kill -0 "$AGENT_PID" 2>/dev/null || { echo "[!] agent failed to start:" >&2; cat "$LOG" >&2; exit 1; }

PASS=0; FAIL=0
printf '\n%-26s %-9s %-9s %s\n' "TEST" "EXPECT" "ACTUAL" "VERDICT"
printf '%s\n' "----------------------------------------------------------------------"

# attempt <name> <BLOCKED|ALLOWED> <cmd...>  ; <cmd> returns 0 iff access SUCCEEDED.
attempt() {
    local name="$1" expect="$2"; shift 2
    local actual
    if "$@" >>"$WORK/probe.out" 2>&1; then actual="ALLOWED"; else actual="BLOCKED"; fi
    local verdict
    if [[ "$actual" == "$expect" ]]; then verdict="PASS"; PASS=$((PASS + 1))
    else verdict="*** FAIL ***"; FAIL=$((FAIL + 1)); fi
    printf '%-26s %-9s %-9s %s\n' "$name" "$expect" "$actual" "$verdict"
}
skip() { printf '%-26s %-9s %-9s %s\n' "$1" "$2" "SKIP" "($3)"; }

# --------------------------------------------------------------------------
# Denied target.
# --------------------------------------------------------------------------
SECRET="$BASE/secret"
echo "$MARKER" >"$SECRET"
"$BIN" block add "$SECRET" >/dev/null 2>&1 || die "block add failed"

read_ok() { dd if="$1" bs=1 count=1 status=none >/dev/null 2>&1; }

# 0. Sanity: the plain open is denied (gate is live).
attempt "direct-open (sanity)" BLOCKED read_ok "$SECRET"

# 1. io_uring OPENAT + READ — async / io-wq worker context. MUST be denied.
attempt "io_uring-openat-read" BLOCKED "$WORK/altread" iouring "$SECRET"

# 2. open_by_handle_at — reopen by file handle, skipping path lookup. MUST be denied.
attempt "open_by_handle_at" BLOCKED "$WORK/altread" handle "$SECRET" "$BASE"

# 3. openat2 with RESOLVE flags — the newer open syscall. MUST be denied.
openat2_probe() {
    python3 - "$1" <<'PY'
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
class open_how(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]
how = open_how(os.O_RDONLY, 0, 0)
SYS_openat2 = 437
AT_FDCWD = -100
fd = libc.syscall(SYS_openat2, AT_FDCWD, sys.argv[1].encode(), ctypes.byref(how), ctypes.sizeof(how))
if fd < 0:
    sys.exit(1)   # denied
try:
    data = os.read(fd, 16)
    sys.exit(0 if data else 1)
except OSError:
    sys.exit(1)
PY
}
attempt "openat2" BLOCKED openat2_probe "$SECRET"

# --------------------------------------------------------------------------
# EXPECTED-ALLOWED honest boundaries (NOT bugs; documented limits).
# --------------------------------------------------------------------------

# 4. fd opened BEFORE the rule keeps working — deny is not retroactive.
preblock_test() {
    local f="$BASE/preblock"
    echo "$MARKER" >"$f"
    rm -f "$f.opened" "$f.go" "$f.rc"
    ( python3 - "$f" <<'PY' &
import os, sys, time
f = sys.argv[1]
fd = os.open(f, os.O_RDONLY)          # opened BEFORE block
open(f + ".opened", "w").close()
while not os.path.exists(f + ".go"):  # wait for the rule to be added
    time.sleep(0.02)
try:
    d = os.read(fd, 32)               # read AFTER block, on the pre-existing fd
    rc = 0 if d else 1
except OSError:
    rc = 1
open(f + ".rc", "w").write(str(rc))
PY
    )
    local t=0
    while [[ ! -e "$f.opened" && $t -lt 200 ]]; do sleep 0.02; t=$((t+1)); done
    "$BIN" block add "$f" >/dev/null 2>&1
    : >"$f.go"
    t=0; while [[ ! -e "$f.rc" && $t -lt 200 ]]; do sleep 0.02; t=$((t+1)); done
    [[ "$(cat "$f.rc" 2>/dev/null || echo 1)" == "0" ]]
}
attempt "preblock-fd-survives" ALLOWED preblock_test

# 5. Raw block-device read bypasses the VFS entirely (block-level, not file LSM).
if [[ "$RAW_ENABLED" == "1" ]]; then
    rawdev_test() {
        sync
        echo 3 >/proc/sys/vm/drop_caches 2>/dev/null || true
        grep -qa "$MARKER" "$LOOPDEV"    # read the backing block device directly
    }
    attempt "raw-block-device-read" ALLOWED rawdev_test
else
    skip "raw-block-device-read" "ALLOWED" "loop/mkfs.ext4 unavailable"
fi

# --------------------------------------------------------------------------
echo
echo "--- probe output ---"
[[ -s "$WORK/probe.out" ]] && sed 's/^/    /' "$WORK/probe.out"
echo
echo "block events logged by agent: $(grep -c '"type":"block"' "$LOG" 2>/dev/null || echo '?')"
echo
echo "RESULT: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
