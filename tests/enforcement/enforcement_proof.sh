#!/usr/bin/env bash
#
# Enforcement proof harness — Step 1 of docs/ENFORCEMENT_WEDGE_STRATEGY.md.
#
# Boots the REAL artifact via the shipped `policy apply` -> `run` flow (two
# separate processes, exactly as the systemd unit does) and proves, behaviorally:
#
#   1. The "No Pretend Enforce Invariant": the daemon reaches runtime_state
#      ENFORCE, or it refuses to claim enforce. It must NEVER report ENFORCE
#      while a deny class silently leaks.
#   2. Every enforcement class actually denies: the denied syscall returns
#      -EPERM (or the action provably does not occur), attempted from a
#      NON-exempt cgroup (the agent self-exempts its own cgroup, so probes run
#      via `systemd-run --scope`).
#   3. No silent downgrade: posture is still ENFORCE after the probes.
#
# Enforcement uses --enforce-signal=none so the ONLY enforcement mechanism under
# test is the synchronous BPF-LSM -EPERM deny (no SIGKILL/SIGTERM masking the
# result). This is the determinism claim, made testable.
#
# Exit codes: 0 = all asserted classes blocked + posture honest.
#             1 = a class leaked, or the daemon claimed enforce dishonestly.
#             77 = skipped (no BPF-LSM / not root / missing toolchain) — the
#                  daemon correctly refused to pretend, nothing to assert.
#
# Env overrides:
#   AEGIS_BIN       path to the aegisbpf binary  (default: build/aegisbpf)
#   AEGIS_BPF_OBJ   path to aegis.bpf.o          (default: build/aegis.bpf.o)
#
set -uo pipefail

# ---------------------------------------------------------------- locate inputs
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${AEGIS_BIN:-$REPO_ROOT/build/aegisbpf}"
BPF_OBJ="${AEGIS_BPF_OBJ:-$REPO_ROOT/build/aegis.bpf.o}"

log()  { printf '%s %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; }
ok()   { printf '\033[32mPASS\033[0m %s\n' "$*"; }
skip() { printf '\033[33mSKIP\033[0m %s\n' "$*"; }

[ -x "$BIN" ]      || { skip "binary not found: $BIN (set AEGIS_BIN)"; exit 77; }
[ -f "$BPF_OBJ" ]  || { skip "bpf object not found: $BPF_OBJ (set AEGIS_BPF_OBJ)"; exit 77; }
[ "$(id -u)" -eq 0 ] || { skip "must run as root (BPF-LSM enforcement needs CAP_*)"; exit 77; }
command -v systemd-run >/dev/null 2>&1 || { skip "systemd-run unavailable (need separate cgroup for probes)"; exit 77; }

export AEGIS_BPF_OBJ="$BPF_OBJ"
export AEGIS_ALLOW_UNSIGNED_BPF=1

WORK="$(mktemp -d /tmp/aegis-proof.XXXXXX)"
REPORT="$WORK/capabilities.json"
RUN_LOG="$WORK/run.log"
DAEMON_PID=""

cleanup() {
  [ -n "$DAEMON_PID" ] && kill -TERM "$DAEMON_PID" 2>/dev/null
  sleep 0.5
  pkill -TERM -f "aegisbpf run" 2>/dev/null
  rm -rf /sys/fs/bpf/aegisbpf 2>/dev/null
  rm -rf "$WORK" 2>/dev/null
}
trap cleanup EXIT

# ---------------------------------------------------------------- probe payloads
DENIED_FILE="$WORK/denied_secret"
echo "top secret" > "$DENIED_FILE"
DENIED_EXE="$WORK/aegis_denied_x"   # comm == basename, <=15 chars
cp /bin/true "$DENIED_EXE" 2>/dev/null || { skip "cannot stage exec probe"; exit 77; }
chmod +x "$DENIED_EXE"

# Compile the syscall-level probes (ptrace / bpf / connect) once.
HAVE_CC=1
command -v cc >/dev/null 2>&1 || HAVE_CC=0
if [ "$HAVE_CC" -eq 1 ]; then
  cat > "$WORK/p_ptrace.c" <<'C'
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
int main(void){
  pid_t c = fork();
  if (c==0){ pause(); _exit(0); }
  usleep(50000);
  long r = ptrace(PTRACE_ATTACH, c, 0, 0);
  int e = errno;
  if (r==0){ waitpid(c,0,0); ptrace(PTRACE_DETACH,c,0,0); kill(c,9); printf("attached\n"); return 1; }
  kill(c,9); waitpid(c,0,0);
  if (e==EPERM){ printf("EPERM\n"); return 0; }
  printf("errno=%d\n", e); return 2;  /* failed for another reason — inconclusive */
}
C
  cat > "$WORK/p_bpf.c" <<'C'
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
int main(void){
  struct bpf_insn insns[] = {
    { .code=0xb7, .dst_reg=0, .src_reg=0, .off=0, .imm=0 }, /* mov r0, 0 */
    { .code=0x95, .dst_reg=0, .src_reg=0, .off=0, .imm=0 }, /* exit */
  };
  union bpf_attr a; memset(&a,0,sizeof(a));
  a.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
  a.insn_cnt = 2;
  a.insns = (unsigned long)insns;
  char lic[]="GPL"; a.license=(unsigned long)lic;
  int fd = syscall(SYS_bpf, BPF_PROG_LOAD, &a, sizeof(a));
  int e = errno;
  if (fd>=0){ close(fd); printf("loaded\n"); return 1; }
  if (e==EPERM){ printf("EPERM\n"); return 0; }
  printf("errno=%d\n", e); return 2;
}
C
  cat > "$WORK/p_connect.c" <<'C'
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
int main(void){
  signal(SIGALRM, SIG_DFL); alarm(3);
  int s = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in sa; sa.sin_family=AF_INET; sa.sin_port=htons(80);
  inet_pton(AF_INET, "240.0.0.1", &sa.sin_addr);   /* denied CIDR 240.0.0.0/4 */
  int r = connect(s, (struct sockaddr*)&sa, sizeof(sa));
  int e = errno; close(s);
  if (r==0){ printf("connected\n"); return 1; }
  if (e==EPERM){ printf("EPERM\n"); return 0; }
  printf("errno=%d\n", e); return 2;
}
C
  cc -O0 -o "$WORK/p_ptrace" "$WORK/p_ptrace.c" 2>/dev/null || HAVE_CC=0
  cc -O0 -o "$WORK/p_bpf"     "$WORK/p_bpf.c"     2>/dev/null || HAVE_CC=0
  cc -O0 -o "$WORK/p_connect" "$WORK/p_connect.c" 2>/dev/null || HAVE_CC=0
fi

# ---------------------------------------------------------------- policy (all classes)
POLICY="$WORK/proof.conf"
cat > "$POLICY" <<EOF
version=1

[deny_module_load]

[deny_ptrace]

[deny_bpf]

[deny_path]
$DENIED_FILE

[deny_comm]
aegis_denied_x

[deny_cidr]
240.0.0.0/4
EOF

# ---------------------------------------------------------------- boot real flow
rm -rf /sys/fs/bpf/aegisbpf 2>/dev/null
log "STEP A: policy apply --reset  (systemd ExecStartPre analog)"
"$BIN" policy apply "$POLICY" --reset >"$WORK/apply.log" 2>&1 || { fail "policy apply failed"; cat "$WORK/apply.log"; exit 1; }

log "STEP B: run --enforce --enforce-signal=none  (separate process, ExecStart analog)"
AEGIS_CAPABILITIES_REPORT_PATH="$REPORT" \
  "$BIN" run --enforce --enforce-gate-mode=fail-closed --enforce-signal=none \
  >"$RUN_LOG" 2>&1 &
DAEMON_PID=$!

read_state() { grep -oE '"runtime_state"[ ]*:[ ]*"[A-Z_]+"' "$REPORT" 2>/dev/null | grep -oE '[A-Z_]+"$' | tr -d '"' | tail -1; }

STATE=""
for _ in $(seq 1 60); do
  kill -0 "$DAEMON_PID" 2>/dev/null || break
  STATE="$(read_state)"
  [ -n "$STATE" ] && break
  sleep 0.25
done

# ---------------------------------------------------------------- No-Pretend invariant
if [ "$STATE" != "ENFORCE" ]; then
  # The daemon did NOT claim enforce. On a host without BPF-LSM (fail-closed)
  # this is the CORRECT, honest behavior — there is nothing to assert.
  if grep -qiE 'BPF_LSM_DISABLED|CAPABILITY_AUDIT_ONLY|enforce.*refus|fail.closed' "$RUN_LOG" "$REPORT" 2>/dev/null; then
    skip "daemon honestly refused enforce (state='${STATE:-none}') — no BPF-LSM. No-Pretend invariant HELD."
    exit 77
  fi
  fail "daemon never reached ENFORCE (state='${STATE:-none}') and gave no blocker reason"
  echo "---- run.log (tail) ----"; tail -20 "$RUN_LOG"
  exit 1
fi
ok "No-Pretend invariant: runtime_state=ENFORCE"

# ---------------------------------------------------------------- per-class probes
RESULT=0
scope() { systemd-run --scope --quiet "$@" 2>/dev/null; }   # run in a fresh (non-exempt) cgroup

assert_blocked() {  # $1=class label  $2=0 if blocked  $3=detail
  if [ "$2" -eq 0 ]; then ok   "class '$1' BLOCKED ($3)";
  else                    fail "class '$1' LEAKED ($3)"; RESULT=1; fi
}

# module: cpuid (or fallback) must not load
MOD=""
for m in cpuid msr crc32_generic; do lsmod | grep -q "^$m " || { MOD="$m"; break; }; done
if [ -n "$MOD" ]; then
  scope modprobe "$MOD"
  if lsmod | grep -q "^$MOD "; then rmmod "$MOD" 2>/dev/null; assert_blocked module 1 "$MOD loaded"; else assert_blocked module 0 "$MOD not loaded"; fi
else skip "module: no unloaded candidate module available"; fi

# file: open() of denied path must fail
scope --pipe cat "$DENIED_FILE" >/dev/null 2>&1
assert_blocked file "$(( $? == 0 ? 1 : 0 ))" "open($DENIED_FILE)"

# exec: denied comm must not execute
if scope "$DENIED_EXE"; then assert_blocked exec 1 "ran $DENIED_EXE"; else assert_blocked exec 0 "exec denied"; fi

# ptrace / bpf / network: syscall-level EPERM
if [ "$HAVE_CC" -eq 1 ]; then
  scope "$WORK/p_ptrace";  assert_blocked ptrace  "$?" "PTRACE_ATTACH"
  scope "$WORK/p_bpf";     assert_blocked bpf     "$?" "BPF_PROG_LOAD"
  scope "$WORK/p_connect"; assert_blocked network "$?" "connect 240.0.0.1:80"
else
  skip "ptrace/bpf/network: no C compiler to build syscall probes"
fi

# ---------------------------------------------------------------- bypass probes
# Behavioral regressions for docs/BYPASS_CATALOG.md. [deny_path] resolves to the
# target INODE, so inode-aliasing bypasses (symlink / hardlink / rename to the
# same inode) must STILL be denied. A `bypass SUCCEEDED` result means enforcement
# was circumvented. Each probe name here is the regression anchor the bypass
# catalog binds to (validate_bypass_catalog.py greps for `assert_bypass <name>`).
assert_bypass() {  # $1=name  $2=0 if STILL blocked (bypass failed)  $3=detail
  if [ "$2" -eq 0 ]; then ok   "bypass '$1' BLOCKED ($3)";
  else                    fail "bypass '$1' SUCCEEDED — enforcement circumvented ($3)"; RESULT=1; fi
}
BSL="$WORK/byp_symlink"; BHL="$WORK/byp_hardlink"; BRN="$WORK/byp_renamed"

ln -s "$DENIED_FILE" "$BSL" 2>/dev/null
scope --pipe cat "$BSL" >/dev/null 2>&1
assert_bypass symlink "$(( $? == 0 ? 1 : 0 ))" "read denied inode via symlink"

if ln "$DENIED_FILE" "$BHL" 2>/dev/null; then
  scope --pipe cat "$BHL" >/dev/null 2>&1
  assert_bypass hardlink "$(( $? == 0 ? 1 : 0 ))" "read denied inode via hardlink"
else
  skip "bypass 'hardlink': cannot hardlink across this filesystem"
fi

BBM="$WORK/byp_bindmount"; : > "$BBM"
if mount --bind "$DENIED_FILE" "$BBM" 2>/dev/null; then
  scope --pipe cat "$BBM" >/dev/null 2>&1
  assert_bypass bindmount "$(( $? == 0 ? 1 : 0 ))" "read denied inode via bind mount"
  umount "$BBM" 2>/dev/null || true
else
  skip "bypass 'bindmount': cannot bind mount target"
fi

# rename the denied file itself: inode is unchanged, so the deny must follow it.
# Done last (it moves $DENIED_FILE); restored best-effort afterwards.
if mv "$DENIED_FILE" "$BRN" 2>/dev/null; then
  scope --pipe cat "$BRN" >/dev/null 2>&1
  assert_bypass rename "$(( $? == 0 ? 1 : 0 ))" "read denied inode after rename"
  mv "$BRN" "$DENIED_FILE" 2>/dev/null || true
else
  skip "bypass 'rename': cannot rename target"
fi

# ---------------------------------------------------------------- no silent downgrade
STATE2="$(read_state)"
if [ "$STATE2" != "ENFORCE" ]; then
  fail "posture downgraded during probes: ENFORCE -> '$STATE2'"
  RESULT=1
else
  ok "no silent downgrade: runtime_state still ENFORCE"
fi

echo "--------------------------------------------------"
[ "$RESULT" -eq 0 ] && log "RESULT: all asserted enforcement classes BLOCKED, posture honest." \
                    || log "RESULT: enforcement leak or dishonest posture detected."
exit "$RESULT"
