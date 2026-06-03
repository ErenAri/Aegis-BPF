#!/usr/bin/env bash
#
# Behavioral proof for Tier-3 signal-fallback enforcement + the ENFORCE_SIGNAL
# gate promotion (docs/GUARANTEES.md "Signal-fallback").
#
# On a host WITHOUT BPF-LSM, lsm/file_open cannot attach and open() cannot be
# denied with -EPERM. When the operator opts in with --enforce-fallback=signal,
# the enforce-gate promotes to the honest, strictly-weaker ENFORCE_SIGNAL posture
# and the sys_enter_openat tracepoint terminates a process that opens a denied
# path via bpf_send_signal().
#
# We exercise the agent's REAL no-BPF-LSM code path on any kernel using the
# AEGIS_LSM_PATH test seam (kernel_features.cpp reads it instead of
# /sys/kernel/security/lsm). The kernel's actual BPF-LSM is irrelevant here: the
# agent believes BPF-LSM is absent, so it attaches ONLY the tracepoints — exactly
# what happens on a genuinely no-BPF-LSM kernel. The tracepoint+bpf_send_signal
# mechanism is kernel-version-independent.
#
# Asserts:
#   1. Gate promotion + No-Pretend: runtime_state == ENFORCE_SIGNAL,
#      audit_only == false, enforce_capable == false (the BPF_LSM_DISABLED
#      blocker keeps the node from claiming full ENFORCE).
#   2. Enforcement fires: a process opening the denied path from a non-exempt
#      cgroup is killed by a signal (exit > 128). Without the signal the open
#      would SUCCEED (there is no LSM -EPERM on this path), so a signal-kill is
#      unambiguous proof the tracepoint enforced.
#
# Exit: 0 all asserted; 1 a class leaked / posture dishonest; 77 skipped.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${AEGIS_BIN:-$REPO_ROOT/build/aegisbpf}"
BPF_OBJ="${AEGIS_BPF_OBJ:-$REPO_ROOT/build/aegis.bpf.o}"

ok()   { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; }
skip() { printf '\033[33mSKIP\033[0m %s\n' "$*"; }

[ -x "$BIN" ]     || { skip "binary not found: $BIN (set AEGIS_BIN)"; exit 77; }
[ -f "$BPF_OBJ" ] || { skip "bpf object not found: $BPF_OBJ (set AEGIS_BPF_OBJ)"; exit 77; }
[ "$(id -u)" -eq 0 ] || { skip "must run as root (BPF needs CAP_*)"; exit 77; }
command -v systemd-run >/dev/null 2>&1 || { skip "systemd-run unavailable (need a non-exempt cgroup)"; exit 77; }

W="$(mktemp -d /tmp/aegis-sigfb.XXXXXX)"
DAEMON_PID=""
cleanup() {
    [ -n "$DAEMON_PID" ] && kill -TERM "$DAEMON_PID" 2>/dev/null
    sleep 0.3
    pkill -TERM -f "aegisbpf run" 2>/dev/null
    rm -rf /sys/fs/bpf/aegisbpf 2>/dev/null
    rm -rf "$W" 2>/dev/null
}
trap cleanup EXIT

FAKE_LSM="$W/lsm"; echo "lockdown,capability,yama,apparmor" > "$FAKE_LSM"   # NOTE: no 'bpf'
DENIED="$W/denied_secret"; echo "top secret" > "$DENIED"
POLICY="$W/policy.conf"; printf 'version=1\n[deny_path]\n%s\n' "$DENIED" > "$POLICY"
REPORT="$W/cap.json"; RUNLOG="$W/run.log"

export AEGIS_BPF_OBJ="$BPF_OBJ"
export AEGIS_ALLOW_UNSIGNED_BPF=1
export AEGIS_LSM_PATH="$FAKE_LSM"     # force the no-BPF-LSM code path

"$BIN" policy apply "$POLICY" --reset >"$W/apply.log" 2>&1 || { fail "policy apply failed"; cat "$W/apply.log"; exit 1; }

AEGIS_CAPABILITIES_REPORT_PATH="$REPORT" \
    "$BIN" run --enforce --enforce-fallback=signal --enforce-gate-mode=audit-fallback >"$RUNLOG" 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 60); do [ -f "$REPORT" ] && break; kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.25; done
if ! kill -0 "$DAEMON_PID" 2>/dev/null; then fail "daemon exited during startup"; tail -20 "$RUNLOG"; exit 1; fi
[ -f "$REPORT" ] || { fail "no capability report produced"; tail -20 "$RUNLOG"; exit 1; }

rc=0
field() { grep -oE "\"$1\":[[:space:]]*[^,}]*" "$REPORT" | head -1 | sed -E "s/.*:[[:space:]]*//"; }

state="$(field runtime_state | tr -d '"')"
enforce_capable="$(field enforce_capable)"
audit_only="$(field audit_only)"

[ "$state" = "ENFORCE_SIGNAL" ] && ok "gate promoted to ENFORCE_SIGNAL" || { fail "runtime_state=$state (want ENFORCE_SIGNAL)"; rc=1; }
[ "$audit_only" = "false" ] && ok "audit_only=false (enforcing, not degraded)" || { fail "audit_only=$audit_only (want false)"; rc=1; }
[ "$enforce_capable" = "false" ] && ok "No-Pretend: enforce_capable=false (BPF_LSM_DISABLED honest)" \
    || { fail "enforce_capable=$enforce_capable (want false — must not claim full enforce)"; rc=1; }

sleep 0.5
# Open the denied path from a fresh (non-exempt) cgroup. Killed -> exit>128.
systemd-run --scope --quiet cat "$DENIED" >/dev/null 2>&1; probe=$?
if [ "$probe" -gt 128 ]; then
    ok "denied open killed by signal (exit=$probe)"
else
    fail "denied open NOT enforced (exit=$probe; expected signal kill >128)"; rc=1
fi

[ "$rc" -eq 0 ] && echo "signal-fallback proof: ALL PASS" || echo "signal-fallback proof: FAILURES"
exit "$rc"
