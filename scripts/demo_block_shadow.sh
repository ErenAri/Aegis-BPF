#!/usr/bin/env bash
# Proof-oriented file deny demo. Run ONLY on an isolated/disposable BPF-LSM test host.
set -euo pipefail

BIN="${AEGIS_BIN:-./build/aegisbpf}"
DEMO_DIR=""
AGENT_PID=""
RULE_INSTALLED=0

cleanup() {
  local rc=$?
  trap - EXIT
  set +e
  if [[ "$RULE_INSTALLED" -eq 1 ]]; then
    "$BIN" block del "$DEMO_DIR/secret" >/dev/null 2>&1
  fi
  if [[ -n "$AGENT_PID" ]]; then
    kill "$AGENT_PID" >/dev/null 2>&1
    wait "$AGENT_PID" >/dev/null 2>&1
  fi
  if [[ $rc -ne 0 && -n "$DEMO_DIR" && -f "$DEMO_DIR/agent.log" ]]; then
    echo "Demo failed; agent log follows:" >&2
    tail -n 60 "$DEMO_DIR/agent.log" >&2
  fi
  if [[ -n "$DEMO_DIR" ]]; then
    rm -rf -- "$DEMO_DIR"
  fi
  exit "$rc"
}
trap cleanup EXIT

if [[ "$EUID" -ne 0 ]]; then
  echo "Run as root on a disposable test host: sudo $0" >&2
  exit 1
fi
if [[ ! -x "$BIN" ]]; then
  echo "Executable not found: $BIN (build AegisBPF first)" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to verify the exact denial errno" >&2
  exit 1
fi
if [[ ! -r /sys/kernel/security/lsm ]] || ! grep -qw bpf /sys/kernel/security/lsm; then
  echo "BPF LSM is not enabled; refusing to claim an enforcement demo passed" >&2
  exit 1
fi
if [[ ! -f /sys/fs/cgroup/cgroup.controllers || ! -r /sys/kernel/btf/vmlinux ]]; then
  echo "cgroup v2 and readable kernel BTF are required" >&2
  exit 1
fi

umask 077
DEMO_DIR="$(mktemp -d -t aegisbpf-file-demo.XXXXXXXX)"
TARGET="$DEMO_DIR/secret"
printf 'temporary-demo-data\n' > "$TARGET"
cat "$TARGET" >/dev/null
echo "Baseline: the temporary test file is readable."

"$BIN" run --enforce --strict-degrade --enforce-signal=none --log=stdout --log-format=json > "$DEMO_DIR/agent.log" 2>&1 &
AGENT_PID=$!
sleep 2
if ! kill -0 "$AGENT_PID" 2>/dev/null; then
  echo "Enforcement agent exited before the test" >&2
  exit 1
fi

"$BIN" block add "$TARGET"
RULE_INSTALLED=1

python3 - "$TARGET" <<'PY'
import errno
import os
import sys

try:
    fd = os.open(sys.argv[1], os.O_RDONLY)
except OSError as exc:
    if exc.errno == errno.EPERM:
        print("PASS: BPF-LSM deny observed (open returned EPERM).")
        sys.exit(0)
    print(f"FAIL: open returned errno={exc.errno}, not EPERM.", file=sys.stderr)
    sys.exit(1)
else:
    os.close(fd)
    print("FAIL: denied file was still readable.", file=sys.stderr)
    sys.exit(1)
PY

if ! kill -0 "$AGENT_PID" 2>/dev/null; then
  echo "FAIL: the agent exited during the demonstration" >&2
  exit 1
fi
echo "Only this demo's rule and temporary directory will be removed."
