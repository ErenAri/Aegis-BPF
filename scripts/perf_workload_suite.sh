#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-${ROOT_DIR}/build/aegisbpf}"
FILE="${FILE:-/etc/hosts}"
OPEN_ITERATIONS="${OPEN_ITERATIONS:-200000}"
READ_ITERATIONS="${READ_ITERATIONS:-50000}"
CONNECT_ITERATIONS="${CONNECT_ITERATIONS:-50000}"
STAT_SAMPLE="${STAT_SAMPLE:-400}"
STAT_ITERATIONS="${STAT_ITERATIONS:-50}"
MAX_OPEN_PCT="${MAX_OPEN_PCT:-15}"
MAX_CONNECT_PCT="${MAX_CONNECT_PCT:-15}"
MAX_READ_PCT="${MAX_READ_PCT:-15}"
MAX_STAT_PCT="${MAX_STAT_PCT:-15}"
FORMAT="${FORMAT:-text}" # text|json
OUT="${OUT:-}"
PIN_CPUS="${PIN_CPUS:-1}"
BENCH_CPU="${BENCH_CPU:-}"
AGENT_CPU="${AGENT_CPU:-}"

if [[ "${PIN_CPUS}" -eq 1 ]] && command -v taskset >/dev/null 2>&1; then
    cpu_count="$(nproc 2>/dev/null || echo 1)"
    if [[ "${cpu_count}" -ge 2 ]]; then
        if [[ -z "${BENCH_CPU}" ]]; then
            BENCH_CPU="0"
        fi
        if [[ -z "${AGENT_CPU}" ]]; then
            AGENT_CPU="1"
        fi
    fi
fi

if [[ "$(id -u)" -ne 0 ]]; then
    echo "perf_workload_suite.sh must run as root (starts agent in audit mode)." >&2
    exit 1
fi

if [[ ! -x "${BIN}" ]]; then
    echo "aegisbpf binary not found or not executable: ${BIN}" >&2
    exit 1
fi

if [[ ! -r "${FILE}" ]]; then
    echo "Benchmark file is not readable: ${FILE}" >&2
    exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet aegisbpf.service; then
        echo "aegisbpf.service is active; stop it before running perf_workload_suite." >&2
        exit 1
    fi
fi

AGENT_PID=""
AGENT_LOG="$(mktemp)"
STAT_FILE_LIST="$(mktemp)"

cleanup() {
    set +e
    if [[ -n "${AGENT_PID}" ]]; then
        kill "${AGENT_PID}" >/dev/null 2>&1
        wait "${AGENT_PID}" >/dev/null 2>&1
    fi
    # Keep self-hosted runs isolated for subsequent jobs.
    "${BIN}" block clear >/dev/null 2>&1 || true
    "${BIN}" network deny clear >/dev/null 2>&1 || true
    rm -f "${AGENT_LOG}" "${STAT_FILE_LIST}"
}
trap cleanup EXIT

# Ensure stale pinned maps from previous jobs do not skew benchmarks.
"${BIN}" block clear >/dev/null 2>&1 || true
"${BIN}" network deny clear >/dev/null 2>&1 || true

# `find | head` exits with SIGPIPE under `set -o pipefail`; scope-disable pipefail.
set +o pipefail
find /usr/bin /usr/sbin /bin /sbin -type f 2>/dev/null | head -n "${STAT_SAMPLE}" >"${STAT_FILE_LIST}"
set -o pipefail
if [[ ! -s "${STAT_FILE_LIST}" ]]; then
    echo "${FILE}" >"${STAT_FILE_LIST}"
fi

start_agent() {
    if [[ -n "${AGENT_CPU}" ]] && command -v taskset >/dev/null 2>&1; then
        taskset -c "${AGENT_CPU}" "${BIN}" run --audit >"${AGENT_LOG}" 2>&1 &
    else
        "${BIN}" run --audit >"${AGENT_LOG}" 2>&1 &
    fi
    AGENT_PID=$!
    sleep 1
    if ! kill -0 "${AGENT_PID}" >/dev/null 2>&1; then
        echo "Agent failed to start; log follows:" >&2
        cat "${AGENT_LOG}" >&2
        exit 1
    fi
}

stop_agent() {
    if [[ -n "${AGENT_PID}" ]]; then
        kill "${AGENT_PID}" >/dev/null 2>&1 || true
        wait "${AGENT_PID}" >/dev/null 2>&1 || true
        AGENT_PID=""
    fi
}

run_read_bench() {
    local path="$1"
    local iterations="$2"
    PYTHON_PREFIX=()
    if [[ -n "${BENCH_CPU}" ]] && command -v taskset >/dev/null 2>&1; then
        PYTHON_PREFIX=(taskset -c "${BENCH_CPU}")
    fi
    "${PYTHON_PREFIX[@]}" python3 - <<PY
import os
import time

path = "${path}"
iterations = int("${iterations}")
start = time.perf_counter()
for _ in range(iterations):
    with open(path, "rb") as f:
        f.read()
end = time.perf_counter()
us_per_op = ((end - start) / iterations) * 1e6
print(f"{us_per_op:.2f}")
PY
}

run_stat_bench() {
    local list_path="$1"
    local iterations="$2"
    PYTHON_PREFIX=()
    if [[ -n "${BENCH_CPU}" ]] && command -v taskset >/dev/null 2>&1; then
        PYTHON_PREFIX=(taskset -c "${BENCH_CPU}")
    fi
    "${PYTHON_PREFIX[@]}" python3 - <<PY
import os
import time

with open("${list_path}", "r", encoding="utf-8") as f:
    files = [line.strip() for line in f if line.strip()]

iterations = int("${iterations}")
ops_per_iter = len(files)
if ops_per_iter == 0:
    print("0.00")
    raise SystemExit(0)

start = time.perf_counter()
for _ in range(iterations):
    for path in files:
        os.stat(path)
end = time.perf_counter()
total_ops = iterations * ops_per_iter
us_per_op = ((end - start) / total_ops) * 1e6
print(f"{us_per_op:.2f}")
PY
}

open_baseline=$(ITERATIONS="${OPEN_ITERATIONS}" FILE="${FILE}" FORMAT=text "${ROOT_DIR}/scripts/perf_open_bench.sh" | awk -F= '/^us_per_op=/{print $2}')
connect_baseline=$(ITERATIONS="${CONNECT_ITERATIONS}" FORMAT=text "${ROOT_DIR}/scripts/perf_connect_bench.sh" | awk -F= '/^us_per_op=/{print $2}')
read_baseline=$(run_read_bench "${FILE}" "${READ_ITERATIONS}")
stat_baseline=$(run_stat_bench "${STAT_FILE_LIST}" "${STAT_ITERATIONS}")

open_with_agent=$(WITH_AGENT=1 BIN="${BIN}" ITERATIONS="${OPEN_ITERATIONS}" FILE="${FILE}" FORMAT=text "${ROOT_DIR}/scripts/perf_open_bench.sh" | awk -F= '/^us_per_op=/{print $2}')
connect_with_agent=$(WITH_AGENT=1 BIN="${BIN}" ITERATIONS="${CONNECT_ITERATIONS}" FORMAT=text "${ROOT_DIR}/scripts/perf_connect_bench.sh" | awk -F= '/^us_per_op=/{print $2}')
start_agent
read_with_agent=$(run_read_bench "${FILE}" "${READ_ITERATIONS}")
stat_with_agent=$(run_stat_bench "${STAT_FILE_LIST}" "${STAT_ITERATIONS}")
stop_agent

python3 - <<PY
import json

rows = [
    ("open_close", float("${open_baseline}"), float("${open_with_agent}"), float("${MAX_OPEN_PCT}")),
    ("connect_loopback", float("${connect_baseline}"), float("${connect_with_agent}"), float("${MAX_CONNECT_PCT}")),
    ("full_read", float("${read_baseline}"), float("${read_with_agent}"), float("${MAX_READ_PCT}")),
    ("stat_walk", float("${stat_baseline}"), float("${stat_with_agent}"), float("${MAX_STAT_PCT}")),
]

payload = {"benchmarks": []}
failed = False
for name, baseline, with_agent, limit in rows:
    delta = with_agent - baseline
    pct = (delta / baseline * 100.0) if baseline else 0.0
    item = {
        "name": name,
        "baseline_us_per_op": round(baseline, 2),
        "with_agent_us_per_op": round(with_agent, 2),
        "delta_us_per_op": round(delta, 2),
        "delta_pct": round(pct, 2),
        "max_allowed_pct": round(limit, 2),
        "pass": pct <= limit,
    }
    payload["benchmarks"].append(item)
    if pct > limit:
        failed = True

fmt = "${FORMAT}".lower()
if fmt == "json":
    out = json.dumps(payload, separators=(",", ":"))
else:
    lines = []
    for b in payload["benchmarks"]:
        lines.append(
            f'{b["name"]}: baseline={b["baseline_us_per_op"]:.2f}us with_agent={b["with_agent_us_per_op"]:.2f}us '
            f'delta={b["delta_us_per_op"]:.2f}us ({b["delta_pct"]:.2f}%) limit={b["max_allowed_pct"]:.2f}% '
            f'pass={"yes" if b["pass"] else "no"}'
        )
    out = "\n".join(lines)

out_path = "${OUT}"
if out_path:
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(out + "\n")
print(out)

if failed:
    raise SystemExit(1)
PY
