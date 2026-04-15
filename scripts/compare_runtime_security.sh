#!/usr/bin/env bash
# compare_runtime_security.sh — Head-to-head runtime-security comparison driver.
#
# Runs the same open/read/close microbench (scripts/perf_open_bench.sh) under
# different runtime-security agents in isolation and emits a single results
# table. Currently supports:
#
#   - none       baseline, no agent
#   - aegisbpf   this repository's agent (audit-only, empty policy)
#   - falco      Falco in modern-bpf mode, with an empty rules file
#   - tetragon   Cilium Tetragon with no tracing policies
#   - tracee     Aqua Tracee in detect-only mode with no signatures
#   - kubearmor  KubeArmor host-mode with no policies
#
# Only agents that are installed on the host are exercised. Missing agents
# are skipped with a clear [SKIP] message. No agent is installed or removed
# by this script.
#
# IMPORTANT: this script only produces numbers that were measured on the
# same host. Do not edit docs/PERFORMANCE_COMPARISON.md to reference numbers
# from anywhere else.
#
# Usage:
#   sudo scripts/compare_runtime_security.sh \
#       --agents none,aegisbpf,falco,tetragon \
#       --workload open_close \
#       --iterations 200000 \
#       --out results/
#
# Exit codes:
#   0  all requested agents ran (or skipped cleanly)
#   1  invalid arguments or baseline failed
#   2  one or more requested agents failed to run

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." &>/dev/null && pwd)"

AGENTS_ARG="none,aegisbpf"
WORKLOAD="open_close"
ITERATIONS="${ITERATIONS:-200000}"
OUT_DIR=""
COOLDOWN_SECONDS="${COOLDOWN_SECONDS:-5}"
STRICT_MISSING="${STRICT_MISSING:-0}"
AEGISBPF_BIN="${AEGISBPF_BIN:-${REPO_ROOT}/build/aegisbpf}"
PERF_OPEN_BENCH="${PERF_OPEN_BENCH:-${REPO_ROOT}/scripts/perf_open_bench.sh}"
PERF_CONNECT_BENCH="${PERF_CONNECT_BENCH:-${REPO_ROOT}/scripts/perf_connect_bench.sh}"

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  --agents LIST         Comma-separated agent IDs to exercise.
                        Supported: none,aegisbpf,falco,tetragon,tracee,kubearmor
                        Default: none,aegisbpf
  --workload NAME       Workload profile: open_close (default), connect_close.
  --iterations N        Iterations per run (default: ${ITERATIONS}).
  --out DIR             Write per-agent JSON + results.md to DIR.
  --cooldown SECONDS    Seconds to wait between agent runs (default: ${COOLDOWN_SECONDS}).
  --strict-missing      Exit non-zero if any requested agent is not installed.
  -h, --help            Show this help.

Environment overrides:
  AEGISBPF_BIN          Path to the aegisbpf binary (default: \${REPO}/build/aegisbpf)
  PERF_OPEN_BENCH       Path to perf_open_bench.sh (default: \${REPO}/scripts/perf_open_bench.sh)

Reproducibility:
  - Run on a quiesced host with no other runtime-security agent active.
  - Run as root: every agent except 'none' needs CAP_BPF or equivalent.
  - Do not change AEGISBPF_BIN, kernel, or workload between runs in the
    same comparison: the output is only meaningful within a single run.

See docs/COMPETITIVE_BENCH_METHODOLOGY.md for full methodology.
EOF
}

log() { echo "[compare] $*"; }
warn() { echo "[compare] WARN: $*" >&2; }
err() { echo "[compare] ERROR: $*" >&2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --agents) AGENTS_ARG="$2"; shift 2 ;;
        --workload) WORKLOAD="$2"; shift 2 ;;
        --iterations) ITERATIONS="$2"; shift 2 ;;
        --out) OUT_DIR="$2"; shift 2 ;;
        --cooldown) COOLDOWN_SECONDS="$2"; shift 2 ;;
        --strict-missing) STRICT_MISSING=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) err "unknown argument: $1"; usage >&2; exit 1 ;;
    esac
done

case "${WORKLOAD}" in
    open_close)
        if [[ ! -x "${PERF_OPEN_BENCH}" ]]; then
            err "perf_open_bench.sh not found or not executable: ${PERF_OPEN_BENCH}"
            exit 1
        fi
        ;;
    connect_close)
        if [[ ! -x "${PERF_CONNECT_BENCH}" ]]; then
            err "perf_connect_bench.sh not found or not executable: ${PERF_CONNECT_BENCH}"
            exit 1
        fi
        ;;
    *)
        err "unsupported workload '${WORKLOAD}' (supported: open_close, connect_close)"
        exit 1
        ;;
esac

IFS=',' read -r -a AGENTS <<<"${AGENTS_ARG}"
if [[ "${#AGENTS[@]}" -eq 0 ]]; then
    err "no agents requested"
    exit 1
fi

if [[ "${EUID}" -ne 0 && "${AGENTS_ARG}" != "none" ]]; then
    warn "running as non-root; only the 'none' baseline can be measured"
fi

if [[ -n "${OUT_DIR}" ]]; then
    mkdir -p "${OUT_DIR}"
fi

HOST_ID="$(uname -n)-$(uname -r)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "host=${HOST_ID} ts=${TIMESTAMP} workload=${WORKLOAD} iterations=${ITERATIONS}"

# Per-agent state. We key everything by agent ID so skips/fails surface in
# the final table without aborting.
declare -A STATUS
declare -A US_PER_OP
declare -A P50_US
declare -A P95_US
declare -A P99_US
declare -A NOTES

have_cmd() { command -v "$1" >/dev/null 2>&1; }

assert_no_conflicting_agent() {
    # The moment any peer agent is left running, the baseline is invalid.
    # We only check the ones we know about; this is advisory, not exhaustive.
    local running=()
    if pgrep -x falco >/dev/null 2>&1; then running+=(falco); fi
    if pgrep -x tetragon >/dev/null 2>&1; then running+=(tetragon); fi
    if pgrep -x tracee >/dev/null 2>&1; then running+=(tracee); fi
    if pgrep -x tracee-ebpf >/dev/null 2>&1; then running+=(tracee-ebpf); fi
    if pgrep -x karmor >/dev/null 2>&1 || pgrep -x kubearmor >/dev/null 2>&1; then
        running+=(kubearmor)
    fi
    if pgrep -x aegisbpf >/dev/null 2>&1; then running+=(aegisbpf); fi
    if [[ "${#running[@]}" -gt 0 ]]; then
        err "other security agent(s) already running: ${running[*]}"
        err "stop them before starting the comparison"
        return 1
    fi
    return 0
}

stop_pid() {
    local pid="$1"
    if [[ -z "${pid}" ]]; then return 0; fi
    if kill -0 "${pid}" 2>/dev/null; then
        kill "${pid}" 2>/dev/null || true
        for _ in 1 2 3 4 5; do
            kill -0 "${pid}" 2>/dev/null || return 0
            sleep 0.5
        done
        kill -9 "${pid}" 2>/dev/null || true
    fi
}

run_perf_bench() {
    # Wraps the appropriate bench script and returns a JSON payload.
    local agent_id="$1"
    local out_json="${OUT_DIR:+${OUT_DIR}/${agent_id}.json}"
    local tmp_json bench_script
    tmp_json="$(mktemp)"
    case "${WORKLOAD}" in
        open_close)    bench_script="${PERF_OPEN_BENCH}" ;;
        connect_close) bench_script="${PERF_CONNECT_BENCH}" ;;
    esac
    FORMAT=json OUT="${tmp_json}" ITERATIONS="${ITERATIONS}" WITH_AGENT=0 \
        "${bench_script}" >/dev/null
    if [[ -n "${out_json}" ]]; then
        cp "${tmp_json}" "${out_json}"
    fi
    cat "${tmp_json}"
    rm -f "${tmp_json}"
}

record_result_from_json() {
    local agent_id="$1"
    local json="$2"
    US_PER_OP[${agent_id}]="$(python3 -c 'import sys,json; print(json.loads(sys.stdin.read())["us_per_op"])' <<<"${json}")"
    P50_US[${agent_id}]="$(python3 -c 'import sys,json; print(json.loads(sys.stdin.read())["p50_us"])' <<<"${json}")"
    P95_US[${agent_id}]="$(python3 -c 'import sys,json; print(json.loads(sys.stdin.read())["p95_us"])' <<<"${json}")"
    P99_US[${agent_id}]="$(python3 -c 'import sys,json; print(json.loads(sys.stdin.read())["p99_us"])' <<<"${json}")"
    STATUS[${agent_id}]="ok"
}

# ---------- Per-agent runners ----------
#
# Each runner must:
#   1. Start the agent with the most-benign possible policy (empty / audit).
#   2. Wait for the agent to be ready.
#   3. Run the workload.
#   4. Stop the agent cleanly.
#   5. Populate STATUS/US_PER_OP/P95_US/etc. on success, or set
#      STATUS[agent]=skipped/failed with NOTES[agent].

run_none() {
    local agent_id="none"
    log "== ${agent_id} =="
    local json
    if ! json="$(run_perf_bench "${agent_id}")"; then
        STATUS[${agent_id}]="failed"
        NOTES[${agent_id}]="baseline run failed"
        return 1
    fi
    record_result_from_json "${agent_id}" "${json}"
}

run_aegisbpf() {
    local agent_id="aegisbpf"
    log "== ${agent_id} =="
    if [[ ! -x "${AEGISBPF_BIN}" ]]; then
        STATUS[${agent_id}]="skipped"
        NOTES[${agent_id}]="binary not found at ${AEGISBPF_BIN}"
        return 0
    fi
    local logfile
    logfile="$(mktemp)"
    "${AEGISBPF_BIN}" run --audit >"${logfile}" 2>&1 &
    local pid=$!
    sleep 2
    if ! kill -0 "${pid}" 2>/dev/null; then
        STATUS[${agent_id}]="failed"
        NOTES[${agent_id}]="agent exited early; see ${logfile}"
        return 1
    fi
    local json status=0
    if ! json="$(run_perf_bench "${agent_id}")"; then
        status=1
    fi
    stop_pid "${pid}"
    wait "${pid}" 2>/dev/null || true
    rm -f "${logfile}"
    if [[ "${status}" -ne 0 ]]; then
        STATUS[${agent_id}]="failed"
        NOTES[${agent_id}]="workload run failed"
        return 1
    fi
    record_result_from_json "${agent_id}" "${json}"
}

run_falco() {
    local agent_id="falco"
    log "== ${agent_id} =="
    if ! have_cmd falco; then
        STATUS[${agent_id}]="skipped"
        NOTES[${agent_id}]="falco not installed"
        return 0
    fi
    local rules_dir logfile
    rules_dir="$(mktemp -d)"
    logfile="$(mktemp)"
    : >"${rules_dir}/empty.yaml"
    # Falco 0.43+ uses config-based driver selection, not --modern-bpf flag.
    # The engine.kind is set to modern_ebpf via config.d by the package installer.
    falco -r "${rules_dir}/empty.yaml" -o "log_level=error" \
        -o "engine.kind=modern_ebpf" \
        >"${logfile}" 2>&1 &
    local pid=$!
    sleep 3
    if ! kill -0 "${pid}" 2>/dev/null; then
        STATUS[${agent_id}]="failed"
        NOTES[${agent_id}]="agent exited early; see ${logfile}"
        rm -rf "${rules_dir}"
        return 1
    fi
    local json status=0
    if ! json="$(run_perf_bench "${agent_id}")"; then
        status=1
    fi
    stop_pid "${pid}"
    wait "${pid}" 2>/dev/null || true
    rm -rf "${rules_dir}" "${logfile}"
    if [[ "${status}" -ne 0 ]]; then
        STATUS[${agent_id}]="failed"
        NOTES[${agent_id}]="workload run failed"
        return 1
    fi
    record_result_from_json "${agent_id}" "${json}"
}

run_tetragon() {
    local agent_id="tetragon"
    log "== ${agent_id} =="
    if ! have_cmd tetragon; then
        STATUS[${agent_id}]="skipped"
        NOTES[${agent_id}]="tetragon not installed (expects 'tetragon' in PATH)"
        return 0
    fi
    local logfile
    logfile="$(mktemp)"
    # Tetragon v1.6+ uses --export-filename (not --export-file).
    # --bpf-lib defaults to /usr/local/lib/tetragon/bpf/ from package install.
    tetragon --export-filename "" \
        >"${logfile}" 2>&1 &
    local pid=$!
    sleep 5
    if ! kill -0 "${pid}" 2>/dev/null; then
        STATUS[${agent_id}]="failed"
        NOTES[${agent_id}]="agent exited early; see ${logfile}"
        return 1
    fi
    local json status=0
    if ! json="$(run_perf_bench "${agent_id}")"; then
        status=1
    fi
    stop_pid "${pid}"
    wait "${pid}" 2>/dev/null || true
    rm -f "${logfile}"
    if [[ "${status}" -ne 0 ]]; then
        STATUS[${agent_id}]="failed"
        NOTES[${agent_id}]="workload run failed"
        return 1
    fi
    record_result_from_json "${agent_id}" "${json}"
}

run_tracee() {
    local agent_id="tracee"
    log "== ${agent_id} =="
    local bin=""
    if have_cmd tracee; then
        bin=tracee
    elif have_cmd tracee-ebpf; then
        bin=tracee-ebpf
    else
        STATUS[${agent_id}]="skipped"
        NOTES[${agent_id}]="tracee not installed"
        return 0
    fi
    local logfile
    logfile="$(mktemp)"
    "${bin}" --output option:no-color --output json --scope global \
        >"${logfile}" 2>&1 &
    local pid=$!
    sleep 3
    if ! kill -0 "${pid}" 2>/dev/null; then
        STATUS[${agent_id}]="failed"
        NOTES[${agent_id}]="agent exited early; see ${logfile}"
        return 1
    fi
    local json status=0
    if ! json="$(run_perf_bench "${agent_id}")"; then
        status=1
    fi
    stop_pid "${pid}"
    wait "${pid}" 2>/dev/null || true
    rm -f "${logfile}"
    if [[ "${status}" -ne 0 ]]; then
        STATUS[${agent_id}]="failed"
        NOTES[${agent_id}]="workload run failed"
        return 1
    fi
    record_result_from_json "${agent_id}" "${json}"
}

run_kubearmor() {
    local agent_id="kubearmor"
    log "== ${agent_id} =="
    if ! have_cmd kubearmor && ! have_cmd karmor; then
        STATUS[${agent_id}]="skipped"
        NOTES[${agent_id}]="kubearmor not installed (expects 'kubearmor' binary in PATH)"
        return 0
    fi
    if ! have_cmd kubearmor; then
        STATUS[${agent_id}]="skipped"
        NOTES[${agent_id}]="'karmor' CLI found but 'kubearmor' daemon binary missing; host-mode run not supported"
        return 0
    fi
    local logfile
    logfile="$(mktemp)"
    kubearmor --enableKubeArmorPolicy=false --enableKubeArmorHostPolicy=true \
        --k8s=false >"${logfile}" 2>&1 &
    local pid=$!
    sleep 5
    if ! kill -0 "${pid}" 2>/dev/null; then
        STATUS[${agent_id}]="failed"
        NOTES[${agent_id}]="agent exited early; see ${logfile}"
        return 1
    fi
    local json status=0
    if ! json="$(run_perf_bench "${agent_id}")"; then
        status=1
    fi
    stop_pid "${pid}"
    wait "${pid}" 2>/dev/null || true
    rm -f "${logfile}"
    if [[ "${status}" -ne 0 ]]; then
        STATUS[${agent_id}]="failed"
        NOTES[${agent_id}]="workload run failed"
        return 1
    fi
    record_result_from_json "${agent_id}" "${json}"
}

dispatch() {
    case "$1" in
        none)      run_none ;;
        aegisbpf)  run_aegisbpf ;;
        falco)     run_falco ;;
        tetragon)  run_tetragon ;;
        tracee)    run_tracee ;;
        kubearmor) run_kubearmor ;;
        *)
            STATUS[$1]="skipped"
            NOTES[$1]="unknown agent id"
            ;;
    esac
    sleep "${COOLDOWN_SECONDS}"
}

# ---------- Main ----------

if ! assert_no_conflicting_agent; then
    exit 1
fi

OVERALL_RC=0
for agent in "${AGENTS[@]}"; do
    agent="${agent// /}"
    [[ -z "${agent}" ]] && continue
    if ! dispatch "${agent}"; then
        OVERALL_RC=2
    fi
done

# ---------- Results table ----------

emit_markdown() {
    local baseline_us="${US_PER_OP[none]:-}"
    echo "# Runtime-security comparison results"
    echo
    echo "- host: \`${HOST_ID}\`"
    echo "- timestamp: ${TIMESTAMP}"
    echo "- workload: ${WORKLOAD}"
    echo "- iterations: ${ITERATIONS}"
    echo
    echo "| agent | status | us/op | p50 (µs) | p95 (µs) | p99 (µs) | delta vs none | notes |"
    echo "|---|---|---|---|---|---|---|---|"
    for agent in "${AGENTS[@]}"; do
        agent="${agent// /}"
        [[ -z "${agent}" ]] && continue
        local st="${STATUS[${agent}]:-missing}"
        local us="${US_PER_OP[${agent}]:-}"
        local p50="${P50_US[${agent}]:-}"
        local p95="${P95_US[${agent}]:-}"
        local p99="${P99_US[${agent}]:-}"
        local note="${NOTES[${agent}]:-}"
        local delta="—"
        if [[ -n "${us}" && -n "${baseline_us}" && "${agent}" != "none" ]]; then
            delta="$(python3 -c "b=${baseline_us}; x=${us}; print(f'{(x-b)/b*100:+.2f}%')")"
        fi
        printf '| %s | %s | %s | %s | %s | %s | %s | %s |\n' \
            "${agent}" "${st}" "${us}" "${p50}" "${p95}" "${p99}" "${delta}" "${note}"
    done
    echo
    echo "> Numbers are only meaningful when all agents were measured on the same host"
    echo "> in the same run of this script. Do not copy rows across runs."
}

emit_markdown | tee "${OUT_DIR:+${OUT_DIR}/results.md}"

# If strict-missing was requested, demote skipped to failure.
if [[ "${STRICT_MISSING}" -eq 1 ]]; then
    for agent in "${AGENTS[@]}"; do
        agent="${agent// /}"
        [[ -z "${agent}" ]] && continue
        if [[ "${STATUS[${agent}]:-}" == "skipped" ]]; then
            OVERALL_RC=2
        fi
    done
fi

exit "${OVERALL_RC}"
