#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-build-release-readiness}"
CMAKE_GENERATOR="${CMAKE_GENERATOR:-Ninja}"

echo "[1/7] Configure release-readiness build"
cmake -S "${ROOT_DIR}" -B "${ROOT_DIR}/${BUILD_DIR}" -G "${CMAKE_GENERATOR}" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_TESTING=ON \
  -DBUILD_BENCHMARKS=OFF \
  -DSKIP_BPF_BUILD=ON

echo "[2/7] Build"
cmake --build "${ROOT_DIR}/${BUILD_DIR}" -j"$(nproc)"

echo "[3/7] Test"
ctest --test-dir "${ROOT_DIR}/${BUILD_DIR}" --output-on-failure --timeout 180

echo "[4/7] Contract checks"
python3 "${ROOT_DIR}/scripts/validate_event_schema.py" \
  --schema "${ROOT_DIR}/config/event-schema.json" \
  --samples "${ROOT_DIR}/tests/event_samples"
python3 "${ROOT_DIR}/scripts/validate_json_samples.py"
python3 "${ROOT_DIR}/tests/check_systemd_policy_prestart.py" \
  "${ROOT_DIR}/packaging/systemd/aegisbpf.service"
python3 "${ROOT_DIR}/tests/check_metrics_contract.py" \
  "${ROOT_DIR}/src/commands_monitoring.cpp" \
  "${ROOT_DIR}/config/prometheus/alerts.yml" \
  "${ROOT_DIR}/config/grafana/dashboard.json" \
  "${ROOT_DIR}/docs/man/aegisbpf.1.md"
python3 "${ROOT_DIR}/tests/check_slo_contract.py" \
  "${ROOT_DIR}/config/prometheus/alerts.yml" \
  "${ROOT_DIR}/docs/PRODUCT.md"
python3 "${ROOT_DIR}/tests/check_support_policy.py" \
  "${ROOT_DIR}/docs/SUPPORT_POLICY.md"
python3 "${ROOT_DIR}/tests/check_docs_security_contract.py"
python3 "${ROOT_DIR}/tests/check_upgrade_compat.py" \
  "${ROOT_DIR}/${BUILD_DIR}/aegisbpf" \
  "${ROOT_DIR}/tests/fixtures/upgrade/policy_v1.conf" \
  "${ROOT_DIR}/tests/fixtures/upgrade/policy_v2.conf"
strict_flag=""
if [[ "${AEGIS_INDUSTRIAL_STRICT:-0}" == "1" ]]; then
  strict_flag="--strict"
fi
python3 "${ROOT_DIR}/tests/check_perf_baseline_doc.py" \
  "${ROOT_DIR}/docs/PERF_BASELINE.md" \
  ${strict_flag}

echo "[5/7] CLI parser sanity"
if "${ROOT_DIR}/${BUILD_DIR}/aegisbpf" metrics --invalid >/dev/null 2>&1; then
  echo "expected 'metrics --invalid' to fail" >&2
  exit 1
fi
if "${ROOT_DIR}/${BUILD_DIR}/aegisbpf" health --json --unknown >/dev/null 2>&1; then
  echo "expected 'health --json --unknown' to fail" >&2
  exit 1
fi
if "${ROOT_DIR}/${BUILD_DIR}/aegisbpf" network deny add --ip 192.0.2.1 --cidr 10.0.0.0/8 >/dev/null 2>&1; then
  echo "expected conflicting network selectors to fail" >&2
  exit 1
fi

echo "[6/7] Key-rotation contract checks"
ctest --test-dir "${ROOT_DIR}/${BUILD_DIR}" --output-on-failure \
  -R "CmdPolicySignTest\\.CreatesSignedBundle|CmdPolicyApplySignedTest\\.RequireSignatureRejectsUnsignedPolicy|CmdPolicyApplySignedTest\\.RejectsRollbackBundleVersion|CmdKeysAddTest\\.RejectsWorldWritableKeyFile"

echo "[7/7] Go-live artifact sanity"
required_files=(
  "${ROOT_DIR}/docs/BRANCH_PROTECTION.md"
  "${ROOT_DIR}/docs/CANARY_RUNBOOK.md"
  "${ROOT_DIR}/docs/RELEASE_DRILL.md"
  "${ROOT_DIR}/config/required_checks.txt"
  "${ROOT_DIR}/scripts/check_branch_protection.sh"
  "${ROOT_DIR}/scripts/canary_gate.sh"
  "${ROOT_DIR}/scripts/perf_workload_suite.sh"
  "${ROOT_DIR}/scripts/release_drill.sh"
  "${ROOT_DIR}/scripts/key_rotation_drill.sh"
  "${ROOT_DIR}/.github/workflows/canary.yml"
  "${ROOT_DIR}/.github/workflows/release-drill.yml"
  "${ROOT_DIR}/.github/workflows/key-rotation-drill.yml"
  "${ROOT_DIR}/.github/workflows/go-live-gate.yml"
  "${ROOT_DIR}/.github/workflows/branch-protection-audit.yml"
)
for f in "${required_files[@]}"; do
  if [[ ! -f "${f}" ]]; then
    echo "missing required go-live artifact: ${f}" >&2
    exit 1
  fi
done

echo "Release readiness checks passed."
