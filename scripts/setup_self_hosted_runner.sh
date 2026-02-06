#!/usr/bin/env bash
set -euo pipefail

REPO="${REPO:-ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype}"
RUNNER_NAME="${RUNNER_NAME:-}"
LABELS="${LABELS:-}"
RUNNER_DIR="${RUNNER_DIR:-}"
WORK_DIR="${WORK_DIR:-_work}"
ALLOW_RUN_AS_ROOT="${ALLOW_RUN_AS_ROOT:-1}"

if [[ -z "${RUNNER_NAME}" || -z "${LABELS}" ]]; then
  echo "usage: RUNNER_NAME=<name> LABELS=<comma,labels> [REPO=owner/repo] [RUNNER_DIR=/opt/actions-runner] $0" >&2
  exit 1
fi

if [[ -z "${RUNNER_DIR}" ]]; then
  RUNNER_DIR="/opt/actions-runner-${RUNNER_NAME}"
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "setup_self_hosted_runner.sh must run as root (uses systemd service + BPF privileges)." >&2
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI (gh) is required on the runner host." >&2
  exit 1
fi

echo "fetching runner registration token..."
TOKEN="$(gh api -X POST repos/${REPO}/actions/runners/registration-token --jq .token)"

if [[ -z "${TOKEN}" ]]; then
  echo "failed to fetch runner registration token" >&2
  exit 1
fi

mkdir -p "${RUNNER_DIR}"
cd "${RUNNER_DIR}"

if [[ ! -x ./config.sh ]]; then
  RUNNER_VERSION="$(curl -fsSL https://api.github.com/repos/actions/runner/releases/latest | python3 -c 'import json,sys;print(json.load(sys.stdin)["tag_name"].lstrip("v"))')"
  RUNNER_TGZ="actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
  echo "downloading actions runner ${RUNNER_VERSION}..."
  curl -fsSL -o "${RUNNER_TGZ}" "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${RUNNER_TGZ}"
  tar xzf "${RUNNER_TGZ}"
fi

export RUNNER_ALLOW_RUNASROOT="${ALLOW_RUN_AS_ROOT}"

echo "configuring runner..."
./config.sh --unattended \
  --url "https://github.com/${REPO}" \
  --token "${TOKEN}" \
  --name "${RUNNER_NAME}" \
  --labels "${LABELS}" \
  --work "${WORK_DIR}" \
  --replace

echo "installing runner service..."
./svc.sh install
./svc.sh start

echo "runner '${RUNNER_NAME}' registered for ${REPO} with labels: ${LABELS}"
