#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run the machine-checked enforcement proofs in a self-contained venv.
#   1. model-fidelity guard  — modeled hook bodies still match the lock
#   2. z3 proof obligations   — inode-alias bypass-resistance
#
# Idempotent: reuses .venv if present. $0 deps: python3 (>=3.10) + internet on
# first run to fetch the pinned z3-solver wheel.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${AEGIS_PROOFS_VENV:-$HERE/.venv}"

if [ ! -x "$VENV/bin/python" ]; then
  echo "» creating proof venv at $VENV"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q --upgrade pip
  "$VENV/bin/pip" install -q -r "$HERE/requirements.txt"
fi

echo "» step 1/2: model-fidelity guard"
"$VENV/bin/python" "$HERE/check_model_fidelity.py"

echo "» step 2/2: proof obligations"
"$VENV/bin/python" "$HERE/inode_alias_resistance.py"
