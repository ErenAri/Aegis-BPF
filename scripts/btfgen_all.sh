#!/usr/bin/env bash
# btfgen_all.sh — Auto-detect the running kernel and download its BTF
#                 blob from BTFhub-archive.
#
# This is a thin wrapper around btfgen.sh that passes $(uname -r).
#
# Usage:
#   sudo ./scripts/btfgen_all.sh [--output-dir /path] [--force]
#
# All arguments are forwarded to btfgen.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec "$SCRIPT_DIR/btfgen.sh" --auto "$@"
