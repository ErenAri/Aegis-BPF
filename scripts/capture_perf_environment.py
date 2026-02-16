#!/usr/bin/env python3
"""Capture deterministic perf environment metadata as JSON."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import time
from pathlib import Path
from typing import Any


_SCHEMA_SEMVER = "1.0.0"


def _read_os_release() -> dict[str, str]:
    path = Path("/etc/os-release")
    values: dict[str, str] = {}
    if not path.is_file():
        return values

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", maxsplit=1)
        key = key.strip()
        value = raw_value.strip().strip('"')
        values[key] = value
    return values


def _read_cpu_model() -> str:
    try:
        cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "unknown"

    for line in cpuinfo.splitlines():
        if line.lower().startswith("model name") and ":" in line:
            return line.split(":", maxsplit=1)[1].strip()
    return "unknown"


def _read_mem_total_kib() -> int:
    try:
        meminfo = Path("/proc/meminfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0

    for line in meminfo.splitlines():
        if line.startswith("MemTotal:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
    return 0


def _run_capture(cmd: list[str]) -> str:
    try:
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    except OSError:
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def _filesystem_type(path: str) -> str:
    out = _run_capture(["stat", "-f", "-c", "%T", path])
    return out or "unknown"


def build_payload() -> dict[str, Any]:
    os_release = _read_os_release()

    payload: dict[str, Any] = {
        "schema_version": 1,
        "schema_semver": _SCHEMA_SEMVER,
        "generated_at_unix": int(time.time()),
        "host": {
            "hostname": platform.node() or "unknown",
            "kernel_release": platform.release() or "unknown",
            "kernel_version": platform.version() or "unknown",
            "architecture": platform.machine() or "unknown",
        },
        "cpu": {
            "model": _read_cpu_model(),
            "logical_cores": os.cpu_count() or 0,
        },
        "memory": {
            "mem_total_kib": _read_mem_total_kib(),
        },
        "os": {
            "id": os_release.get("ID", "unknown"),
            "version_id": os_release.get("VERSION_ID", "unknown"),
            "pretty_name": os_release.get("PRETTY_NAME", "unknown"),
        },
        "filesystem": {
            "tmp_type": _filesystem_type("/tmp"),
        },
    }
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Output JSON path",
    )
    args = parser.parse_args()

    payload = build_payload()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
