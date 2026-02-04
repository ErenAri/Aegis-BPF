#!/usr/bin/env python3
"""Validate Phase-4 portability gates remain enforced."""

from __future__ import annotations

from pathlib import Path
import re
import sys


def require_contains(path: Path, needles: list[str]) -> list[str]:
    if not path.is_file():
        return [f"missing file: {path}"]
    text = path.read_text(encoding="utf-8")
    missing = [n for n in needles if n not in text]
    return [f"{path}: missing '{item}'" for item in missing]


def main() -> int:
    if len(sys.argv) != 5:
        print(
            "usage: check_phase4_portability_contract.py "
            "<kernel-matrix.yml> <compatibility.md> <phase4-evidence.md> <test-kernel-features.cpp>",
            file=sys.stderr,
        )
        return 2

    workflow = Path(sys.argv[1])
    compatibility = Path(sys.argv[2])
    evidence = Path(sys.argv[3])
    kernel_tests = Path(sys.argv[4])

    errors: list[str] = []
    errors += require_contains(
        compatibility,
        ["docs/PHASE4_PORTABILITY_EVIDENCE.md"],
    )
    errors += require_contains(
        evidence,
        [
            "Phase 4 Portability Evidence",
            "kernel-matrix-weekly",
            "5.14",
            "5.15",
            "6.1",
            "6.5",
            "ubuntu",
            "debian",
            "rhel",
        ],
    )
    errors += require_contains(
        kernel_tests,
        [
            "check_bpf_lsm_enabled",
            "check_btf_available",
            "check_cgroup_v2",
            "check_bpffs_mounted",
        ],
    )

    if workflow.is_file():
        text = workflow.read_text(encoding="utf-8")
        weekly_marker = "kernel-matrix-weekly:"
        if weekly_marker not in text:
            errors.append(f"{workflow}: missing '{weekly_marker}'")
        else:
            weekly_block = text.split(weekly_marker, maxsplit=1)[1]
            kernels = set(re.findall(r"kernel:\s*\"?([0-9]+(?:\.[0-9]+)*)\"?", weekly_block))
            distros = set(re.findall(r"distro_family:\s*([A-Za-z0-9_.-]+)", weekly_block))
            if len(kernels) < 4:
                errors.append(
                    f"{workflow}: expected >=4 kernel targets in kernel-matrix-weekly, found {len(kernels)}"
                )
            if len(distros) < 2:
                errors.append(
                    f"{workflow}: expected >=2 distro families in kernel-matrix-weekly, found {len(distros)}"
                )
    else:
        errors.append(f"missing file: {workflow}")

    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
