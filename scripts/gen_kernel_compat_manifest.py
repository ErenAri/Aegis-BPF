#!/usr/bin/env python3
"""Generate the canonical kernel-compatibility manifest from the source of truth.

The manifest is a backend-neutral description of what AegisBPF must satisfy on
each target kernel, derived from:
  * src/hook_capabilities.cpp        — the BPF programs + their bpf_lsm_* attach
                                        symbols + required flags
  * tests/enforcement/enforcement_classes.tsv — the ENFORCED enforcement classes

It describes two verification LAYERS so consumers never conflate them:
  * A (object compat):  load + verify + attach aegis.bpf.o on kernel X.
  * B (behavioral):     run tests/enforcement/enforcement_proof.sh on kernel X
                        and assert -EPERM per class with posture ENFORCE.

A compatibility backend (e.g. the bpfcompat service) consumes this manifest; the
service-specific wire format is a thin adapter over this canonical document.

Usage:
  gen_kernel_compat_manifest.py             # write tests/enforcement/kernel_compat_manifest.json
  gen_kernel_compat_manifest.py --stdout    # print to stdout
  gen_kernel_compat_manifest.py --check      # fail if the committed file is stale

See docs/KERNEL_COMPAT_MATRIX.md.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK_CATALOG = REPO / "src/hook_capabilities.cpp"
CLASSES_TSV = REPO / "tests/enforcement/enforcement_classes.tsv"
OUT = REPO / "tests/enforcement/kernel_compat_manifest.json"

HOOKSPEC_RE = re.compile(r'\{"(lsm_[a-z0-9_]+)",\s*"(bpf_lsm_[a-z0-9_]+)",\s*(true|false)\s*,')

# Recommended kernel matrix: LTS-anchored + the two most-deployed Ubuntu kernels,
# plus one deliberately no-BPF-LSM target to prove the No-Pretend invariant.
KERNEL_MATRIX = [
    {"version": "5.15", "bpf_lsm": True, "note": "Ubuntu 22.04 LTS — realistic floor"},
    {"version": "6.1", "bpf_lsm": True, "note": "Debian 12 LTS"},
    {"version": "6.6", "bpf_lsm": True, "note": "LTS"},
    {"version": "6.8", "bpf_lsm": True, "note": "Ubuntu 24.04 LTS"},
    {"version": "6.12", "bpf_lsm": True, "note": "latest LTS"},
    {"version": "no-lsm", "bpf_lsm": False, "note": "kernel without bpf in lsm= — proves No-Pretend invariant"},
]


def parse_programs(text: str) -> list[dict]:
    progs = []
    for name, attach, required in HOOKSPEC_RE.findall(text):
        progs.append({"name": name, "attach": attach, "required": required == "true"})
    return progs


def parse_classes(text: str) -> list[dict]:
    classes = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        cols = [c.strip() for c in line.split("\t")]
        if len(cols) != 4:
            continue
        cls, label, hooks, _claim = cols
        classes.append({"class": cls, "label": label, "hooks": hooks.split(",")})
    return classes


def build_manifest() -> dict:
    programs = parse_programs(HOOK_CATALOG.read_text(encoding="utf-8"))
    classes = parse_classes(CLASSES_TSV.read_text(encoding="utf-8"))
    if not programs or not classes:
        raise ValueError("failed to parse programs or classes from source of truth")
    return {
        "schema_version": 1,
        "artifact": "aegis.bpf.o",
        "generated_from": ["src/hook_capabilities.cpp", "tests/enforcement/enforcement_classes.tsv"],
        "note": "GENERATED — do not edit by hand. Run scripts/gen_kernel_compat_manifest.py.",
        "lsm_boot_requirement": (
            "kernels with bpf_lsm=true MUST boot with 'bpf' in the lsm= list; verify "
            "/sys/kernel/security/lsm contains 'bpf' (CONFIG_BPF_LSM=y alone is not enough)."
        ),
        "kernel_matrix": KERNEL_MATRIX,
        "programs": programs,
        "enforcement_classes": classes,
        "layers": {
            "A_object_compat": {
                "action": "load + verify + attach aegis.bpf.o",
                "gate": "all programs with required=true attach; non-required may be absent on older kernels",
            },
            "B_behavioral": {
                "action": "run the enforcement proof harness on the kernel",
                "entrypoint": "tests/enforcement/enforcement_proof.sh",
                "needs_root": True,
                "needs_bpf_lsm": True,
                "gate": "exit 0 — every ENFORCED class returns -EPERM and runtime_state==ENFORCE",
                "no_lsm_expectation": "on a bpf_lsm=false kernel the harness exits 77 (daemon honestly refuses enforce)",
            },
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate the canonical kernel-compat manifest")
    ap.add_argument("--stdout", action="store_true", help="print to stdout instead of writing the file")
    ap.add_argument("--check", action="store_true", help="fail if the committed manifest is stale")
    args = ap.parse_args()

    try:
        manifest = build_manifest()
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    rendered = json.dumps(manifest, indent=2) + "\n"

    if args.check:
        if not OUT.is_file():
            print(f"error: {OUT} missing — run scripts/gen_kernel_compat_manifest.py", file=sys.stderr)
            return 1
        if OUT.read_text(encoding="utf-8") != rendered:
            print(
                f"error: {OUT.name} is stale — regenerate with scripts/gen_kernel_compat_manifest.py",
                file=sys.stderr,
            )
            return 1
        print(f"{OUT.name} is up to date ({len(manifest['programs'])} programs, "
              f"{len(manifest['enforcement_classes'])} classes, {len(manifest['kernel_matrix'])} kernels).")
        return 0

    if args.stdout:
        sys.stdout.write(rendered)
    else:
        OUT.write_text(rendered, encoding="utf-8")
        print(f"wrote {OUT.relative_to(REPO)} "
              f"({len(manifest['programs'])} programs, {len(manifest['enforcement_classes'])} classes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
