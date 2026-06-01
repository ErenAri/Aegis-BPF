#!/usr/bin/env python3
"""Validate the enforcement-class proof contract.

Binds three sources so an ENFORCED claim cannot drift from its proof:

  1. the manifest        tests/enforcement/enforcement_classes.tsv  (source of truth)
  2. the proof harness   tests/enforcement/enforcement_proof.sh     (behavioral probe)
  3. the whitepaper      docs/ENFORCEMENT_SEMANTICS_WHITEPAPER.md   (the public claim)

Fails (exit 1) if:
  * a class in the manifest has no `assert_blocked <class>` probe in the harness,
  * the harness probes a class absent from the manifest,
  * an ENFORCED-labeled manifest row's claim phrase is missing from the
    whitepaper's "In-scope (ENFORCED)" section.

This makes "every ENFORCED claim points to a green per-class test" structural.
Kernel-free; the behavioral proof itself is the harness on the kernel matrix.
See docs/ENFORCEMENT_WEDGE_STRATEGY.md (Step 2).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "tests/enforcement/enforcement_classes.tsv"
HARNESS = REPO / "tests/enforcement/enforcement_proof.sh"
WHITEPAPER = REPO / "docs/ENFORCEMENT_SEMANTICS_WHITEPAPER.md"

ASSERT_RE = re.compile(r"assert_blocked\s+([A-Za-z_]\w*)")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Validate enforcement-class proof contract")
    p.add_argument("--manifest", type=Path, default=MANIFEST)
    p.add_argument("--harness", type=Path, default=HARNESS)
    p.add_argument("--whitepaper", type=Path, default=WHITEPAPER)
    return p.parse_args()


def read(path: Path) -> str:
    if not path.is_file():
        raise FileNotFoundError(f"missing file: {path}")
    return path.read_text(encoding="utf-8")


def parse_manifest(text: str) -> list[dict]:
    rows = []
    for ln, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        cols = line.split("\t")
        if len(cols) != 4:
            raise ValueError(f"manifest line {ln}: expected 4 tab-separated columns, got {len(cols)}: {line!r}")
        cls, label, hooks, claim = (c.strip() for c in cols)
        rows.append({"class": cls, "label": label, "hooks": hooks, "claim": claim})
    return rows


def whitepaper_enforced_section(text: str) -> str:
    marker = "### In-scope (ENFORCED)"
    if marker not in text:
        raise ValueError(f"whitepaper missing '{marker}' section")
    section = text.split(marker, 1)[1]
    section = section.split("\n### ", 1)[0]  # up to the next h3
    return section


def main() -> int:
    args = parse_args()
    errors: list[str] = []

    try:
        manifest = parse_manifest(read(args.manifest))
        harness_text = read(args.harness)
        whitepaper_text = read(args.whitepaper)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not manifest:
        print("error: manifest has no enforcement classes", file=sys.stderr)
        return 1

    manifest_classes = {r["class"] for r in manifest}
    harness_classes = set(ASSERT_RE.findall(harness_text))

    missing_probe = sorted(manifest_classes - harness_classes)
    if missing_probe:
        errors.append(
            "manifest classes with no harness probe (no `assert_blocked <class>` in "
            f"{args.harness.name}): {missing_probe}"
        )

    orphan_probe = sorted(harness_classes - manifest_classes)
    if orphan_probe:
        errors.append(
            f"harness probes a class absent from the manifest: {orphan_probe}"
        )

    enforced_section = whitepaper_enforced_section(whitepaper_text)
    for row in manifest:
        if row["label"] != "ENFORCED":
            continue
        if row["claim"] not in enforced_section:
            errors.append(
                f"class '{row['class']}' is ENFORCED in the manifest but its claim "
                f"phrase {row['claim']!r} is absent from the whitepaper "
                "'In-scope (ENFORCED)' section"
            )

    if errors:
        print("Enforcement proof contract FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(
        f"Enforcement proof contract validated: {len(manifest)} classes "
        f"({', '.join(sorted(manifest_classes))}) bound to harness probes and whitepaper claims."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
