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
    whitepaper's "In-scope (ENFORCED)" section,
  * a 'mitigated' entry in docs/BYPASS_CATALOG.md cites no Regression anchor, or
    an anchor that does not resolve to a real test/probe/step,
  * a hook a manifest class enforces with (lsm/X) is missing from the capability
    catalog src/hook_capabilities.cpp (as bpf_lsm_X).

This makes "every ENFORCED claim points to a green per-class test" and "no bypass
is mitigated without a regression" structural, not editorial. Kernel-free; the
behavioral proofs themselves are the harness/tests on the kernel matrix.
See docs/ENFORCEMENT_WEDGE_STRATEGY.md (Steps 2-3).
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
BYPASS_CATALOG = REPO / "docs/BYPASS_CATALOG.md"
BYPASS_TESTS = REPO / "tests/e2e/test_bypasses.cpp"
KERNEL_MATRIX = REPO / ".github/workflows/kernel-matrix.yml"
HOOK_CATALOG = REPO / "src/hook_capabilities.cpp"

ASSERT_RE = re.compile(r"assert_blocked\s+([A-Za-z_]\w*)")
ENTRY_RE = re.compile(r"\n### (BYP-\S+)[^\n]*\n")
STATUS_RE = re.compile(r"\*\*Status:\*\*\s*(\w+)")
REGRESSION_RE = re.compile(r"\*\*Regression:\*\*\s*(.+)")
BACKTICK_RE = re.compile(r"`([^`]+)`")


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


def parse_catalog_entries(text: str) -> list[dict]:
    """Parse '### BYP-xxx' entries with their Status and Regression anchors."""
    entries = []
    parts = ENTRY_RE.split(text)
    # parts[0] is the preamble; then alternating (id, body).
    for i in range(1, len(parts), 2):
        byp_id = parts[i]
        body = parts[i + 1] if i + 1 < len(parts) else ""
        status_m = STATUS_RE.search(body)
        reg_m = REGRESSION_RE.search(body)
        anchors = BACKTICK_RE.findall(reg_m.group(1)) if reg_m else []
        entries.append(
            {"id": byp_id, "status": status_m.group(1) if status_m else None, "anchors": anchors}
        )
    return entries


def resolve_regression_anchor(anchor: str, src: dict[str, str]) -> bool:
    """True if the regression anchor resolves to a real test/probe/step."""
    if anchor.startswith("enforcement_proof.sh:"):
        name = anchor.split(":", 1)[1]
        return re.search(rf"assert_(?:bypass|blocked)\s+{re.escape(name)}\b", src["harness"]) is not None
    if anchor.startswith("test_bypasses.cpp::"):
        name = anchor.split("::", 1)[1]
        return re.search(rf"TEST_F\(BypassTest,\s*{re.escape(name)}\b", src["bypass_tests"]) is not None
    if anchor.startswith("kernel-matrix.yml:"):
        step = anchor.split(":", 1)[1]
        return f"name: {step}" in src["kernel_matrix"]
    return False


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

    # Every hook a manifest class enforces with must be in the capability catalog
    # (src/hook_capabilities.cpp), so `capabilities` honestly reports it. The hook
    # `lsm/X` is catalogued as the trampoline symbol `bpf_lsm_X`.
    try:
        hook_catalog_text = read(HOOK_CATALOG)
        for row in manifest:
            for hook in (h.strip() for h in row["hooks"].split(",") if h.strip()):
                if not hook.startswith("lsm/"):
                    continue
                symbol = "bpf_lsm_" + hook.split("/", 1)[1]
                if symbol not in hook_catalog_text:
                    errors.append(
                        f"class '{row['class']}' enforces with {hook} but its capability-catalog "
                        f"symbol {symbol!r} is absent from {HOOK_CATALOG.name}"
                    )
    except FileNotFoundError as exc:
        errors.append(f"hook catalog check: {exc}")

    # Bypass catalog: every 'mitigated' entry must cite a regression that exists.
    mitigated = 0
    try:
        src = {
            "harness": harness_text,
            "bypass_tests": read(BYPASS_TESTS),
            "kernel_matrix": read(KERNEL_MATRIX),
        }
        for entry in parse_catalog_entries(read(BYPASS_CATALOG)):
            if entry["status"] != "mitigated":
                continue
            mitigated += 1
            if not entry["anchors"]:
                errors.append(f"bypass {entry['id']} is 'mitigated' but cites no Regression anchor")
                continue
            for anchor in entry["anchors"]:
                if not resolve_regression_anchor(anchor, src):
                    errors.append(
                        f"bypass {entry['id']} Regression anchor {anchor!r} does not resolve "
                        "to a real test/probe/step"
                    )
    except FileNotFoundError as exc:
        errors.append(f"bypass catalog check: {exc}")

    if errors:
        print("Enforcement proof contract FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(
        f"Enforcement proof contract validated: {len(manifest)} classes "
        f"({', '.join(sorted(manifest_classes))}) bound to harness probes and whitepaper claims; "
        f"{mitigated} mitigated bypass entries each backed by a regression."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
