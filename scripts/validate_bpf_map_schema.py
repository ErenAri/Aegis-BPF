#!/usr/bin/env python3
"""Validate that every BPF map in aegis.bpf.c is documented in BPF_MAP_SCHEMA.md.

Contract test: ensures documentation stays in sync with code.

Usage:
    python3 scripts/validate_bpf_map_schema.py
"""

import re
import sys
from pathlib import Path

BPF_SOURCE = Path("bpf/aegis.bpf.c")
SCHEMA_DOC = Path("docs/BPF_MAP_SCHEMA.md")


def _read_source_with_includes(path: Path) -> str:
    """Read a BPF C source file, inlining local #include \"...\" headers."""
    content = path.read_text(encoding="utf-8")
    include_re = re.compile(r'^#include\s+"([^"]+)"', re.MULTILINE)
    parts: list[str] = []
    last = 0
    for m in include_re.finditer(content):
        parts.append(content[last:m.start()])
        header = path.parent / m.group(1)
        if header.exists():
            parts.append(header.read_text(encoding="utf-8"))
        last = m.end()
    parts.append(content[last:])
    return "".join(parts)


def extract_maps_from_source(path: Path) -> set[str]:
    """Extract map names from SEC('.maps') declarations in BPF C source."""
    content = _read_source_with_includes(path)
    # Match pattern: } map_name SEC(".maps");
    pattern = re.compile(r'\}\s+(\w+)\s+SEC\("\.maps"\)\s*;')
    maps = set(pattern.findall(content))

    # Also match the agent_config global variable (backed by .data map)
    if "volatile struct agent_config agent_cfg" in content:
        maps.add("agent_config")

    return maps


def extract_maps_from_docs(path: Path) -> set[str]:
    """Extract map names from ### headings in the schema doc."""
    content = path.read_text(encoding="utf-8")
    # Match ### `map_name` headings
    pattern = re.compile(r"^###\s+`(\w+)`", re.MULTILINE)
    return set(pattern.findall(content))


def main() -> int:
    errors = []

    if not BPF_SOURCE.exists():
        print(f"Error: BPF source not found: {BPF_SOURCE}")
        return 2

    if not SCHEMA_DOC.exists():
        print(f"Error: Schema doc not found: {SCHEMA_DOC}")
        return 2

    source_maps = extract_maps_from_source(BPF_SOURCE)
    doc_maps = extract_maps_from_docs(SCHEMA_DOC)

    # Maps in code but not documented
    undocumented = source_maps - doc_maps
    if undocumented:
        for m in sorted(undocumented):
            errors.append(f"Map '{m}' exists in {BPF_SOURCE} but is NOT documented in {SCHEMA_DOC}")

    # Maps documented but not in code (stale docs)
    stale = doc_maps - source_maps
    if stale:
        for m in sorted(stale):
            errors.append(f"Map '{m}' is documented in {SCHEMA_DOC} but NOT found in {BPF_SOURCE}")

    if errors:
        print(f"BPF Map Schema validation FAILED ({len(errors)} issues):\n")
        for e in errors:
            print(f"  - {e}")
        print(f"\nSource maps ({len(source_maps)}): {sorted(source_maps)}")
        print(f"Documented maps ({len(doc_maps)}): {sorted(doc_maps)}")
        return 1

    print(f"BPF Map Schema validation PASSED: {len(source_maps)} maps documented")
    return 0


if __name__ == "__main__":
    sys.exit(main())
