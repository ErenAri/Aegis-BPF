#!/usr/bin/env python3
"""Validate Phase-6 meta-security gates remain enforced."""

from __future__ import annotations

from pathlib import Path
import sys


def require_text(path: Path, needles: list[str]) -> list[str]:
    if not path.is_file():
        return [f"missing file: {path}"]
    text = path.read_text(encoding="utf-8")
    missing = [needle for needle in needles if needle not in text]
    return [f"{path}: missing '{item}'" for item in missing]


def main() -> int:
    if len(sys.argv) != 7:
        print(
            "usage: check_phase6_meta_security_contract.py "
            "<phase6-evidence.md> <release.yml> <security.md> <key_management.md> "
            "<test_commands.cpp> <systemd-service>",
            file=sys.stderr,
        )
        return 2

    evidence_doc = Path(sys.argv[1])
    release_workflow = Path(sys.argv[2])
    security_doc = Path(sys.argv[3])
    key_mgmt_doc = Path(sys.argv[4])
    command_tests = Path(sys.argv[5])
    service_unit = Path(sys.argv[6])

    errors: list[str] = []
    errors += require_text(
        evidence_doc,
        [
            "Phase 6 Meta-Security Evidence",
            "RotateAndRevokeTrustedSigningKeys",
            "RejectsRollbackBundleVersion",
            "Generate SBOM",
            "attest-build-provenance",
            "CapabilityBoundingSet",
        ],
    )
    errors += require_text(
        release_workflow,
        [
            "Generate SBOM",
            "Sign artifacts with Cosign",
            "actions/attest-build-provenance",
        ],
    )
    errors += require_text(
        security_doc,
        ["Minimum Privileges", "CAP_BPF", "CAP_SYS_ADMIN", "CAP_NET_ADMIN"],
    )
    errors += require_text(
        key_mgmt_doc,
        ["Rotate signing keys", "Revoke a compromised key", "Anti-rollback"],
    )
    errors += require_text(
        command_tests,
        [
            "KeyLifecycleTest",
            "RotateAndRevokeTrustedSigningKeys",
            "RejectsRollbackBundleVersion",
        ],
    )
    errors += require_text(
        service_unit,
        ["CapabilityBoundingSet", "AmbientCapabilities", "AEGIS_ALLOW_SIGKILL"],
    )

    if errors:
        for item in errors:
            print(item, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
