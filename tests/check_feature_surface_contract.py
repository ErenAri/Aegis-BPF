#!/usr/bin/env python3
"""Validate that current implementation claims match the shipped feature surface."""

from pathlib import Path
import sys


def forbid(text: str, path: Path, needles: list[str], errors: list[str]) -> None:
    for needle in needles:
        if needle in text:
            errors.append(f"{path}: unexpected '{needle}'")


def require(text: str, path: Path, needles: list[str], errors: list[str]) -> None:
    for needle in needles:
        if needle not in text:
            errors.append(f"{path}: missing '{needle}'")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors: list[str] = []

    forbidden_checks = {
        root / "src" / "kernel_features.hpp": ["sk_storage"],
        root / "src" / "kernel_features.cpp": ["sk_storage", "check_sk_storage_support"],
        root / "src" / "bpf_ops.cpp": ["BPF_MAP_TYPE_SK_STORAGE", "socket caching"],
        root / "src" / "commands_monitoring.cpp": ['"sk_storage"'],
        root / "bpf" / "aegis.bpf.c": ["deny_bloom", "deny_exact", "MAX_DENY_BLOOM_ENTRIES", "MAX_DENY_EXACT_ENTRIES"],
        root / "docs" / "API_REFERENCE.md": ["deny_bloom"],
        root / "docs" / "CAPACITY_PLANNING.md": ["deny_bloom_map", "deny_exact_map"],
        root / "docs" / "COMPATIBILITY.md": ["BPF_MAP_TYPE_SK_STORAGE", "Socket Caching", "Perf event array fallback"],
        root / "docs" / "THREAT_MODEL.md": ["planned Phase 5"],
    }

    required_checks = {
        root / "src" / "types.hpp": ["IpPortRule", "deny_ip_ports"],
        root / "bpf" / "aegis.bpf.c": [
            "deny_ip_port_v4",
            "deny_ip_port_v6",
            "handle_socket_accept",
            "EVENT_NET_ACCEPT_BLOCK",
            "handle_socket_sendmsg",
            "EVENT_NET_SENDMSG_BLOCK",
        ],
        root / "docs" / "API_REFERENCE.md": ["[deny_ip_port]", "deny_ip_port_v4", "deny_ip_port_v6"],
        root / "docs" / "NETWORK_LAYER_DESIGN.md": [
            "Status: Reference design for the shipped network layer plus future extensions.",
            "Bloom-filter fast paths in this document are not implemented today.",
        ],
        root / "docs" / "POLICY_SEMANTICS.md": [
            "`socket_accept` uses the same remote match order as `socket_connect`",
            "`socket_bind` and `socket_listen` continue to apply port deny logic only.",
        ],
        root / "docs" / "GUARANTEES.md": [
            "`accept()` is covered for remote exact IP, CIDR, IP:port, and local-port",
            "Exact IP and CIDR rules do not apply to `listen()` decisions in this release.",
        ],
        root / "config" / "schemas" / "capabilities_v1.json": ["lsm_socket_accept", "lsm_socket_sendmsg"],
        root / "config" / "event-schema.json": ["net_accept_block", "net_sendmsg_block", "\"accept\"", "\"send\""],
        root / "docs" / "THREAT_MODEL.md": ["socket_accept", "socket_sendmsg"],
    }

    for path, needles in forbidden_checks.items():
        text = path.read_text(encoding="utf-8")
        forbid(text, path, needles, errors)

    for path, needles in required_checks.items():
        text = path.read_text(encoding="utf-8")
        require(text, path, needles, errors)

    if errors:
        print("Feature surface contract violations detected:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1

    print("Feature surface contract checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
