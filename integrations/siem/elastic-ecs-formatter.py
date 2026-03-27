#!/usr/bin/env python3
"""
AegisBPF → Elastic Common Schema (ECS) Formatter

Reads AegisBPF JSON events from stdin and transforms them into
Elastic Common Schema (ECS) format for ingestion into Elasticsearch,
Elastic SIEM, or Elastic Agent.

Usage:
    sudo aegisbpf daemon --audit-only 2>&1 | python3 elastic-ecs-formatter.py | \
        curl -X POST http://elasticsearch:9200/aegisbpf-events/_bulk \
             -H 'Content-Type: application/x-ndjson' --data-binary @-

    # Or pipe to Filebeat:
    sudo aegisbpf daemon 2>&1 | python3 elastic-ecs-formatter.py >> /var/log/aegisbpf-ecs.jsonl

Requires: Python 3.7+
"""

import json
import sys
import time
from datetime import datetime, timezone


def aegis_to_ecs(event: dict) -> dict:
    """Transform an AegisBPF event into Elastic Common Schema format."""
    ecs = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "ecs": {"version": "8.11.0"},
        "event": {
            "kind": "event",
            "module": "aegisbpf",
            "dataset": "aegisbpf.events",
        },
        "agent": {
            "type": "aegisbpf",
            "name": "aegisbpf",
        },
    }

    event_type = event.get("type", "unknown")

    # Process fields (common to all events)
    if "pid" in event:
        ecs["process"] = {
            "pid": event["pid"],
        }
        if "ppid" in event:
            ecs["process"]["parent"] = {"pid": event["ppid"]}
        if "comm" in event:
            ecs["process"]["name"] = event["comm"]
        if "exec_id" in event:
            ecs["process"]["entity_id"] = event["exec_id"]
        if "start_time" in event:
            ecs["process"]["start"] = event["start_time"]

    # Container/K8s fields
    if "k8s_pod" in event:
        ecs["kubernetes"] = {
            "pod": {"name": event["k8s_pod"]},
        }
        if "k8s_namespace" in event:
            ecs["kubernetes"]["namespace"] = event["k8s_namespace"]
        if "k8s_service_account" in event:
            ecs["kubernetes"]["service_account"] = {"name": event["k8s_service_account"]}

    # Cgroup path → container label
    if "cgroup_path" in event:
        ecs.setdefault("container", {})["runtime"] = "cgroup"
        ecs["container"]["id"] = event.get("cgid", "")
        ecs["labels"] = {"cgroup_path": event["cgroup_path"]}

    # Event-type-specific mapping
    if event_type == "exec":
        ecs["event"]["category"] = ["process"]
        ecs["event"]["type"] = ["start"]
        ecs["event"]["action"] = "process-started"

    elif event_type == "block":
        ecs["event"]["category"] = ["file", "intrusion_detection"]
        ecs["event"]["type"] = ["denied"]
        ecs["event"]["action"] = "file-access-denied"
        ecs["event"]["outcome"] = "failure"

        if "path" in event:
            ecs["file"] = {"path": event["path"]}
        if "resolved_path" in event:
            ecs.setdefault("file", {})["target_path"] = event["resolved_path"]
        if "ino" in event:
            ecs.setdefault("file", {})["inode"] = str(event["ino"])
        if "action" in event:
            ecs["event"]["reason"] = event["action"]

    elif event_type.startswith("net_"):
        ecs["event"]["category"] = ["network", "intrusion_detection"]
        ecs["event"]["type"] = ["denied", "connection"]
        ecs["event"]["action"] = f"network-{event_type.replace('net_', '').replace('_block', '')}-denied"
        ecs["event"]["outcome"] = "failure"

        if "remote_ip" in event:
            ecs["destination"] = {
                "ip": event["remote_ip"],
                "port": event.get("remote_port", 0),
            }
        if "local_port" in event:
            ecs["source"] = {"port": event["local_port"]}
        if "protocol" in event:
            ecs["network"] = {
                "transport": event["protocol"],
                "direction": event.get("direction", "unknown"),
            }
        if "rule_type" in event:
            ecs.setdefault("rule", {})["name"] = event["rule_type"]

    elif event_type.startswith("kernel_"):
        ecs["event"]["category"] = ["intrusion_detection"]
        ecs["event"]["type"] = ["denied"]
        rule_type = event.get("rule_type", "unknown")
        ecs["event"]["action"] = f"kernel-{rule_type}-denied"
        ecs["event"]["outcome"] = "failure"
        ecs["rule"] = {"name": rule_type}

        if "target_pid" in event and event["target_pid"]:
            ecs["process"]["target"] = {"pid": event["target_pid"]}

    elif event_type == "forensic_block":
        ecs["event"]["category"] = ["file", "intrusion_detection"]
        ecs["event"]["type"] = ["denied"]
        ecs["event"]["action"] = "forensic-file-access-denied"
        ecs["event"]["outcome"] = "failure"

        if "ino" in event:
            ecs["file"] = {"inode": str(event["ino"])}

    elif event_type == "state_change":
        ecs["event"]["category"] = ["configuration"]
        ecs["event"]["type"] = ["change"]
        ecs["event"]["action"] = "runtime-state-change"
        ecs["event"]["reason"] = event.get("reason_code", "")
        if "state" in event:
            ecs["labels"] = ecs.get("labels", {})
            ecs["labels"]["runtime_state"] = event["state"]

    # Preserve original event
    ecs["aegisbpf"] = event

    return ecs


def main():
    """Read AegisBPF events from stdin, output ECS-formatted events."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
            ecs_event = aegis_to_ecs(event)
            # Output as NDJSON (one JSON object per line)
            print(json.dumps(ecs_event, separators=(",", ":")))
            sys.stdout.flush()
        except json.JSONDecodeError:
            # Non-JSON lines (logs, errors) pass through
            sys.stderr.write(f"WARN: non-JSON line skipped: {line[:100]}\n")
        except Exception as e:
            sys.stderr.write(f"ERROR: {e}\n")


if __name__ == "__main__":
    main()
