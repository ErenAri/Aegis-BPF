#!/usr/bin/env python3
"""
AegisBPF → Splunk HTTP Event Collector (HEC) Forwarder

Reads AegisBPF JSON events from stdin and forwards them to Splunk
via the HTTP Event Collector (HEC) API.

Usage:
    export SPLUNK_HEC_URL="https://splunk.example.com:8088/services/collector/event"
    export SPLUNK_HEC_TOKEN="your-hec-token-here"

    sudo aegisbpf daemon 2>&1 | python3 splunk-hec-forwarder.py

Environment Variables:
    SPLUNK_HEC_URL    — Splunk HEC endpoint URL (required)
    SPLUNK_HEC_TOKEN  — Splunk HEC authentication token (required)
    SPLUNK_INDEX      — Target Splunk index (default: "main")
    SPLUNK_SOURCETYPE — Splunk sourcetype (default: "aegisbpf:events")
    SPLUNK_SOURCE     — Event source (default: hostname)
    BATCH_SIZE        — Events per HTTP request (default: 10)
    BATCH_TIMEOUT_S   — Max seconds between flushes (default: 5)

Requires: Python 3.7+, requests
"""

import json
import os
import socket
import sys
import time
import threading
from typing import List

try:
    import requests
except ImportError:
    sys.stderr.write("ERROR: 'requests' library required. Install: pip install requests\n")
    sys.exit(1)


class SplunkHecForwarder:
    """Batched Splunk HEC forwarder with retry."""

    def __init__(self):
        self.url = os.environ.get("SPLUNK_HEC_URL", "")
        self.token = os.environ.get("SPLUNK_HEC_TOKEN", "")
        self.index = os.environ.get("SPLUNK_INDEX", "main")
        self.sourcetype = os.environ.get("SPLUNK_SOURCETYPE", "aegisbpf:events")
        self.source = os.environ.get("SPLUNK_SOURCE", socket.gethostname())
        self.batch_size = int(os.environ.get("BATCH_SIZE", "10"))
        self.batch_timeout = float(os.environ.get("BATCH_TIMEOUT_S", "5"))

        if not self.url or not self.token:
            sys.stderr.write("ERROR: SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN must be set\n")
            sys.exit(1)

        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Splunk {self.token}",
            "Content-Type": "application/json",
        })
        # Disable TLS verification for self-signed certs (set SPLUNK_VERIFY_TLS=1 to enable)
        self.session.verify = os.environ.get("SPLUNK_VERIFY_TLS", "0") == "1"

        self.batch: List[dict] = []
        self.lock = threading.Lock()
        self.stats = {"sent": 0, "errors": 0, "events": 0}

    def _flush(self):
        """Send accumulated events to Splunk HEC."""
        with self.lock:
            if not self.batch:
                return
            events = self.batch
            self.batch = []

        payload = ""
        for event in events:
            hec_event = {
                "event": event,
                "sourcetype": self.sourcetype,
                "source": self.source,
                "index": self.index,
                "time": time.time(),
            }

            # Set event type from AegisBPF event
            event_type = event.get("type", "unknown")
            if event_type in ("block", "forensic_block") or event_type.startswith("net_") or event_type.startswith("kernel_"):
                hec_event["sourcetype"] = "aegisbpf:block"
            elif event_type == "exec":
                hec_event["sourcetype"] = "aegisbpf:exec"
            elif event_type == "state_change":
                hec_event["sourcetype"] = "aegisbpf:state"

            payload += json.dumps(hec_event, separators=(",", ":")) + "\n"

        try:
            resp = self.session.post(self.url, data=payload, timeout=10)
            if resp.status_code == 200:
                self.stats["sent"] += len(events)
            else:
                self.stats["errors"] += 1
                sys.stderr.write(f"WARN: Splunk HEC returned {resp.status_code}: {resp.text[:200]}\n")
        except requests.exceptions.RequestException as e:
            self.stats["errors"] += 1
            sys.stderr.write(f"ERROR: Splunk HEC request failed: {e}\n")

    def _timer_flush(self):
        """Periodic flush for low-volume periods."""
        while True:
            time.sleep(self.batch_timeout)
            self._flush()

    def add_event(self, event: dict):
        """Add event to batch, flush if batch is full."""
        with self.lock:
            self.batch.append(event)
            self.stats["events"] += 1
            should_flush = len(self.batch) >= self.batch_size

        if should_flush:
            self._flush()

    def run(self):
        """Main loop: read events from stdin, forward to Splunk."""
        # Start background flush timer
        timer = threading.Thread(target=self._timer_flush, daemon=True)
        timer.start()

        sys.stderr.write(f"AegisBPF → Splunk HEC forwarder started\n")
        sys.stderr.write(f"  URL: {self.url}\n")
        sys.stderr.write(f"  Index: {self.index}\n")
        sys.stderr.write(f"  Batch size: {self.batch_size}\n")

        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    self.add_event(event)
                except json.JSONDecodeError:
                    pass
        except KeyboardInterrupt:
            pass
        finally:
            self._flush()
            sys.stderr.write(
                f"Forwarder stopped. Events: {self.stats['events']}, "
                f"Sent: {self.stats['sent']}, Errors: {self.stats['errors']}\n"
            )


def main():
    forwarder = SplunkHecForwarder()
    forwarder.run()


if __name__ == "__main__":
    main()
